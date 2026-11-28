"""Source-code uploads: HTTP API and MCP tools, type checks, RBAC/ownership, the sandbox scan
(process backend here), reports, audit, and the Kubernetes pod runner (faked kubectl)."""
from __future__ import annotations

import base64
import io
import json
import os
import subprocess
import zipfile

import pytest
from fastapi.testclient import TestClient
from mcp.server.mcpserver.exceptions import ToolError

from pentest_agent import code_upload, rbac, websocket_server
from pentest_agent.config import settings
from pentest_agent.mcp_server import server as mcp_mod
from scopeguard import audit, codescan, k8s

# The real bring-up, captured before conftest stubs it per test.
_REAL_BOOTSTRAP = k8s.bootstrap

VULN_JS = ("app.get('/api/orders/:id', async (req, res) => {\n"
           "  const o = await Order.findById(req.params.id);\n"
           "  res.send('<p>' + req.query.q + '</p>');\n});\n")


def _zip(entries=None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in (entries or [("app/orders.js", VULN_JS), ("../evil.py", "x"), (".env", "A=1")]):
            z.writestr(name, data)
    return buf.getvalue()


@pytest.fixture(autouse=True)
def _inline_jobs(monkeypatch, tmp_path):
    """Fresh upload/report folders, process sandbox."""
    monkeypatch.setattr(settings, "code_upload_dir", str(tmp_path / "uploads"))
    monkeypatch.setattr(settings, "reports_dir", str(tmp_path / "reports"))
    monkeypatch.setattr(settings, "sandbox_backend", "process")
    code_upload._STATUS_CACHE.clear()


def _post(client, data, name="app.zip", ctype="application/zip"):
    return client.post(f"/api/uploads?filename={name}", content=data, headers={"Content-Type": ctype})


# ------------------------------------------------------------------ HTTP: type checks
@pytest.mark.parametrize("name, ctype, data, status, text", [
    ("app.zip", "text/plain", None, 415, "unsupported content type"),
    ("app.tar.gz", "application/zip", None, 415, "only .zip"),
    ("app.exe", "application/octet-stream", None, 415, "only .zip"),
    ("app.zip", "application/zip", b"MZ\x90\x00" + b"\0" * 100, 415, "Windows executable"),
    ("app.zip", "application/zip", b"\x7fELF" + b"\0" * 100, 415, "ELF executable"),
    ("app.zip", "application/zip", b"\x1f\x8b\x08\x00" + b"\0" * 100, 415, "gzip"),
    ("app.zip", "application/zip", b"", 400, "empty"),
])
def test_upload_type_checks(name, ctype, data, status, text):
    with TestClient(websocket_server.app) as client:
        r = _post(client, _zip() if data is None else data, name, ctype)
    assert r.status_code == status and text in r.json()["detail"]
    assert not any((code_upload.uploads_root()).iterdir())  # nothing kept


def test_upload_size_cap(monkeypatch):
    monkeypatch.setattr(settings, "code_upload_max_mb", 1)
    big = _zip([(f"f{i}.txt", base64.b64encode(os.urandom(600_000)).decode()) for i in range(3)])
    with TestClient(websocket_server.app) as client:
        r = _post(client, big)
    assert r.status_code == 413


def test_upload_is_stored_and_code_is_only_analysed_inside_a_web_scan():
    with TestClient(websocket_server.app) as client:
        r = _post(client, _zip(), ctype="application/x-zip-compressed")  # what Windows browsers send
        assert r.status_code == 201, r.text
        uid = r.json()["upload_id"]
        assert r.json()["status"] == "uploaded" and len(r.json()["sha256"]) == 64
        assert r.json()["source"] == {"kind": "zip"}
        # no standalone code scan any more: code SAST is a step of the agent graph
        assert client.post(f"/api/uploads/{uid}/scan", json={"authorization_confirmed": True}).status_code in (
            404, 405)
        policy = client.get("/api/uploads/policy").json()
    assert policy["accepted"]["extension"] == ".zip" and policy["memory"]["multiplier"] == 5
    assert "files" in policy["accepted"] and policy["git"]["hosts"] == ["github.com", "gitlab.com", "bitbucket.org"]
    assert set(policy["modes"]) == {"ask_at_sast", "up_front"}
    assert policy["kubernetes"]["namespace"] == "scopeguard-sandbox"


def test_other_users_cannot_see_or_scan_an_upload():
    alice = rbac.Principal(sub="alice", roles=["admin"])
    meta = code_upload.store_bytes(alice, "a.zip", "application/zip", _zip())
    mallory = rbac.Principal(sub="mallory", roles=["admin"])
    mallory_limited = mallory.model_copy()
    # admin has sessions:any; a role without it is refused (404, existence not revealed)
    monkey_roles = rbac.ROLE_PERMISSIONS["admin"] - {rbac.Permission.SESSIONS_ANY}
    rbac.ROLE_PERMISSIONS["_test_admin_no_any"] = monkey_roles
    try:
        limited = rbac.Principal.model_construct(sub="mallory", roles=["_test_admin_no_any"])
        with pytest.raises(code_upload.UploadError) as e:
            code_upload.get_upload(meta["upload_id"], limited)
        assert e.value.status == 404
    finally:
        rbac.ROLE_PERMISSIONS.pop("_test_admin_no_any")
    assert code_upload.get_upload(meta["upload_id"], mallory_limited)["owner"] == "alice"  # sessions:any


def test_scanner_role_may_not_upload():
    with pytest.raises(rbac.Forbidden):
        code_upload.store_bytes(rbac.Principal(sub="s", roles=["scanner"]), "a.zip", "application/zip", _zip())


def test_failed_scan_keeps_archive_and_checkpoint_for_resume(monkeypatch):
    def boom(*a, **kw):
        raise codescan.CodescanError("sandbox ran out of memory even at 10x")

    monkeypatch.setattr(code_upload.codescan, "scan_archive", boom)
    who = rbac.Principal(sub="alice", roles=["admin"])
    meta = code_upload.store_bytes(who, "a.zip", "application/zip", _zip())
    with pytest.raises(codescan.CodescanError):
        code_upload.analyse_for_scan(meta["upload_id"], who, session_id="web-f")
    after = code_upload.get_upload(meta["upload_id"], who)
    assert after["status"] == "failed" and "10x" in after["error"]
    assert (code_upload.uploads_root() / meta["upload_id"] / "archive.zip").exists()
    assert audit.read(settings.code_audit_log_path)[-1]["event"] == "scan.failed"


# ------------------------------------------------------------------ MCP tools
async def _call(name, args):
    res = await mcp_mod.mcp.call_tool(name, args)
    return json.loads(res.content[0].text)


@pytest.fixture
def mcp_admin(monkeypatch):
    monkeypatch.setattr(settings, "mcp_role", "admin")
    mcp_mod.reset_service()
    yield
    mcp_mod.reset_service()


async def test_mcp_upload_zip_or_files_then_start_scan(mcp_admin):
    tools = {t.name for t in await mcp_mod.mcp.list_tools()}
    assert "upload_code" in tools and not {"start_code_scan", "get_code_scan"} & tools
    up = await _call("upload_code", {"filename": "app.zip", "content_base64": base64.b64encode(_zip()).decode()})
    assert up["source"] == {"kind": "zip"} and "start_scan" in up["next_step"]
    up = await _call("upload_code", {"files": [{"name": "app/orders.js", "content": VULN_JS},
                                               {"name": "app/views.py", "content": "x = 1\n"}]})
    assert up["source"] == {"kind": "files", "count": 2} and up["filename"] == "2-files.zip"
    meta = code_upload.check_attachable(up["upload_id"], rbac.Principal(sub="mcp", roles=["admin"]))
    assert meta["upload_id"] == up["upload_id"]
    policy = await _call("scan_policy", {})
    assert policy["code_uploads"]["allowed"] is True and "kubernetes" in policy["code_uploads"]
    assert "git_url" in policy["code_uploads"]["how"] and "start_code_scan" not in policy["code_uploads"]["how"]


@pytest.mark.parametrize("args, message", [
    ({"filename": "app.tar", "content_base64": base64.b64encode(_zip()).decode()}, "only .zip"),
    ({"filename": "app.zip", "content_base64": "not base64!!"}, "not valid base64"),
    ({"filename": "app.zip", "content_base64": base64.b64encode(b"MZ" + b"\0" * 50).decode()}, "executable"),
    ({}, "either content_base64"),
    ({"files": [{"name": "../etc/passwd.py", "content": "x"}]}, "'..'"),
    ({"files": [{"name": "tool.exe", "content": "x"}]}, "not a source/text file"),
])
async def test_mcp_upload_refusals(mcp_admin, args, message):
    with pytest.raises(ToolError, match=message):
        await mcp_mod.mcp.call_tool("upload_code", args)


async def test_mcp_upload_idempotency_key(mcp_admin):
    """A retried upload with the same key returns the same upload_id; once the upload is gone (used by
    a scan), the same key stores the code again; another content under the key is refused."""
    zip_b64 = base64.b64encode(_zip()).decode()
    args = {"filename": "app.zip", "content_base64": zip_b64, "idempotency_key": "upload-key-0001"}
    first = await _call("upload_code", args)
    again = await _call("upload_code", args)
    assert again["upload_id"] == first["upload_id"] and again["idempotent_replay"] is True
    assert "idempotent_replay" not in first
    assert len([p for p in code_upload.uploads_root().iterdir() if p.is_dir()]) == 1
    with pytest.raises(ToolError, match="different upload_code request"):
        await mcp_mod.mcp.call_tool("upload_code", {**args, "filename": "other.zip"})
    code_upload.delete_upload(first["upload_id"], rbac.Principal(sub="mcp", roles=["admin"]))
    fresh = await _call("upload_code", args)
    assert fresh["upload_id"] != first["upload_id"] and "idempotent_replay" not in fresh


async def test_mcp_upload_size_cap(mcp_admin, monkeypatch):
    monkeypatch.setattr(settings, "mcp_max_upload_mb", 1)
    with pytest.raises(ToolError, match="POST /api/uploads"):
        await mcp_mod.mcp.call_tool("upload_code", {"filename": "a.zip", "content_base64": "A" * 2_000_000})


async def test_mcp_scanner_role_is_refused(monkeypatch):
    monkeypatch.setattr(settings, "mcp_role", "scanner")
    mcp_mod.reset_service()
    with pytest.raises(ToolError, match="scan:source"):
        await mcp_mod.mcp.call_tool("upload_code", {"filename": "a.zip",
                                                    "content_base64": base64.b64encode(_zip()).decode()})


# ------------------------------------------------------------------ Kubernetes Job runner
def test_job_manifest_is_locked_down():
    cfg = k8s.K8sConfig(runtime_class="gvisor")
    m = k8s.job_manifest(name="scopeguard-job-x", cfg=cfg, memory_mb=640, timeout=300, args=[],
                         configmap="scopeguard-analyzer-abc", session_id="upload-abc", owner="h:1")
    assert m["apiVersion"] == "batch/v1" and m["kind"] == "Job"
    job = m["spec"]
    assert job["backoffLimit"] == 0 and job["activeDeadlineSeconds"] == 300 and job["ttlSecondsAfterFinished"] > 0
    spec = job["template"]["spec"]
    c = spec["containers"][0]
    assert c["image"] == "python:3.12-slim" and c["command"][:4] == ["python", "-I", "-B", "-c"]  # stock image
    assert spec["automountServiceAccountToken"] is False and spec["enableServiceLinks"] is False
    assert spec["restartPolicy"] == "Never" and spec["dnsPolicy"] == "None" and spec["runtimeClassName"] == "gvisor"
    assert not (spec["hostNetwork"] or spec["hostPID"] or spec["hostIPC"])
    assert spec["securityContext"]["runAsNonRoot"] and spec["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault"
    sc = c["securityContext"]
    assert sc["readOnlyRootFilesystem"] and not sc["allowPrivilegeEscalation"] and sc["capabilities"]["drop"] == ["ALL"]
    assert c["resources"]["limits"]["memory"] == c["resources"]["requests"]["memory"] == "640Mi"
    assert c["stdin"] and c["stdinOnce"] and not c["tty"]
    code = next(v for v in spec["volumes"] if v["name"] == "analyzer")
    assert code["configMap"]["name"] == "scopeguard-analyzer-abc" and code["configMap"]["defaultMode"] == 0o444
    assert next(v for v in c["volumeMounts"] if v["name"] == "analyzer")["readOnly"] is True
    assert m["metadata"]["labels"][k8s.LABEL] == "1" == job["template"]["metadata"]["labels"][k8s.LABEL]


def test_analyzer_code_fits_a_configmap_and_has_everything_the_worker_imports():
    import ast

    files = k8s.analyzer_files()
    assert sum(len(v.encode()) for v in files.values()) < k8s.MAX_CONFIGMAP_BYTES
    for name, text in files.items():
        for node in ast.walk(ast.parse(text)):
            mods = []
            if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("scopeguard"):
                mods = [node.module.split(".", 1)[1]] if "." in node.module else [a.name for a in node.names]
            for mod in mods:
                assert f"{mod}.py" in files, f"{name} imports scopeguard.{mod}, which is not shipped"


@pytest.mark.parametrize("policy, ok", [
    ({"spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}}, True),
    ({"spec": {"podSelector": {}, "policyTypes": ["Ingress"]}}, False),
    ({"spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"], "egress": [{}]}}, False),
    ({"spec": {"podSelector": {"matchLabels": {"a": "b"}}, "policyTypes": ["Ingress", "Egress"]}}, False),
])
def test_network_policy_must_deny_everything(policy, ok):
    assert k8s.network_policy_ok(policy)[0] is ok


class FakeKubectl:
    """Plays the API server: the first Job pod is OOMKilled after 2 files, the second succeeds."""

    def __init__(self, configmap_data=None):
        self.jobs, self.created, self.deleted, self.stdins = 0, [], [], []
        self.configmaps = {} if configmap_data is None else configmap_data

    def __call__(self, args, input_=None, timeout=60.0):
        verb = args[args.index("-n") + 2]
        what = args[args.index("-n") + 3] if len(args) > args.index("-n") + 3 else ""
        if verb == "get" and what == "configmap":
            name = args[args.index("configmap") + 1]
            if name not in self.configmaps:
                return subprocess.CompletedProcess(args, 1, b"", b"NotFound")
            return subprocess.CompletedProcess(args, 0, json.dumps({"data": self.configmaps[name]}).encode(), b"")
        if verb == "create":
            obj = json.loads(input_)
            if obj["kind"] == "ConfigMap":
                assert obj["immutable"] is True
                self.configmaps[obj["metadata"]["name"]] = obj["data"]
            else:
                self.jobs += 1
                self.created.append(obj)
            return subprocess.CompletedProcess(args, 0, b"", b"")
        if verb == "delete":
            self.deleted.append(what)
            return subprocess.CompletedProcess(args, 0, b"", b"")
        if verb == "get" and what == "pods":
            oom = self.jobs == 1
            state = {"terminated": {"exitCode": 137 if oom else 0, "reason": "OOMKilled" if oom else "Completed"}}
            pod = {"metadata": {"name": f"job-pod-{self.jobs}"}, "status": {
                "phase": "Failed" if oom else "Succeeded",
                "containerStatuses": [{"name": k8s.CONTAINER, "state": state}]}}
            return subprocess.CompletedProcess(args, 0, json.dumps({"items": [pod]}).encode(), b"")
        if verb == "logs":
            if self.jobs == 1:
                lines = [{"type": "checkpoint", "done": ["source:a.py", "source:b.py"], "findings": [],
                          "stats": {"source_files": 2}}]
            else:
                lines = [{"type": "result", "ok": True, "findings": [], "stats": {"source_files": 1},
                          "violations": [], "archive": {"stats": {}}}]
            return subprocess.CompletedProcess(args, 0, "\n".join(json.dumps(x) for x in lines).encode(), b"")
        raise AssertionError(args)


@pytest.fixture
def fake_cluster(monkeypatch):
    fake = FakeKubectl()
    monkeypatch.setattr(k8s, "_run", fake)
    monkeypatch.setattr(k8s, "cluster_status", lambda cfg: (True, "ok"))
    monkeypatch.setattr(k8s.subprocess, "run", lambda args, input=None, **kw: fake.stdins.append(input))
    monkeypatch.setattr(k8s, "_kubectl", lambda: "kubectl")
    return fake


def test_kubernetes_oomkilled_job_is_retried_with_10x_and_resumes(fake_cluster):
    fake = fake_cluster
    data = _zip([("a.py", "x" * 40_000), ("b.py", "y"), ("c.py", "z")])
    out = codescan.scan_archive(data, backend="kubernetes", timeout=60, floor_mb=64)
    first, second = (j["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"]["memory"]
                     for j in fake.created)
    assert [a["outcome"] for a in out["sandbox"]["attempts"]] == ["oom", "ok"]
    assert int(second[:-2]) >= int(first[:-2]) and out["sandbox"]["attempts"][0]["reason"] == "OOMKilled"
    assert json.loads(fake.stdins[1].split(b"\n", 1)[0])["done"] == ["source:a.py", "source:b.py"]  # resumed
    assert out["stats"]["source_files"] == 3 and out["sandbox"]["workload"] == "Job"
    assert fake.deleted.count("jobs") >= 4                               # every Job deleted (before + after)
    assert len(fake.configmaps) == 1                                     # analyzer code shipped once


def test_tampered_analyzer_configmap_is_refused(monkeypatch):
    files = k8s.analyzer_files()
    name = k8s.CONFIGMAP_PREFIX + k8s.files_digest(files)[:16]
    fake = FakeKubectl(configmap_data={name: {**files, "codecheck.py": "print('backdoor')"}})
    monkeypatch.setattr(k8s, "_run", fake)
    monkeypatch.setattr(k8s, "_kubectl", lambda: "kubectl")
    with pytest.raises(k8s.K8sError, match="different content"):
        k8s.ensure_analyzer_configmap(k8s.K8sConfig())


def test_kubernetes_required_but_unavailable_is_an_error():
    with pytest.raises(codescan.CodescanError, match="Kubernetes sandbox unavailable"):
        codescan.scan_archive(_zip(), backend="kubernetes", require_kubernetes=True)


def test_kubernetes_unavailable_falls_back_only_when_allowed():
    out = codescan.scan_archive(_zip(), backend="kubernetes", require_kubernetes=False, timeout=120)
    assert out["sandbox"]["kind"] == "process" and "no cluster in tests" in out["sandbox"]["fallback_reason"]


class FakeProbeCluster:
    """Answers the isolation probe Job with the given result line."""

    def __init__(self, result):
        self.result, self.jobs, self.configmaps, self.deleted = result, 0, {}, 0

    def __call__(self, args, input_=None, timeout=60.0):
        verb = args[args.index("-n") + 2]
        what = args[args.index("-n") + 3] if len(args) > args.index("-n") + 3 else ""
        if verb == "get" and what == "configmap":
            name = args[args.index("configmap") + 1]
            if name in self.configmaps:
                return subprocess.CompletedProcess(args, 0, json.dumps({"data": self.configmaps[name]}).encode(), b"")
            return subprocess.CompletedProcess(args, 1, b"", b"NotFound")
        if verb == "create":
            obj = json.loads(input_)
            if obj["kind"] == "ConfigMap":
                self.configmaps[obj["metadata"]["name"]] = obj["data"]
            else:
                self.jobs += 1
                assert obj["spec"]["template"]["spec"]["containers"][0]["command"][:3] == ["python", "-I", "-c"]
            return subprocess.CompletedProcess(args, 0, b"", b"")
        if verb == "get" and what == "pods":
            pod = {"metadata": {"name": "probe-pod"}, "status": {"containerStatuses": [
                {"name": k8s.CONTAINER, "state": {"terminated": {"exitCode": 0, "reason": "Completed"}}}]}}
            return subprocess.CompletedProcess(args, 0, json.dumps({"items": [pod]}).encode(), b"")
        if verb == "logs":
            return subprocess.CompletedProcess(args, 0, f"SCOPEGUARD_PROBE {json.dumps(self.result)}".encode(), b"")
        if verb == "delete":
            self.deleted += 1
            return subprocess.CompletedProcess(args, 0, b"", b"")
        raise AssertionError(args)


@pytest.mark.parametrize("result, ok, text", [
    ({"api": "blocked:TimeoutError", "internet": "blocked:TimeoutError"}, True, "ok"),
    ({"api": "connected", "internet": "blocked:TimeoutError"}, False, "NOT enforced: a sandbox pod reached api"),
    ({"api": "connected", "internet": "connected"}, False, "reached api, internet"),
])
def test_isolation_probe_proves_the_policy_is_enforced(monkeypatch, result, ok, text):
    fake = FakeProbeCluster(result)
    monkeypatch.setattr(k8s, "_run", fake)
    monkeypatch.setattr(k8s, "_kubectl", lambda: "kubectl")
    monkeypatch.setattr(k8s, "_PROBE_CACHE", {})
    got = k8s.egress_blocked(k8s.K8sConfig(), poll=0)
    assert got[0] is ok and text in got[1]
    assert fake.deleted >= 2                               # probe Job (and pods) removed
    k8s.egress_blocked(k8s.K8sConfig(), poll=0)
    assert fake.jobs == 1                                  # cached: no second probe


def test_isolation_probe_without_a_result_is_not_trusted(monkeypatch):
    fake = FakeProbeCluster({})
    monkeypatch.setattr(k8s, "_run", fake)
    monkeypatch.setattr(k8s, "_kubectl", lambda: "kubectl")
    monkeypatch.setattr(k8s, "_PROBE_CACHE", {})
    ok, why = k8s.egress_blocked(k8s.K8sConfig(), poll=0)
    assert not ok and "refusing to trust" in why


class FakeBringUp:
    """kubectl/docker for bootstrap(): API down until the kind node starts, namespace missing."""

    def __init__(self):
        self.started, self.applied, self.calls = False, False, []

    def run(self, args, input_=None, timeout=60.0):
        self.calls.append(args)
        if "/readyz" in args:
            return subprocess.CompletedProcess(args, 0 if self.started else 1, b"ok" if self.started else b"", b"")
        if "namespace" in args:
            return subprocess.CompletedProcess(args, 0 if self.applied else 1, b"", b"NotFound")
        if "apply" in args:
            self.applied = True
            return subprocess.CompletedProcess(args, 0, b"", b"")
        if "configmap" in args:
            return subprocess.CompletedProcess(args, 1, b"", b"NotFound")
        if "create" in args:
            return subprocess.CompletedProcess(args, 0, b"", b"")
        raise AssertionError(args)

    def docker(self, args, **kw):
        self.calls.append(args)
        if args[1] == "inspect":
            return subprocess.CompletedProcess(args, 0, "false\n", "")
        if args[1] == "start":
            self.started = True
            return subprocess.CompletedProcess(args, 0, "", "")
        raise AssertionError(args)


def test_bootstrap_starts_the_kind_node_applies_manifests_and_probes(monkeypatch, tmp_path):
    fake = FakeBringUp()
    manifests = tmp_path / "sandbox.yaml"
    manifests.write_text("kind: Namespace", encoding="utf-8")
    monkeypatch.setattr(k8s, "_run", fake.run)
    monkeypatch.setattr(k8s, "_kubectl", lambda: "kubectl")
    monkeypatch.setattr(k8s.shutil, "which", lambda name: name)
    monkeypatch.setattr(k8s.subprocess, "run", fake.docker)
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)
    monkeypatch.setattr(k8s, "cluster_status", lambda cfg: (True, "ok"))
    res = _REAL_BOOTSTRAP(k8s.K8sConfig(), kind_cluster="scopeguard", manifests=str(manifests), wait_seconds=5)
    assert res["ready"] is True
    joined = " | ".join(res["actions"])
    assert "scopeguard-control-plane: started" in joined and "applied sandbox.yaml" in joined
    assert any(c[:2] == ["docker", "start"] for c in fake.calls)


def test_bootstrap_creates_a_missing_kind_cluster_and_installs_checked_calico(monkeypatch, tmp_path):
    fake = FakeBringUp()
    manifests = tmp_path / "sandbox.yaml"
    manifests.write_text("kind: Namespace", encoding="utf-8")
    calico = tmp_path / f"calico-{k8s.CALICO_VERSION}.yaml"
    calico.write_bytes(b"pinned")
    monkeypatch.setattr(k8s, "CALICO_SHA256", __import__("hashlib").sha256(b"pinned").hexdigest())
    base_run = fake.run

    def run(args, input_=None, timeout=60.0):
        if "current-context" in args:
            return subprocess.CompletedProcess(args, 0, b"kind-scopeguard\n", b"")
        if "daemonset" in args:
            fake.calls.append(args)
            return subprocess.CompletedProcess(args, 1, b"", b"NotFound")
        if "rollout" in args:
            return subprocess.CompletedProcess(args, 0, b"", b"")
        if "apply" in args and str(calico) in args:
            fake.calls.append(args)
            return subprocess.CompletedProcess(args, 0, b"", b"")
        return base_run(args, input_, timeout)

    def docker(args, **kw):
        fake.calls.append(args)
        if args[1] == "inspect":                                  # no node container at all
            return subprocess.CompletedProcess(args, 1, "", "No such object")
        if args[1:3] == ["create", "cluster"]:
            assert "--config" in args and args[args.index("--name") + 1] == "scopeguard"
            fake.started = True
            return subprocess.CompletedProcess(args, 0, "", "")
        raise AssertionError(args)

    monkeypatch.setattr(k8s, "_run", run)
    monkeypatch.setattr(k8s, "_kubectl", lambda: "kubectl")
    monkeypatch.setattr(k8s, "_kind", lambda: "kind")
    monkeypatch.setattr(k8s.shutil, "which", lambda name: name)
    monkeypatch.setattr(k8s.subprocess, "run", docker)
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)
    monkeypatch.setattr(k8s, "cluster_status", lambda cfg: (True, "ok"))
    kind_cfg = tmp_path / "kind.yaml"
    kind_cfg.write_text("kind: Cluster", encoding="utf-8")
    res = _REAL_BOOTSTRAP(k8s.K8sConfig(), kind_cluster="scopeguard", manifests=str(manifests), wait_seconds=5,
                          auto_create=True, kind_config=str(kind_cfg), cache_dir=str(tmp_path))
    joined = " | ".join(res["actions"])
    assert res["ready"] is True, res
    assert "kind cluster scopeguard: created" in joined and f"Calico: installed {k8s.CALICO_VERSION}" in joined
    assert "applied sandbox.yaml" in joined
    # without auto_create a missing cluster is only reported (scans use the Python sandbox)
    fake.started = False
    res = _REAL_BOOTSTRAP(k8s.K8sConfig(), kind_cluster="scopeguard", manifests=str(manifests), wait_seconds=1)
    assert res["ready"] is False and "no kind node container" in res["reason"]


def test_calico_is_never_installed_into_another_context_or_with_a_bad_hash(monkeypatch, tmp_path):
    calls = []

    def run(args, input_=None, timeout=60.0):
        calls.append(args)
        if "current-context" in args:
            return subprocess.CompletedProcess(args, 0, b"prod-cluster\n", b"")
        raise AssertionError(args)

    monkeypatch.setattr(k8s, "_run", run)
    monkeypatch.setattr(k8s, "_kubectl", lambda: "kubectl")
    assert k8s._ensure_calico(k8s.K8sConfig(), "scopeguard", str(tmp_path)).startswith("skipped")
    assert not any("apply" in c for c in calls)
    (tmp_path / f"calico-{k8s.CALICO_VERSION}.yaml").write_bytes(b"tampered")

    class Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self, n):
            return b"tampered"

    monkeypatch.setattr("urllib.request.urlopen", lambda url, timeout=0: Resp())
    with pytest.raises(k8s.K8sError, match="SHA-256"):
        k8s._calico_manifest(str(tmp_path))


def test_bootstrap_without_kubectl_or_docker_means_python_sandbox(monkeypatch):
    monkeypatch.setattr(k8s, "_kubectl", lambda: None)
    assert _REAL_BOOTSTRAP(k8s.K8sConfig())["reason"] == "kubectl not found"
    monkeypatch.setattr(k8s, "_kubectl", lambda: "kubectl")
    monkeypatch.setattr(k8s, "_run", lambda args, input_=None, timeout=60.0: subprocess.CompletedProcess(args, 1, b"", b""))
    monkeypatch.setattr(k8s.shutil, "which", lambda name: None)              # no docker CLI
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)
    res = _REAL_BOOTSTRAP(k8s.K8sConfig(), kind_cluster="scopeguard", wait_seconds=1)
    assert res["ready"] is False and "docker CLI not found" in res["reason"]
    # default policy: Kubernetes unavailable -> the scan still runs, in the Python process sandbox
    from pentest_agent.config import Settings

    assert "sandbox_require_kubernetes" not in Settings.model_fields  # no setting: falling back is a must
    out = codescan.scan_archive(_zip(), backend="kubernetes", require_kubernetes=False, timeout=120)
    assert out["sandbox"]["kind"] == "process" and out["findings"]


# ------------------------------------------------------------------ web scan + attached code (SAST step)
_ADMIN = rbac.Principal(sub="op", roles=["admin"])


def test_attached_upload_is_analysed_in_the_scans_sast_step():
    from pentest_agent import code_audit
    from pentest_agent.tools.sandbox_check import execute_upload_analysis

    meta = code_upload.store_bytes(_ADMIN, "app.zip", "application/zip", _zip())
    out = execute_upload_analysis(upload_id=meta["upload_id"], principal=_ADMIN.state_dict(), session_id="web-1")
    rules = {f["title"].split(":", 1)[0] for f in out["findings"]}
    assert {"XSS_REFLECTED_RESPONSE", "IDOR_DIRECT_OBJECT_LOOKUP"} <= rules, rules
    assert all(f["source"] == "code_upload" for f in out["findings"])
    # no Python in this archive: the note and a red flag say the results are partial
    assert "No Python files" in out["notes"] and out["upload"]["filename"] == "app.zip"
    assert any("not a Python project" in f for f in out["red_flags"])
    assert out["upload"]["recommendations"] and out["upload"]["guardrails"]["post"]
    # analysed: the whole upload folder (archive, checkpoint, meta) is gone, audited as such
    assert not (code_upload.uploads_root() / meta["upload_id"]).exists()
    with pytest.raises(code_upload.UploadError) as gone:
        code_upload.get_upload(meta["upload_id"], _ADMIN)
    assert gone.value.status == 404
    trail = json.dumps(code_audit.view(limit=20), default=str)
    assert "scan.completed" in trail and '"via": "scan"' in trail
    assert '"upload.deleted"' in trail and "code analysis done" in trail


def test_someone_elses_upload_is_not_analysed_in_a_scan():
    from pentest_agent.tools.sandbox_check import execute_upload_analysis

    meta = code_upload.store_bytes(_ADMIN, "app.zip", "application/zip", _zip())
    out = execute_upload_analysis(upload_id=meta["upload_id"], principal={"sub": "eve", "roles": ["scanner"]},
                                  session_id="web-2")
    assert not out.get("findings") and "not analysed" in out["red_flags"][0]
    out = execute_upload_analysis(upload_id=meta["upload_id"], principal=_ADMIN.state_dict(), session_id="web-3",
                                  allowed=False)
    assert "scan:source" in out["red_flags"][0]
    with pytest.raises(code_upload.UploadError):
        code_upload.check_attachable("0" * 32, _ADMIN)


def test_graph_code_nodes_analyse_the_upload_and_the_report_shows_it(monkeypatch, tmp_path):
    from pentest_agent import graph
    from pentest_agent.schemas import FinalReport, TargetInput
    from pentest_agent.tools.report_tool import _render_markdown, render_report_html

    with pytest.raises(ValueError):
        TargetInput.model_validate({"url": "https://a.example/", "upload_id": "../../etc"})
    meta = code_upload.store_bytes(_ADMIN, "app.zip", "application/zip", _zip())
    monkeypatch.setattr(settings, "sandbox_check_enabled", False)
    state = {"session_id": "web-4", "principal": _ADMIN.state_dict(), "allowed_domains": ["a.example"],
             "target": {"url": "https://a.example/", "upload_id": meta["upload_id"], "authorization_confirmed": True},
             "findings": []}
    cmd = graph.code_source_node(state)  # named in the request: no pause
    assert cmd.goto[0].node == "code_sast" and cmd.update["code_source"]["upload_id"] == meta["upload_id"]
    state.update(cmd.update)
    cmd = graph.code_sast_node(state)
    up = cmd.update["code_report"]
    assert cmd.goto == "plan_probes" and cmd.update["findings"] and up["findings"] == len(cmd.update["findings"])
    assert up["source"] == {"kind": "zip"}
    # the site/source-folder check no longer touches the upload
    state.update(cmd.update)
    assert "code_report" not in graph.sandbox_check_node(state).update
    import datetime as dt

    now = dt.datetime.now(dt.UTC)
    report = FinalReport(session_id="web-4", target_url="https://a.example/", profile="standard", jwt_provided=False,
                         auth_tested=False, pages_crawled=1, started_at=now, finished_at=now,
                         findings=cmd.update["findings"], executive_summary="x", code_upload=up)
    md = _render_markdown(report)
    assert "Source code (code SAST step)" in md and "Python only for now" in md and "app.zip" in md
    assert ".zip archive uploaded" in md
    assert "### How to fix (per rule)" in md and "### Guardrails" in md
    html = render_report_html(report)
    assert "Code SAST" in html and "<script" not in html.lower()
    assert "Guardrails" in html and "Remediation" in html
    # one document for the whole scan: the Word report carries the code fixes and verdicts too
    import docx

    from pentest_agent.tools.report_tool import render_report_docx

    path = render_report_docx(report, tmp_path / "report.docx")
    text = "\n".join(p.text for p in docx.Document(str(path)).paragraphs)
    tables = "\n".join(c.text for t in docx.Document(str(path)).tables for r in t.rows for c in r.cells)
    assert "Source Code: How to Fix (per rule)" in text and "XSS_REFLECTED_RESPONSE" in text
    assert "Source Code: Guardrails" in text and "archive_integrity" in tables
    assert "Source code" in tables and ".zip archive uploaded" in tables
    # Python only for now: the JavaScript file is named and marked in every format
    assert "Not Python (partial coverage)" in tables and "app/orders.js (JavaScript)" in tables
    assert "### Language coverage" in md and "partial (not Python)" in md
    assert "Not Python (partial coverage)" in html


def test_missing_kubernetes_is_a_normal_python_sandbox_run_not_a_red_flag():
    assert k8s.not_available("kubectl not found")
    assert k8s.not_available("namespace scopeguard-sandbox not reachable (Unable to connect to the server)")
    assert not k8s.not_available("NetworkPolicy scopeguard-deny-all present but NOT enforced (egress reached)")
    assert not k8s.not_available("not allowed to create jobs in scopeguard-sandbox")
    from pentest_agent.tools.sandbox_check import red_flags_from_result

    quiet = {"sandbox": {"kind": "process", "fallback_reason": "Kubernetes sandbox unavailable: kubectl not found",
                         "fallback_expected": True}}
    loud = {"sandbox": {"kind": "process", "fallback_reason": "Kubernetes sandbox unavailable: NOT enforced",
                        "fallback_expected": False}}
    assert red_flags_from_result(quiet) == [] and red_flags_from_result(loud)
    assert code_upload.red_flags(quiet) == [] and code_upload.red_flags(loud)


# ---------------------------------------------------------------- sandbox auto-check at startup
@pytest.mark.parametrize("tools, expected, changed", [
    ({}, "process", True),                                  # no kubectl: process sandbox for this run
    ({"kubectl": "/usr/bin/kubectl"}, "kubernetes", False),  # kubectl: Kubernetes tried first
])
def test_sandbox_autodetect_picks_the_backend_the_machine_supports(monkeypatch, tools, expected, changed):
    import shutil

    monkeypatch.setattr(settings, "sandbox_backend", "kubernetes")
    monkeypatch.setattr(shutil, "which", lambda name: tools.get(name))
    result = code_upload.autodetect_sandbox()
    assert result["backend"] == expected and result["changed"] is changed
    assert settings.sandbox_backend == expected  # the effective setting for this run (.env untouched)
    assert code_upload.sandbox_status(refresh=True)["autodetect"]["reason"] == result["reason"]


def test_sandbox_autodetect_leaves_an_explicit_process_backend_alone(monkeypatch):
    import shutil

    monkeypatch.setattr(settings, "sandbox_backend", "process")
    monkeypatch.setattr(shutil, "which", lambda name: None)
    assert code_upload.autodetect_sandbox() == {"configured_backend": "process", "tools": {"kubectl": False,
                                                "docker": False}, "changed": False, "backend": "process",
                                                "reason": "SANDBOX_BACKEND=process"}
