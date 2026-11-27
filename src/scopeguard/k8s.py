"""Run the sandboxed code analyzer as a Kubernetes Job via ``kubectl``. Stdlib only.

Kubernetes only: no Docker, no custom image, nothing is built. The Job runs a stock
Python image (``K8S_IMAGE``, default ``python:3.12-slim``; pin a digest). The analyzer
code (the stdlib-only modules in :data:`ANALYZER_MODULES`) reaches the pod as an
immutable ConfigMap named after its SHA-256 and mounted read-only at /app/scopeguard;
an existing ConfigMap is verified against that hash before use. The input archive is
streamed into the Job pod's stdin (``kubectl attach``), the JSON-lines result is read
from the pod log, and the Job is deleted. Used for uploaded code and the agent's code check.

Job / pod hardening (see :func:`job_manifest`):

* ``backoffLimit: 0`` (the caller retries an out-of-memory run itself, with 10x memory
  and the checkpoint), ``activeDeadlineSeconds``, ``ttlSecondsAfterFinished`` so the
  cluster removes the Job even if the server dies, ``restartPolicy: Never``
* namespace ``scopeguard-sandbox`` with a default-deny NetworkPolicy (checked before
  every run; refused when missing) and Pod Security ``restricted`` (k8s/sandbox.yaml)
* no service-account token, no service links, DNS pointed at 127.0.0.1
* non-root 65534, read-only root filesystem, all capabilities dropped, no privilege
  escalation, RuntimeDefault seccomp, optional RuntimeClass (gVisor / Kata)
* memory request = limit (sized from the content: x5, x10 on retry), CPU and
  ephemeral-storage limits, size-limited emptyDir for the extracted text files
* the analyzer's own audit hooks still block network, processes and writes
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass

from scopeguard.limits import RunResult

DEFAULT_NAMESPACE = "scopeguard-sandbox"
DEFAULT_IMAGE = "python:3.12-slim"
CONFIGMAP_PREFIX = "scopeguard-analyzer-"
APP_DIR = "/app"
# Everything scopeguard.upload_worker imports (stdlib only); shipped as a ConfigMap.
ANALYZER_MODULES = ("__init__", "upload_worker", "codecheck", "codestyle", "archive", "engine", "limits", "textsafe",
                    "contentpolicy", "ratelimit")
MAX_CONFIGMAP_BYTES = 900_000  # Kubernetes objects are capped at 1 MiB
BOOT = ("import sys;sys.path.insert(0,'/app');"
        "from scopeguard.upload_worker import main;raise SystemExit(main())")
NETWORK_POLICY = "scopeguard-deny-all"
CONTAINER = "analyzer"
LABEL = "scopeguard.io/codecheck"
SESSION_LABEL = "scopeguard.io/session"
OWNER_ANNOTATION = "scopeguard.io/owner"
JOB_PREFIX = "scopeguard-job-"
WORK_MB = 160          # extracted text files (archive.MAX_EXTRACT_BYTES) + slack
JOB_TTL_SECONDS = 300  # the cluster deletes a finished Job after this, even if we could not
MAX_LOG_BYTES = 32 * 1024 * 1024
_LABEL_RE = re.compile(r"[^a-z0-9-]+")
# kubectl auth can-i checks run before every scan (all must answer "yes")
REQUIRED_ACCESS = (("create", "jobs.batch"), ("delete", "jobs.batch"), ("get", "jobs.batch"),
                   ("list", "pods"), ("create", "pods/attach"), ("get", "pods/log"),
                   ("get", "configmaps"), ("create", "configmaps"))


class K8sError(RuntimeError):
    pass


@dataclass
class K8sConfig:
    namespace: str = DEFAULT_NAMESPACE
    image: str = DEFAULT_IMAGE
    context: str | None = None
    kubeconfig: str | None = None
    runtime_class: str | None = None
    cpu: str = "1"
    image_pull_policy: str = "IfNotPresent"
    require_network_policy: bool = True
    # Prove the policy is enforced (a probe pod must fail to connect out), not just present:
    # a CNI without NetworkPolicy support (e.g. some kind/Docker Desktop setups) ignores it.
    verify_network_isolation: bool = True
    request_timeout: int = 20


_NOT_AVAILABLE = ("kubectl not found", "not reachable", "Kubernetes API not reachable", "docker CLI not found",
                  "kind CLI not found", "no kind node container")


def not_available(reason: str) -> bool:
    """True when Kubernetes is simply absent (no kubectl / Docker / cluster, or it is stopped):
    the Python process sandbox is then the normal place to run. False for a reachable cluster
    that is unsafe or misconfigured (RBAC, NetworkPolicy missing or not enforced)."""
    text = str(reason or "")
    return any(marker in text for marker in _NOT_AVAILABLE) and "NetworkPolicy" not in text


def _kubectl() -> str | None:
    return shutil.which("kubectl")


def base_cmd(cfg: K8sConfig) -> list[str]:
    cmd = [_kubectl() or "kubectl", f"--request-timeout={cfg.request_timeout}s"]
    if cfg.kubeconfig:
        cmd += ["--kubeconfig", cfg.kubeconfig]
    if cfg.context:
        cmd += ["--context", cfg.context]
    return cmd + ["-n", cfg.namespace]


def _run(args: list[str], *, input_: bytes | None = None, timeout: float = 60.0) -> subprocess.CompletedProcess:
    return subprocess.run(args, input=input_, capture_output=True, timeout=timeout, check=False)


def analyzer_files() -> dict[str, str]:
    """The analyzer's source files, as ConfigMap data (flat keys = file names)."""
    here = os.path.dirname(os.path.abspath(__file__))
    files = {}
    for mod in ANALYZER_MODULES:
        with open(os.path.join(here, f"{mod}.py"), encoding="utf-8") as fh:
            files[f"{mod}.py"] = fh.read()
    if sum(len(v.encode()) for v in files.values()) > MAX_CONFIGMAP_BYTES:
        raise K8sError("analyzer code is too large for a ConfigMap")
    return files


def files_digest(files: dict[str, str]) -> str:
    h = hashlib.sha256()
    for name in sorted(files):
        h.update(name.encode() + b"\0" + str(files[name]).encode() + b"\0")
    return h.hexdigest()


def ensure_analyzer_configmap(cfg: K8sConfig) -> str:
    """Create (or verify) the immutable ConfigMap holding the analyzer code; returns its name.
    A ConfigMap with our name but different content is refused, never used."""
    files = analyzer_files()
    digest = files_digest(files)
    name = CONFIGMAP_PREFIX + digest[:16]
    base = base_cmd(cfg)
    for _ in range(2):
        got = _run([*base, "get", "configmap", name, "-o", "json"], timeout=cfg.request_timeout + 5)
        if got.returncode == 0:
            try:
                data = json.loads(got.stdout or b"{}").get("data") or {}
            except ValueError:
                data = {}
            if files_digest(data) != digest:
                raise K8sError(f"ConfigMap {name} exists with different content; refusing to run it "
                               "(delete it and let the scanner recreate it)")
            return name
        cm = {"apiVersion": "v1", "kind": "ConfigMap", "immutable": True,
              "metadata": {"name": name, "namespace": cfg.namespace,
                           "labels": {LABEL: "1", "scopeguard.io/role": "analyzer-code"},
                           "annotations": {"scopeguard.io/sha256": digest}},
              "data": files}
        made = _run([*base, "create", "-f", "-"], input_=json.dumps(cm).encode(), timeout=cfg.request_timeout + 10)
        if made.returncode == 0:
            return name
        if b"AlreadyExists" not in (made.stderr or b""):  # else: made concurrently, verify it
            raise K8sError("could not create the analyzer ConfigMap: "
                           f"{made.stderr.decode('utf-8', 'replace')[-300:]}")
    raise K8sError("could not create or verify the analyzer ConfigMap")


def job_name(session_id: str | None) -> str:
    """RFC 1123 Job name ``scopeguard-job-<id>`` (lower-case, <= 52 chars so pod names fit)."""
    import uuid

    sid = _LABEL_RE.sub("-", (session_id or "").lower()).strip("-")[:30] or uuid.uuid4().hex[:12]
    return (JOB_PREFIX + sid)[:52].rstrip("-")


def network_policy_ok(policy: dict) -> tuple[bool, str]:
    """The policy must select every pod and allow neither ingress nor egress."""
    spec = policy.get("spec") or {}
    if spec.get("podSelector") not in ({}, None) and spec.get("podSelector") != {"matchLabels": {}}:
        return False, "network policy does not select every pod in the namespace"
    types = set(spec.get("policyTypes") or [])
    if not {"Ingress", "Egress"} <= types:
        return False, "network policy must list both Ingress and Egress in policyTypes"
    if spec.get("egress") or spec.get("ingress"):
        return False, "network policy allows some traffic (egress/ingress rules present)"
    return True, "ok"


STATUS_TTL_SECONDS = 60
POLICY_SETTLE_SECONDS = 15  # a just-applied NetworkPolicy can take a few seconds to be enforced
_STATUS_CACHE: dict[tuple, tuple[float, bool, str]] = {}


def _cfg_key(cfg: K8sConfig) -> tuple:
    return (cfg.kubeconfig, cfg.context, cfg.namespace, cfg.image, cfg.require_network_policy,
            cfg.verify_network_isolation)


def invalidate_status() -> None:
    _STATUS_CACHE.clear()
    _PROBE_CACHE.clear()


def cluster_status(cfg: K8sConfig) -> tuple[bool, str]:
    """(usable, reason), cached for STATUS_TTL_SECONDS so an unreachable cluster does not
    slow every scan. See :func:`_cluster_status` for what is checked."""
    key = _cfg_key(cfg)
    hit = _STATUS_CACHE.get(key)
    if hit and time.monotonic() - hit[0] < STATUS_TTL_SECONDS:
        return hit[1], hit[2]
    ok, why = _cluster_status(cfg)
    _STATUS_CACHE[key] = (time.monotonic(), ok, why)
    return ok, why


def _cluster_status(cfg: K8sConfig) -> tuple[bool, str]:
    """kubectl present, cluster reachable, namespace exists, we may run Jobs, attach and
    read logs, and the default-deny NetworkPolicy is in place and proven enforced."""
    if not _kubectl():
        return False, "kubectl not found"
    base = base_cmd(cfg)
    try:
        ns = _run([*base[:-2], "get", "namespace", cfg.namespace, "-o", "name"], timeout=cfg.request_timeout + 5)
        if ns.returncode != 0:
            err = ns.stderr.decode("utf-8", "replace").strip()[-200:]
            return False, f"namespace {cfg.namespace} not reachable ({err or 'kubectl failed'})"
        for verb, res in REQUIRED_ACCESS:
            can = _run([*base, "auth", "can-i", verb, res], timeout=cfg.request_timeout + 5)
            if can.stdout.decode().strip() != "yes":
                return False, f"not allowed to {verb} {res} in {cfg.namespace} (apply k8s/sandbox.yaml RBAC)"
        if cfg.require_network_policy:
            pol = _run([*base, "get", "networkpolicy", NETWORK_POLICY, "-o", "json"], timeout=cfg.request_timeout + 5)
            if pol.returncode != 0:
                return False, f"NetworkPolicy {NETWORK_POLICY} missing in {cfg.namespace} (apply k8s/sandbox.yaml)"
            ok, why = network_policy_ok(json.loads(pol.stdout or b"{}"))
            if not ok:
                return False, why
            if cfg.verify_network_isolation:
                ok, why = egress_blocked(cfg)
                if not ok:
                    return False, why
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        return False, f"cluster not reachable ({exc.__class__.__name__})"
    return True, "ok"


# --------------------------------------------------------------------------- isolation probe
PROBE_TTL_SECONDS = 600
_PROBE_CACHE: dict[tuple, tuple[float, bool, str]] = {}
# Tries the Kubernetes API service (always routable in-cluster, no internet needed) and a
# public address. Any successful connect means the NetworkPolicy is not enforced.
# Some CNIs program a NetworkPolicy a moment after a pod starts, so a short-lived pod can get
# out before enforcement: the probe tries every target from the first instant and again over a
# few seconds, and ONE successful connection anywhere means "not enforced".
_PROBE = ("import json,os,socket,time\n"
          "t=(('api',(os.environ.get('KUBERNETES_SERVICE_HOST','10.96.0.1'),"
          "int(os.environ.get('KUBERNETES_SERVICE_PORT','443')))),('internet',('1.1.1.1',443)))\n"
          "r={k:'untested' for k,_ in t}\n"
          "for d in (0,0.5,1,2):\n"
          " time.sleep(d)\n"
          " for k,h in t:\n"
          "  try:\n   socket.create_connection(h,timeout=3).close(); r[k]='connected'\n"
          "  except OSError as e:\n   r[k]=r[k] if r[k]=='connected' else 'blocked:'+type(e).__name__\n"
          "print('SCOPEGUARD_PROBE '+json.dumps(r))")


def egress_blocked(cfg: K8sConfig, *, poll: float = 1.0) -> tuple[bool, str]:
    """Run a throw-away probe Job in the sandbox namespace and check that it cannot open any
    connection. Cached for PROBE_TTL_SECONDS per cluster/namespace."""
    key = (cfg.kubeconfig, cfg.context, cfg.namespace, cfg.image)
    hit = _PROBE_CACHE.get(key)
    if hit and time.monotonic() - hit[0] < PROBE_TTL_SECONDS:
        return hit[1], hit[2]
    import uuid

    name = f"scopeguard-netprobe-{uuid.uuid4().hex[:8]}"
    base = base_cmd(cfg)
    manifest = job_manifest(name=name, cfg=cfg, memory_mb=64, timeout=60, args=[],
                            configmap=ensure_analyzer_configmap(cfg), session_id="netprobe")
    c = manifest["spec"]["template"]["spec"]["containers"][0]
    c.update(command=["python", "-I", "-c", _PROBE], args=[], stdin=False, stdinOnce=False)
    result: tuple[bool, str]
    try:
        made = _run([*base, "create", "-f", "-"], input_=json.dumps(manifest).encode(), timeout=cfg.request_timeout + 10)
        if made.returncode != 0:
            return False, f"network isolation probe could not start: {made.stderr.decode('utf-8', 'replace')[-200:]}"
        deadline = time.monotonic() + 90
        pod: dict = {}
        while time.monotonic() < deadline:
            pod = _job_pod(cfg, name)
            problem = _waiting_problem(pod)
            if problem:
                return False, f"network isolation probe could not start ({problem})"
            if _terminated(pod) is not None:
                break
            time.sleep(poll)
        pod_name = (pod.get("metadata") or {}).get("name", "")
        logs = _run([*base, "logs", f"pod/{pod_name}", "-c", CONTAINER], timeout=cfg.request_timeout + 10)
        line = next((x for x in logs.stdout.decode("utf-8", "replace").splitlines()
                     if x.startswith("SCOPEGUARD_PROBE ")), "")
        try:
            probe = json.loads(line.split(" ", 1)[1]) if line else {}
        except ValueError:
            probe = {}
        if not probe:
            result = (False, "network isolation probe gave no result; refusing to trust the NetworkPolicy")
        elif any(v == "connected" for v in probe.values()):
            reached = ", ".join(k for k, v in probe.items() if v == "connected")
            result = (False, (f"NetworkPolicy {NETWORK_POLICY} is NOT enforced: a sandbox pod reached {reached}. "
                             "Use a CNI that enforces NetworkPolicy (e.g. Calico or Cilium)"))
        else:
            result = (True, "ok")
    finally:
        delete_job(cfg, name)
    _PROBE_CACHE[key] = (time.monotonic(), *result)
    return result


def _labels(session_id: str | None) -> dict:
    return {LABEL: "1", SESSION_LABEL: _LABEL_RE.sub("-", (session_id or "adhoc").lower())[:63].strip("-") or "adhoc"}


def pod_spec(*, cfg: K8sConfig, memory_mb: int, args: list[str], configmap: str) -> dict:
    mem = f"{int(memory_mb)}Mi"
    spec: dict = {
        "restartPolicy": "Never",
        "terminationGracePeriodSeconds": 0,
        "automountServiceAccountToken": False,
        "enableServiceLinks": False,
        "hostNetwork": False, "hostPID": False, "hostIPC": False,
        "dnsPolicy": "None", "dnsConfig": {"nameservers": ["127.0.0.1"]},
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "runAsGroup": 65534, "fsGroup": 65534,
                            "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{
            "name": CONTAINER, "image": cfg.image, "imagePullPolicy": cfg.image_pull_policy,
            "command": ["python", "-I", "-B", "-c", BOOT],
            "args": ["--workdir", "/work", "--sandbox-kind", "kubernetes", *args],
            "stdin": True, "stdinOnce": True, "tty": False,
            "workingDir": "/work",
            "env": [{"name": "PYTHONDONTWRITEBYTECODE", "value": "1"},
                    {"name": "PYTHONIOENCODING", "value": "utf-8"}],
            "resources": {
                "requests": {"memory": mem, "cpu": cfg.cpu, "ephemeral-storage": "64Mi"},
                "limits": {"memory": mem, "cpu": cfg.cpu, "ephemeral-storage": f"{WORK_MB + 64}Mi"}},
            "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
                                "privileged": False, "runAsNonRoot": True, "capabilities": {"drop": ["ALL"]},
                                "seccompProfile": {"type": "RuntimeDefault"}},
            "volumeMounts": [{"name": "work", "mountPath": "/work"}, {"name": "tmp", "mountPath": "/tmp"},
                             {"name": "analyzer", "mountPath": f"{APP_DIR}/scopeguard", "readOnly": True}],
        }],
        "volumes": [{"name": "work", "emptyDir": {"sizeLimit": f"{WORK_MB}Mi"}},
                    {"name": "analyzer", "configMap": {"name": configmap, "defaultMode": 0o444}},
                    {"name": "tmp", "emptyDir": {"medium": "Memory", "sizeLimit": "16Mi"}}],
    }
    if cfg.runtime_class:
        spec["runtimeClassName"] = cfg.runtime_class
    return spec


def job_manifest(*, name: str, cfg: K8sConfig, memory_mb: int, timeout: int, args: list[str],
                 configmap: str, session_id: str | None = None, owner: str = "") -> dict:
    """The exact Job object (kept separate so tests can assert every setting)."""
    labels = _labels(session_id)
    return {"apiVersion": "batch/v1", "kind": "Job",
            "metadata": {"name": name, "namespace": cfg.namespace, "labels": labels,
                         "annotations": {OWNER_ANNOTATION: owner}},
            "spec": {"backoffLimit": 0, "completions": 1, "parallelism": 1,
                     "activeDeadlineSeconds": int(timeout), "ttlSecondsAfterFinished": JOB_TTL_SECONDS,
                     "template": {"metadata": {"labels": labels},
                                  "spec": pod_spec(cfg=cfg, memory_mb=memory_mb, args=args,
                                                   configmap=configmap)}}}


def delete_job(cfg: K8sConfig, name: str) -> bool:
    """Delete our Job ``name`` and its pods now (label-checked: never an unrelated Job). Never raises."""
    if not _kubectl():
        return False
    base = base_cmd(cfg)
    try:
        r = _run([*base, "delete", "jobs", "-l", f"{LABEL}=1", "--field-selector", f"metadata.name={name}",
                  "--cascade=background", "--wait=false", "--ignore-not-found"], timeout=cfg.request_timeout + 10)
        _run([*base, "delete", "pods", "-l", f"{LABEL}=1,job-name={name}", "--grace-period=0", "--force",
              "--wait=false", "--ignore-not-found"], timeout=cfg.request_timeout + 10)
        return r.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def remove_leftover_jobs(cfg: K8sConfig) -> list[str]:
    """Delete sandbox Jobs whose owning server process is gone (killed mid-scan).
    Finished ones also expire on their own (ttlSecondsAfterFinished)."""
    from scopeguard.container import _orphaned

    if not _kubectl():
        return []
    try:
        r = _run([*base_cmd(cfg), "get", "jobs", "-l", f"{LABEL}=1", "-o", "json"], timeout=cfg.request_timeout + 5)
        items = json.loads(r.stdout or b"{}").get("items", []) if r.returncode == 0 else []
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return []
    gone = []
    for item in items:
        meta = item.get("metadata") or {}
        if _orphaned((meta.get("annotations") or {}).get(OWNER_ANNOTATION, "")) and delete_job(cfg, meta.get("name", "")):
            gone.append(meta.get("name", ""))
    return gone


def _job_pod(cfg: K8sConfig, name: str) -> dict:
    r = _run([*base_cmd(cfg), "get", "pods", "-l", f"job-name={name}", "-o", "json"], timeout=cfg.request_timeout + 5)
    if r.returncode != 0:
        return {}
    try:
        items = json.loads(r.stdout or b"{}").get("items") or []
    except ValueError:
        return {}
    return items[0] if items else {}


def _terminated(pod: dict) -> dict | None:
    for cs in (pod.get("status") or {}).get("containerStatuses") or []:
        if cs.get("name") == CONTAINER:
            return (cs.get("state") or {}).get("terminated")
    return None


def _waiting_problem(pod: dict) -> str | None:
    for cs in (pod.get("status") or {}).get("containerStatuses") or []:
        waiting = (cs.get("state") or {}).get("waiting") or {}
        if waiting.get("reason") in ("ErrImagePull", "ImagePullBackOff", "InvalidImageName", "CreateContainerError",
                                     "CreateContainerConfigError"):
            return f"{waiting['reason']}: {str(waiting.get('message', ''))[:200]}"
    return None


def run_job(stdin: bytes, *, cfg: K8sConfig, memory_mb: int, timeout: int, args: list[str] | None = None,
            session_id: str | None = None, poll: float = 1.0) -> RunResult:
    """Run one analyzer Job and return its exit code, log and termination reason.
    The Job (and its pod) is always deleted afterwards, also on timeout or error."""
    from scopeguard.container import owner_id

    name = job_name(session_id)
    base = base_cmd(cfg)
    delete_job(cfg, name)  # a Job of the same session left by a killed earlier attempt
    try:
        configmap = ensure_analyzer_configmap(cfg)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise K8sError(f"kubectl failed: {exc.__class__.__name__}: {exc}") from exc
    manifest = job_manifest(name=name, cfg=cfg, memory_mb=memory_mb, timeout=timeout, args=list(args or []),
                            configmap=configmap, session_id=session_id, owner=owner_id())
    deadline = time.monotonic() + timeout + 60
    try:
        made = _run([*base, "create", "-f", "-"], input_=json.dumps(manifest).encode(), timeout=cfg.request_timeout + 10)
        if made.returncode != 0:
            raise K8sError(f"could not create the Job: {made.stderr.decode('utf-8', 'replace').strip()[-300:]}")
        # Wait for the Job's pod to run (its container blocks on stdin until we attach).
        while True:
            pod = _job_pod(cfg, name)
            problem = _waiting_problem(pod)
            if problem:
                raise K8sError(f"Job pod could not start ({problem}); check that the cluster can pull {cfg.image}")
            phase = (pod.get("status") or {}).get("phase")
            if phase in ("Running", "Succeeded", "Failed"):
                break
            if time.monotonic() > deadline:
                raise K8sError("Job pod did not start before the deadline")
            time.sleep(poll)
        pod_name = (pod.get("metadata") or {}).get("name", "")
        attach_timed_out = False
        try:
            subprocess.run([*base, "attach", "-i", "-q", "-c", CONTAINER, f"pod/{pod_name}"], input=stdin,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
                           timeout=max(5.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            attach_timed_out = True
        term = None
        while term is None and time.monotonic() < deadline:
            pod = _job_pod(cfg, name)
            term = _terminated(pod)
            if term is None:
                if not pod or (pod.get("status") or {}).get("reason") == "DeadlineExceeded":
                    break
                time.sleep(poll)
        logs = _run([*base, "logs", f"pod/{pod_name}", "-c", CONTAINER, f"--limit-bytes={MAX_LOG_BYTES}"],
                    timeout=cfg.request_timeout + 30)
        stdout = logs.stdout.decode("utf-8", "replace")
        if term is None:
            return RunResult(-1, stdout, "Job did not finish before the deadline", timed_out=True,
                             memory_mb=memory_mb, reason="Timeout" if attach_timed_out else "DeadlineExceeded")
        reason = str(term.get("reason") or "")
        code = int(term.get("exitCode", -1))
        return RunResult(code, stdout, f"Job pod terminated: {reason} (exit {code})", memory_mb=memory_mb,
                         reason=reason)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise K8sError(f"kubectl failed: {exc.__class__.__name__}: {exc}") from exc
    finally:
        delete_job(cfg, name)


# --------------------------------------------------------------------------- bring-up
def _api_ready(cfg: K8sConfig, timeout: int = 5) -> bool:
    try:
        r = _run([*base_cmd(cfg)[:-2], "get", "--raw", "/readyz", f"--request-timeout={timeout}s"],
                 timeout=timeout + 5)
        return r.returncode == 0 and b"ok" in (r.stdout or b"")
    except (OSError, subprocess.TimeoutExpired):
        return False


# Pinned Calico (NetworkPolicy enforcement for the local kind cluster); the manifest is checked
# against this SHA-256 before it is applied. Same version as k8s/README.md.
CALICO_VERSION = "v3.29.1"
CALICO_URL = f"https://raw.githubusercontent.com/projectcalico/calico/{CALICO_VERSION}/manifests/calico.yaml"
CALICO_SHA256 = "ef325a26cb4e0a2d386d0e512c0cf4fd0fa935ac25777b41b0d3737153025a1c"
CALICO_MAX_BYTES = 4 * 1024 * 1024
KIND_CREATE_TIMEOUT = 600
CALICO_ROLLOUT_SECONDS = 420
MISSING_NODE = "no kind node container"


def _kind() -> str | None:
    """The kind CLI: PATH first, then a winget install (its Links dir is not always on PATH)."""
    found = shutil.which("kind")
    if found:
        return found
    base = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "WinGet")
    if os.environ.get("LOCALAPPDATA"):
        candidates = [os.path.join(base, "Links", "kind.exe")]
        pkgs = os.path.join(base, "Packages")
        if os.path.isdir(pkgs):
            candidates += [os.path.join(pkgs, d, "kind.exe") for d in sorted(os.listdir(pkgs))
                           if d.startswith("Kubernetes.kind_")]
        for path in candidates:
            if os.path.isfile(path):
                return path
    return None


def _on_host() -> bool:
    return not (os.environ.get("KUBERNETES_SERVICE_HOST") or os.path.exists("/.dockerenv"))


def _calico_manifest(cache_dir: str) -> str:
    """Path of the pinned Calico manifest, downloaded once and verified by SHA-256 every time."""
    import urllib.request

    path = os.path.join(cache_dir, f"calico-{CALICO_VERSION}.yaml")
    if os.path.isfile(path):
        with open(path, "rb") as fh:
            if hashlib.sha256(fh.read()).hexdigest() == CALICO_SHA256:
                return path
    with urllib.request.urlopen(CALICO_URL, timeout=60) as resp:  # fixed, pinned https URL
        data = resp.read(CALICO_MAX_BYTES + 1)
    if len(data) > CALICO_MAX_BYTES or hashlib.sha256(data).hexdigest() != CALICO_SHA256:
        raise K8sError(f"Calico {CALICO_VERSION} manifest failed its SHA-256 check; not applied")
    os.makedirs(cache_dir, exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    return path


def _current_context(cfg: K8sConfig) -> str:
    if cfg.context:
        return cfg.context
    r = _run([*base_cmd(cfg)[:-2], "config", "current-context"], timeout=15)
    return (r.stdout or b"").decode("utf-8", "replace").strip() if r.returncode == 0 else ""


def _ensure_calico(cfg: K8sConfig, cluster: str, cache_dir: str) -> str:
    """Install Calico into OUR local kind cluster when it is missing (never into another context)."""
    if _current_context(cfg) != f"kind-{cluster}":
        return "skipped (current context is not the local kind cluster)"
    kc = [*base_cmd(cfg)[:-2], "-n", "kube-system"]
    if _run([*kc, "get", "daemonset", "calico-node", "-o", "name"], timeout=cfg.request_timeout + 5).returncode == 0:
        return "present"
    try:
        manifest = _calico_manifest(cache_dir)
    except (OSError, K8sError) as exc:
        return f"not installed ({exc})"
    applied = _run([*base_cmd(cfg)[:-2], "apply", "-f", manifest], timeout=cfg.request_timeout + 120)
    if applied.returncode != 0:
        return f"apply failed: {applied.stderr.decode('utf-8', 'replace').strip()[-200:]}"
    rolled = _run([*kc, "rollout", "status", "daemonset/calico-node", f"--timeout={CALICO_ROLLOUT_SECONDS}s"],
                  timeout=CALICO_ROLLOUT_SECONDS + 30)
    return f"installed {CALICO_VERSION}" if rolled.returncode == 0 else f"installed {CALICO_VERSION}, not ready yet"


def _create_kind_cluster(cluster: str, kind_config: str | None, cfg: K8sConfig, wait_seconds: int) -> str:
    """Create the local kind cluster (default CNI off; Calico follows). Host only."""
    kind = _kind()
    if not kind:
        return "kind CLI not found (install kind, or create the cluster by hand: k8s/README.md)"
    if not _on_host():
        return "running inside a container: the local kind cluster is not created from here"
    args = [kind, "create", "cluster", "--name", cluster]
    if kind_config and os.path.isfile(kind_config):
        args += ["--config", kind_config]
    try:
        made = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=KIND_CREATE_TIMEOUT, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"kind create failed: {exc.__class__.__name__}"
    if made.returncode != 0:
        return f"kind create failed: {(made.stderr or made.stdout).strip()[-200:]}"
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        if _api_ready(cfg):
            return "created"
        time.sleep(2)
    return f"created but the API server was not ready within {wait_seconds}s"


def _start_kind_node(cluster: str, wait_seconds: int, cfg: K8sConfig) -> str:
    """Start the stopped node container of a local kind cluster (on the host only)."""
    node = f"{cluster}-control-plane"
    docker = shutil.which("docker")
    if not docker:
        return "docker CLI not found (cannot start the kind node)"
    if not _on_host():
        return "running inside a container: the local kind node is not started from here"
    try:
        state = subprocess.run([docker, "inspect", "-f", "{{.State.Running}}", node], capture_output=True,
                               text=True, timeout=20, check=False)
        if state.returncode != 0:
            return f"{MISSING_NODE} {node!r} (create one: kind create cluster --name {cluster})"
        if state.stdout.strip() != "true":
            started = subprocess.run([docker, "start", node], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60,
                                     check=False)
            if started.returncode != 0:
                return f"could not start {node}: {started.stderr.strip()[-200:]}"
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"docker failed: {exc.__class__.__name__}"
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        if _api_ready(cfg):
            return "started"
        time.sleep(2)
    return f"{node} started but the API server was not ready within {wait_seconds}s"


def bootstrap(cfg: K8sConfig, *, kind_cluster: str = "", manifests: str | None = None,
              auto_start: bool = True, auto_apply: bool = True, wait_seconds: int = 120,
              auto_create: bool = False, kind_config: str | None = None, cache_dir: str | None = None) -> dict:
    """Bring the sandbox up and report what happened. Never raises.

    1. API server unreachable + ``kind_cluster`` + ``auto_start``: start its stopped node container;
       with ``auto_create`` and no such container, create the cluster (``kind_config``) and install
       the pinned, SHA-checked Calico (only into context ``kind-<cluster>``).
    2. Sandbox namespace missing + ``auto_apply``: ``kubectl apply -f <manifests>``.
    3. Ship / verify the analyzer ConfigMap.
    4. Full readiness check (RBAC, NetworkPolicy, isolation probe), cache refreshed.
    ``ready`` false means scans use the Python process sandbox (always: falling back is not a setting)."""
    actions: list[str] = []
    if not _kubectl():
        return {"ready": False, "reason": "kubectl not found", "actions": actions}
    try:
        if not _api_ready(cfg):
            if auto_start and kind_cluster:
                outcome = _start_kind_node(kind_cluster, wait_seconds, cfg)
                actions.append(f"kind node {kind_cluster}-control-plane: {outcome}")
                if outcome.startswith(MISSING_NODE) and auto_create:
                    outcome = _create_kind_cluster(kind_cluster, kind_config, cfg, wait_seconds)
                    actions.append(f"kind cluster {kind_cluster}: {outcome}")
                    if outcome == "created":
                        outcome = "started"
                if outcome != "started":
                    return {"ready": False, "reason": f"Kubernetes API not reachable ({outcome})", "actions": actions}
            else:
                return {"ready": False, "reason": "Kubernetes API not reachable", "actions": actions}
        if auto_create and kind_cluster:
            calico = _ensure_calico(cfg, kind_cluster, cache_dir or os.path.join(
                os.path.expanduser("~"), ".cache", "scopeguard"))
            if calico != "present":
                actions.append(f"Calico: {calico}")
        ns = _run([*base_cmd(cfg)[:-2], "get", "namespace", cfg.namespace, "-o", "name"],
                  timeout=cfg.request_timeout + 5)
        if ns.returncode != 0:
            if auto_apply and manifests and os.path.isfile(manifests):
                applied = _run([*base_cmd(cfg)[:-2], "apply", "-f", manifests], timeout=cfg.request_timeout + 60)
                actions.append("applied " + os.path.basename(manifests) if applied.returncode == 0 else
                               f"apply failed: {applied.stderr.decode('utf-8', 'replace').strip()[-200:]}")
            else:
                return {"ready": False, "reason": f"namespace {cfg.namespace} missing (apply k8s/sandbox.yaml)",
                        "actions": actions}
        try:
            actions.append(f"analyzer ConfigMap {ensure_analyzer_configmap(cfg)} ready")
        except K8sError as exc:
            return {"ready": False, "reason": str(exc), "actions": actions}
        invalidate_status()
        ok, why = cluster_status(cfg)
        if not ok and "NOT enforced" in why and any(a.startswith("applied ") for a in actions):
            # A NetworkPolicy created seconds ago may not be programmed yet: probe once more.
            time.sleep(POLICY_SETTLE_SECONDS)
            invalidate_status()
            ok, why = cluster_status(cfg)
            actions.append("re-probed after the NetworkPolicy settled")
        actions.append("isolation probe passed" if ok else "readiness check failed")
        return {"ready": ok, "reason": why, "actions": actions}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ready": False, "reason": f"kubectl failed ({exc.__class__.__name__})", "actions": actions}


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(prog="python -m scopeguard.k8s",
                                 description="Kubernetes Job sandbox: status or bring-up")
    ap.add_argument("--bootstrap", action="store_true", help="start the kind node / apply manifests / probe")
    ap.add_argument("--kind-cluster", default="scopeguard")
    ap.add_argument("--manifests", default="k8s/sandbox.yaml")
    ap.add_argument("--create", action="store_true",
                    help="with --bootstrap: create the kind cluster + Calico when it does not exist")
    ap.add_argument("--kind-config", default="k8s/kind-calico.yaml")
    ap.add_argument("--namespace", default=DEFAULT_NAMESPACE)
    ap.add_argument("--image", default=DEFAULT_IMAGE)
    a = ap.parse_args(argv)
    cfg = K8sConfig(namespace=a.namespace, image=a.image)
    if a.bootstrap:
        res = bootstrap(cfg, kind_cluster=a.kind_cluster, manifests=a.manifests, auto_create=a.create,
                        kind_config=a.kind_config)
        for act in res["actions"]:
            print(" -", act)
    else:
        ok, why = cluster_status(cfg)
        res = {"ready": ok, "reason": why}
    print(("READY: " if res["ready"] else "NOT READY (scans use the Python process sandbox): ") + res["reason"])
    return 0 if res["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
