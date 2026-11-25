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
ANALYZER_MODULES = ("__init__", "upload_worker", "codecheck", "archive", "engine", "limits", "textsafe",
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
    request_timeout: int = 20


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


def cluster_status(cfg: K8sConfig) -> tuple[bool, str]:
    """(usable, reason): kubectl present, cluster reachable, namespace exists, we may run
    Jobs, attach and read logs, and the default-deny NetworkPolicy is in place."""
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
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        return False, f"cluster not reachable ({exc.__class__.__name__})"
    return True, "ok"


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
