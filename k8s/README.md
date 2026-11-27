# Kubernetes Job sandbox: local setup

ScopeGuard analyses backend code and uploaded archives in short-lived Kubernetes Jobs
(`src/scopeguard/k8s.py`). Without a usable cluster everything still works: scans run in the
Python process sandbox, automatically (`.env` is never changed; there is no setting to refuse instead).

A cluster is only used after an **isolation probe** proves that sandbox pods cannot open any
connection (Kubernetes API, internet). The network plugin must therefore enforce
NetworkPolicy. kind's default plugin does not do that reliably, so use Calico.

## Automatic setup

With Docker running and the kind CLI installed (`winget install Kubernetes.kind`), `uv run pentest-agent`
does all of the steps below on start-up when the cluster is missing (`K8S_AUTO_CREATE_CLUSTER=true`, the
default): it creates the cluster, installs the pinned Calico after a SHA-256 check, applies `sandbox.yaml`
and runs the isolation probe. The first run takes a few minutes; the console starts with the Python
sandbox meanwhile and switches to Kubernetes Jobs by itself. Same by hand:
`uv run python -m scopeguard.k8s --bootstrap --create`.

## Manual setup (Windows, macOS or Linux, with Docker running)

```bash
# 1. kind and kubectl (Windows: winget install Kubernetes.kind; kubectl ships with Docker Desktop)
# 2. Cluster without the default network plugin
kind create cluster --name scopeguard --config k8s/kind-calico.yaml
# 3. Calico (pinned version; the node is NotReady until this is running)
curl -fsSL -o calico-v3.29.1.yaml https://raw.githubusercontent.com/projectcalico/calico/v3.29.1/manifests/calico.yaml
# optional integrity check: sha256 ef325a26cb4e0a2d386d0e512c0cf4fd0fa935ac25777b41b0d3737153025a1c
kubectl apply -f calico-v3.29.1.yaml
kubectl -n kube-system rollout status daemonset/calico-node --timeout=420s
# 4. Sandbox namespace, deny-all NetworkPolicy, quota, RBAC + analyzer ConfigMap + isolation probe
uv run python scripts/system_check.py --bootstrap
```

The system check should end with `kubernetes sandbox PASS ... isolation verified` and
`where code scans run: Kubernetes Jobs`.

## Every day

`uv run pentest-agent` brings the sandbox up before the console opens: it starts the stopped
kind node (`K8S_KIND_CLUSTER=scopeguard`), applies `k8s/sandbox.yaml` if the namespace is
missing, ships the analyzer and runs the probe (at most `K8S_STARTUP_WAIT_SECONDS`). The start-up
banner's **Code sandbox** line says where scans run. By hand: `uv run python -m scopeguard.k8s --bootstrap`.

## Looking at it

- `kubectl -n scopeguard-sandbox get jobs,pods -w`: scan Jobs appearing and being removed
- `kubectl get networkpolicy -A`, `kubectl get pods -n kube-system -l k8s-app=calico-node`
- Desktop UI: Headlamp or Lens; terminal UI: k9s (they read the `kind-scopeguard` context)

## Files

| File | Purpose |
|---|---|
| `kind-calico.yaml` | kind cluster config without the default network plugin |
| `sandbox.yaml` | namespace (Pod Security restricted), deny-all NetworkPolicy, quota, limits, RBAC |
