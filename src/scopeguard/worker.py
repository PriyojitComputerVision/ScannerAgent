"""Sandboxed scan worker (child process).

Installs, BEFORE any scan code runs:
  * a permanent audit hook (cannot be removed) that blocks subprocess/exec/fork,
    writes outside the sandbox dir, and any socket/DNS activity to hosts or
    ports outside the scan allowlist;
  * (POSIX) CPU / memory / file-size / fd / process rlimits set by the parent.
Input: JSON on stdin.  Output: one JSON object on stdout.
"""
from __future__ import annotations

import ipaddress
import json
import os
import socket
import sys
import urllib.parse as up


def _install_audit_hook(allowed_hosts: set[str], allowed_ips: set[str], allowed_ports: set[int],
                        sandbox_dir: str):
    sandbox_dir = os.path.realpath(sandbox_dir)
    blocked_events = {"subprocess.Popen", "os.system", "os.exec", "os.fork", "os.forkpty",
                      "os.posix_spawn", "os.spawn", "ctypes.dlopen", "os.remove", "os.rmdir",
                      "os.rename", "os.mkdir", "shutil.rmtree"}

    def hook(event, args):
        if event in blocked_events:
            if event in ("os.remove", "os.rmdir", "os.rename", "os.mkdir", "shutil.rmtree"):
                p = os.path.realpath(str(args[0])) if args else ""
                if p.startswith(sandbox_dir):
                    return
            raise PermissionError(f"sandbox: {event} blocked")
        if event == "open":
            path, mode, flags = args
            writing = (isinstance(mode, str) and any(c in mode for c in "wax+")) or (
                isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND))
            if writing and isinstance(path, (str, bytes, os.PathLike)):
                p = os.path.realpath(os.fsdecode(path))
                if not p.startswith(sandbox_dir) and p not in ("/dev/null", "nul"):
                    raise PermissionError(f"sandbox: write blocked: {p}")
        elif event == "socket.connect":
            addr = args[1]
            if not isinstance(addr, tuple):
                raise PermissionError("sandbox: non-IP socket blocked")
            ip, port = str(addr[0]), int(addr[1])
            if ip not in allowed_ips or (allowed_ports and port not in allowed_ports):
                raise PermissionError(f"sandbox: egress to {ip}:{port} blocked")
        elif event == "socket.getaddrinfo":
            host = args[0]
            host = host.decode() if isinstance(host, bytes) else host
            if host is not None and str(host).lower() not in allowed_hosts and str(host) not in allowed_ips:
                raise PermissionError(f"sandbox: DNS lookup for {host} blocked")
        elif event in ("socket.bind", "socket.listen"):
            raise PermissionError("sandbox: listening sockets blocked")

    sys.addaudithook(hook)


def _pin_reachable_addresses(hosts: set[str], ports: set[int], probe_timeout: float = 1.0) -> None:
    """Make name resolution return only addresses that actually accept connections.

    On Windows "localhost" resolves to ::1 before 127.0.0.1; a dev server bound
    only to IPv4 then costs ~2s per request waiting for the IPv6 refusal. Probing
    once here (before lock-down) and filtering getaddrinfo removes that penalty.
    Falls back to the unfiltered answer when nothing (or everything) answers.
    """
    reachable: dict[str, set[str]] = {}
    for h in hosts:
        try:
            ipaddress.ip_address(h)
            continue  # literal IPs need no pinning
        except ValueError:
            pass
        good: set[str] = set()
        for port in ports:
            try:
                infos = socket.getaddrinfo(h, port, type=socket.SOCK_STREAM)
            except OSError:
                continue
            for fam, stype, proto, _, addr in infos:
                try:
                    with socket.socket(fam, stype, proto) as s:
                        s.settimeout(probe_timeout)
                        s.connect(addr)
                    good.add(addr[0])
                except OSError:
                    pass
        if good:
            reachable[h] = good
    if not reachable:
        return

    original = socket.getaddrinfo

    def getaddrinfo(host, *args, **kwargs):
        res = original(host, *args, **kwargs)
        key = host.decode() if isinstance(host, bytes) else host
        good = reachable.get(str(key).lower()) if key is not None else None
        if good:
            filtered = [r for r in res if r[4][0] in good]
            if filtered:
                return filtered
        return res

    socket.getaddrinfo = getaddrinfo


def main() -> None:
    cfg = json.load(sys.stdin)
    scan = cfg["scan"]
    sandbox_dir = cfg["sandbox_dir"]

    hosts, ports = set(), set()
    for d in scan["allowed_domains"]:
        pr = up.urlparse("//" + d.strip())
        if pr.hostname:
            hosts.add(pr.hostname.lower())
            if pr.port:
                ports.add(pr.port)
    t = up.urlparse(scan["target_url"])
    if t.hostname:
        hosts.add(t.hostname.lower())
        ports.add(t.port or (443 if t.scheme == "https" else 80))
    if any(":" not in d for d in scan["allowed_domains"]):
        ports.update({80, 443})

    ips: set[str] = set()
    for h in hosts:  # resolve once, before the lock engages
        try:
            ipaddress.ip_address(h)
            ips.add(h)
        except ValueError:
            try:
                infos = socket.getaddrinfo(h, None)
            except OSError:
                # An allowed name that does not resolve simply stays
                # unreachable (stricter, not looser); don't abort the scan.
                print(f"sandbox: allowed host {h!r} does not resolve; skipping",
                      file=sys.stderr)
                continue
            for info in infos:
                ips.add(info[4][0])

    _pin_reachable_addresses(hosts, ports)

    # Import everything the scan needs BEFORE the audit hook locks the process
    # down (later imports would be blocked). Do not let a linter prune these.
    import email.parser  # noqa: F401
    import email.utils  # noqa: F401
    import html.parser  # noqa: F401
    import http.client  # noqa: F401
    import ssl  # noqa: F401
    import urllib.request  # noqa: F401

    from scopeguard import engine, ratelimit  # noqa: F401

    os.chdir(sandbox_dir)
    _install_audit_hook(hosts, ips, ports, sandbox_dir)

    try:
        result = engine.run_scan(**scan)
        out = {"ok": True, "result": result, "sandbox": {
            "egress_ips": sorted(ips), "egress_ports": sorted(ports)}}
    except Exception as exc:  # report, never crash silently
        out = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    sys.stdout.write(json.dumps(out))


if __name__ == "__main__":
    main()
