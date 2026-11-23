"""Which IP addresses a scan may ever connect to (stdlib only).

Shared by every layer that touches the network:

* ``pentest_agent.guardrails.pre_run_guardrail`` checks the target and every
  extra allowed host before a scan starts;
* ``pentest_agent.http_retry`` resolves, checks and then connects to exactly
  the checked IP on every new connection (so a DNS answer that changes
  mid-scan, i.e. DNS rebinding, cannot point a request somewhere else);
* ``scopeguard.worker`` drops blocked IPs before it pins the sandbox's
  egress allowlist.

Always blocked: link-local (where cloud metadata services live, e.g.
169.254.169.254, which hands out instance credentials), the known cloud
metadata addresses and names, "this network" 0.0.0.0/8, multicast, reserved
and broadcast. IPv6 forms that embed an IPv4 address (IPv4-mapped, NAT64,
6to4, Teredo) are unwrapped and checked as the IPv4 address.

Loopback and private ranges stay allowed (local dev targets, the built-in
demo target) unless ``block_private`` is set (BLOCK_PRIVATE_TARGETS=true).
"""
from __future__ import annotations

import ipaddress
import socket

_net = ipaddress.ip_network

ALWAYS_BLOCKED = (
    (_net("169.254.0.0/16"), "link-local / cloud metadata"),
    (_net("fe80::/10"), "IPv6 link-local"),
    (_net("fd00:ec2::254/128"), "AWS IPv6 metadata service"),
    (_net("100.100.100.200/32"), "Alibaba Cloud metadata service"),
    (_net("192.0.0.192/32"), "Oracle Cloud metadata service"),
    (_net("0.0.0.0/8"), "'this network' (0.0.0.0 reaches the local host)"),
    (_net("::/128"), "unspecified address"),
    (_net("224.0.0.0/4"), "multicast"),
    (_net("ff00::/8"), "IPv6 multicast"),
    (_net("240.0.0.0/4"), "reserved"),
    (_net("255.255.255.255/32"), "broadcast"),
)
PRIVATE = (
    (_net("127.0.0.0/8"), "loopback"),
    (_net("::1/128"), "IPv6 loopback"),
    (_net("10.0.0.0/8"), "private network"),
    (_net("172.16.0.0/12"), "private network"),
    (_net("192.168.0.0/16"), "private network"),
    (_net("100.64.0.0/10"), "carrier-grade NAT"),
    (_net("fc00::/7"), "IPv6 unique local"),
)
# Names that resolve to a metadata service (some only inside the cloud network).
BLOCKED_HOSTNAMES = frozenset({
    "metadata", "metadata.google.internal", "metadata.goog", "instance-data",
    "instance-data.ec2.internal", "metadata.azure.internal", "metadata.tencentyun.com",
})
LOCAL_HOSTNAMES = ("localhost",)
_NAT64 = _net("64:ff9b::/96")


class BlockedAddress(ValueError):
    """The host is, or resolves to, an address scans must never reach."""


def _embedded_ipv4(ip: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    if ip.ipv4_mapped:
        return ip.ipv4_mapped
    if ip in _NAT64:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    if ip.sixtofour:
        return ip.sixtofour
    if ip.teredo:
        return ip.teredo[1]
    return None


def blocked_reason(ip: str | ipaddress.IPv4Address | ipaddress.IPv6Address,
                   *, block_private: bool = False) -> str | None:
    """Why this address is off limits, or None when it may be scanned."""
    addr = ipaddress.ip_address(str(ip).split("%", 1)[0])  # drop an IPv6 zone id
    candidates = [addr]
    if isinstance(addr, ipaddress.IPv6Address):
        inner = _embedded_ipv4(addr)
        if inner is not None:
            candidates.append(inner)
    rules = ALWAYS_BLOCKED + (PRIVATE if block_private else ())
    for candidate in candidates:
        for network, label in rules:
            if candidate.version == network.version and candidate in network:
                shown = f"{addr} ({candidate})" if candidate is not addr else str(addr)
                return f"{shown} is {label}"
    return None


def resolve(host: str, port: int | None = None) -> list[str]:
    """All addresses ``host`` resolves to (de-duplicated, resolver order)."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    seen: list[str] = []
    for info in infos:
        ip = str(info[4][0])
        if ip not in seen:
            seen.append(ip)
    return seen


def check_host(host: str, port: int | None = None, *, block_private: bool = False) -> list[str]:
    """Resolve ``host`` and return its addresses if *all* of them may be scanned.

    Raises BlockedAddress when the name, or any address it resolves to, is
    blocked (a name that mixes a public and a metadata address is refused as a
    whole). Returns [] when the name does not resolve."""
    name = str(host).strip().strip("[]").rstrip(".").lower()
    if not name:
        raise BlockedAddress("empty host name")
    if name in BLOCKED_HOSTNAMES:
        raise BlockedAddress(f"{name} is a cloud metadata host name")
    if block_private and (name in LOCAL_HOSTNAMES or name.endswith(".localhost")):
        raise BlockedAddress(f"{name} is the local host (BLOCK_PRIVATE_TARGETS=true)")
    try:
        ips = [str(ipaddress.ip_address(name.split("%", 1)[0]))]
    except ValueError:
        try:
            ips = resolve(name, port)
        except (OSError, UnicodeError):
            return []
    for ip in ips:
        reason = blocked_reason(ip, block_private=block_private)
        if reason:
            raise BlockedAddress(f"{name} resolves to {reason}" if ip != name else reason)
    return ips


def allowed_ips(ips, *, block_private: bool = False) -> tuple[set[str], list[str]]:
    """Split addresses into (allowed, reasons for the blocked ones)."""
    ok, blocked = set(), []
    for ip in ips:
        reason = blocked_reason(ip, block_private=block_private)
        if reason:
            blocked.append(reason)
        else:
            ok.add(str(ip))
    return ok, blocked
