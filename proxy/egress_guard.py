"""ConsentCheck egress guard (mitmproxy addon).

The browser sandbox sits on an internal-only Docker network. This proxy is its
single route to the internet, so it is the place to enforce and witness egress:

* every request is written to an append-only JSON-lines log that the sandbox
  cannot touch (independent evidence for the report);
* requests to private, loopback, link-local (cloud metadata) and other
  internal addresses are refused with a 403 and logged as "blocked";
* hosts ending in .consentcheck.test are served from the bundled demo sites,
  so the containment demo works the same everywhere.
"""

import asyncio
import ipaddress
import json
import mimetypes
import os
import socket
import time
from pathlib import Path

from mitmproxy import http

DEMO_ROOT = (Path(__file__).parent / "demo_site").resolve()
DEMO_SUFFIX = ".consentcheck.test"
LOG_PATH = Path(os.environ.get("CC_PROXY_LOG", "/evidence/proxy_log.jsonl"))
BLOCKED_HOSTNAMES = {
    "localhost", "metadata", "metadata.google.internal", "instance-data",
    "host.docker.internal", "gateway.docker.internal",
}
# The auditor's own public address and hostname (set by the orchestrator), so a
# page under audit cannot call back into the ConsentCheck API.
SELF_HOSTS = {h.strip().lower().rstrip(".") for h in os.environ.get("CC_BLOCK_HOSTS", "").split(",") if h.strip()}
MAX_LOG_LINES = 20000
CACHE_TTL = 120
_cache: dict = {}  # host -> (expires, reason, ip): one checked answer per host per scan
_raw_getaddrinfo = None  # the unfiltered resolver, kept for the logging pre-check


async def check_host(host):
    """Return (block_reason, pinned_ip). Connections go to pinned_ip only, so a DNS
    answer that changes between the check and the connection (rebinding) is never used.
    Answers are cached briefly; resolution runs off the event loop."""
    h = host.lower().rstrip(".")
    hit = _cache.get(h)
    if hit and hit[0] > time.time():
        return hit[1], hit[2]
    result = await _check(h)
    _cache[h] = (time.time() + CACHE_TTL, *result)
    return result


def _is_allowed_ip(addr):
    try:
        ip = ipaddress.ip_address(str(addr).split("%")[0])
    except ValueError:
        return False
    return ip.is_global and str(ip) not in SELF_HOSTS


async def _check(h):
    if h in BLOCKED_HOSTNAMES:
        return f"internal hostname '{h}'", None
    if h in SELF_HOSTS:
        return "the auditor's own server", None
    try:
        ips = [ipaddress.ip_address(h)]
    except ValueError:
        try:
            infos = await (_raw_getaddrinfo or asyncio.get_running_loop().getaddrinfo)(h, None)
            ips = sorted({ipaddress.ip_address(ai[4][0].split("%")[0]) for ai in infos}, key=lambda ip: ip.version)
        except (socket.gaierror, UnicodeError):
            return None, None  # unresolvable: let the upstream connection fail normally
    for ip in ips:
        if str(ip) in SELF_HOSTS:
            return "the auditor's own server", None
        if str(ip) == "169.254.169.254" or str(ip).startswith("fd00:ec2::254"):
            return f"cloud metadata endpoint {ip}", None
        if not ip.is_global:  # private, loopback, link-local, CGNAT, reserved, multicast...
            return f"internal address {ip}", None
    return None, (str(ips[0]) if ips else None)


class EgressGuard:
    def __init__(self):
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        self.f = LOG_PATH.open("a", buffering=1)
        self.lines = 0

    def log(self, **entry):
        # Cap the evidence log so a hostile page cannot fill the host disk.
        if self.lines > MAX_LOG_LINES:
            return
        self.lines += 1
        entry["ts"] = round(time.time(), 3)
        if self.lines > MAX_LOG_LINES:
            entry = {"action": "log_truncated", "ts": entry["ts"], "after": MAX_LOG_LINES}
        self.f.write(json.dumps(entry) + "\n")

    def _block(self, flow, host, url, reason):
        flow.response = http.Response.make(
            403, b"Blocked by ConsentCheck egress guard\n",
            {"x-consentcheck-blocked": reason, "content-type": "text/plain"},
        )
        self.log(action="blocked", host=host, method=flow.request.method, url=url, reason=reason)

    async def http_connect(self, flow: http.HTTPFlow):
        host = flow.request.host
        if host.endswith(DEMO_SUFFIX):
            return
        reason, _ = await check_host(host)
        if reason:
            self._block(flow, host, f"CONNECT {host}:{flow.request.port}", reason)

    async def request(self, flow: http.HTTPFlow):
        host = flow.request.pretty_host
        url = flow.request.pretty_url[:2000]
        if host.endswith(DEMO_SUFFIX):
            self._serve_demo(flow, host)
            self.log(action="demo", host=host, method=flow.request.method, url=url)
            return
        reason, _ = await check_host(host)
        if reason:
            self._block(flow, host, url, reason)
            return
        self.log(action="allowed", host=host, method=flow.request.method, url=url)

    def running(self):
        """Filter the proxy's own DNS answers. mitmproxy connects with the addresses
        returned here, so an internal address is dropped from the very answer that is
        used for the connection: a DNS rebinding trick (public IP at check time,
        internal IP at connect time) has nothing left to connect to."""
        global _raw_getaddrinfo
        loop = asyncio.get_running_loop()
        original = _raw_getaddrinfo = loop.getaddrinfo

        async def guarded_getaddrinfo(host, port, *args, **kwargs):
            infos = await original(host, port, *args, **kwargs)
            safe = [ai for ai in infos if _is_allowed_ip(ai[4][0])]
            if not safe:
                raise socket.gaierror(socket.EAI_NONAME, f"blocked by ConsentCheck egress guard: {host}")
            return safe

        loop.getaddrinfo = guarded_getaddrinfo

    def _serve_demo(self, flow, host):
        site = host[: -len(DEMO_SUFFIX)].split(".")[-1]
        path = flow.request.path.split("?")[0].lstrip("/") or "index.html"
        target = (DEMO_ROOT / site / path).resolve()
        if not str(target).startswith(str(DEMO_ROOT)) or not target.is_file():
            # Collector endpoints (e.g. a fake attacker beacon) just get a 204.
            flow.response = http.Response.make(204, b"", {"cache-control": "no-store"})
            return
        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        flow.response = http.Response.make(
            200, target.read_bytes(), {"content-type": ctype, "cache-control": "no-store"}
        )


addons = [EgressGuard()]
