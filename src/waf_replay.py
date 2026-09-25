"""
waf_replay.py
-------------
Replays recorded HTTP requests (e.g. CSIC 2010, src/csic2010.py) through a
LIVE WafProxy: a real aiohttp server on a loopback TCP port, in front of a
stub backend that answers 200 to everything, driven by a real HTTP client.

Each request is attributed to a client IP chosen by the caller. The WAF is
configured to trust X-Forwarded-For from 127.0.0.1 only, so the harness can
present many distinct client IPs while every connection comes from loopback
-- the same path a deployment behind Caddy/nginx takes.

Every refusal looks the same on the wire (403 + request_id), so the harness
does not guess from responses: it wraps the WAF's rate limiter and records,
per request, exactly what the WAF fed it (allowed / refused + weight) and
whether the request was turned away by an active ban.

Used by scripts/09_csic_rate_limit_validation.py and
tests/integration/test_rate_limiter_live.py.
"""

from __future__ import annotations

import copy
from contextlib import asynccontextmanager
from dataclasses import dataclass

from aiohttp import ClientSession, web
from yarl import URL

from src.csic2010 import CsicRequest
from src.waf_proxy import create_app, load_config

# Hop-by-hop / framing headers the client library sets itself.
_SKIP_HEADERS = {"host", "content-length", "connection", "transfer-encoding"}


@dataclass
class ReplayResult:
    status: int                         # 0 = the client could not send it
    client_ip: str
    decision: tuple[bool, int] | None   # (refused, weight) the WAF recorded, None if none
    ban_rejected: bool                  # turned away because the IP was banned
    ban_issued: bool                    # this request got the IP banned

    @property
    def refused(self) -> bool:
        return self.decision is not None and self.decision[0]


class RecordingLimiter:
    """Transparent wrapper around a WAF's rate limiter that remembers the
    calls made while handling the current request."""

    def __init__(self, inner):
        object.__setattr__(self, "_inner", inner)
        self.begin()

    def begin(self) -> None:
        object.__setattr__(self, "decision", None)
        object.__setattr__(self, "ban_rejected", False)
        object.__setattr__(self, "ban_issued", False)

    def is_blocked(self, ip: str) -> bool:
        blocked = self._inner.is_blocked(ip)
        if blocked:
            object.__setattr__(self, "ban_rejected", True)
        return blocked

    def record_request(self, ip: str, refused: bool, weight: int = 1) -> bool:
        object.__setattr__(self, "decision", (refused, weight if refused else 1))
        banned = self._inner.record_request(ip, refused=refused, weight=weight)
        object.__setattr__(self, "ban_issued", banned)
        return banned

    def record_offense(self, ip: str, weight: int = 1) -> bool:
        return self.record_request(ip, refused=True, weight=weight)

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def __setattr__(self, name, value):
        setattr(self._inner, name, value)   # e.g. tests swapping in a virtual clock


async def _start_site(app: web.Application) -> tuple[web.AppRunner, str]:
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    return runner, f"http://127.0.0.1:{port}"


@asynccontextmanager
async def live_waf(rate_limit: dict | None = None, log_path: str = "logs/waf_replay.log", **overrides):
    """Starts a stub backend and a live WAF (shipped config, block mode) in
    front of it. Yields (base_url, waf); waf.rate_limiter is a
    RecordingLimiter. `rate_limit` replaces the config's rate_limit section;
    other keyword arguments override top-level config keys."""
    backend = web.Application()

    async def ok(_request):
        return web.Response(text="ok")

    backend.router.add_route("*", "/{tail:.*}", ok)
    backend_runner, backend_url = await _start_site(backend)

    config = copy.deepcopy(load_config())
    config.update(backend_url=backend_url, trusted_proxies=["127.0.0.1"], log_path=log_path,
                  static_allow_ips=[], static_deny_ips=[], mode="block")
    if rate_limit is not None:
        config["rate_limit"] = rate_limit
    config.update(overrides)

    app, waf = create_app(config)
    waf.logger.also_print = False
    waf.rate_limiter = RecordingLimiter(waf.rate_limiter)
    waf_runner, waf_url = await _start_site(app)
    try:
        yield waf_url, waf
    finally:
        await waf_runner.cleanup()
        await backend_runner.cleanup()


async def send(session: ClientSession, waf_url: str, req: CsicRequest, client_ip: str) -> int:
    """Sends one request as `client_ip`; returns the HTTP status (0 if the
    client library refuses to put the request on the wire)."""
    headers = {k: v for k, v in req.headers if k.lower() not in _SKIP_HEADERS}
    headers["X-Forwarded-For"] = client_ip
    try:
        url = URL(waf_url + req.path_qs, encoded=True)
        async with session.request(req.method, url, headers=headers, data=req.body or None,
                                   allow_redirects=False) as resp:
            await resp.read()
            return resp.status
    except Exception:
        # A handful of CSIC anomalous requests carry targets no HTTP client
        # will send (raw spaces, bare CR/LF in the path).
        return 0


async def replay(waf_url: str, waf, requests: list[CsicRequest], client_ips: list[str]) -> list[ReplayResult]:
    """Sends requests[i] as client_ips[i], in order, one at a time, and
    records what the WAF's rate limiter saw for each."""
    recorder: RecordingLimiter = waf.rate_limiter
    results = []
    async with ClientSession() as session:
        for req, ip in zip(requests, client_ips):
            recorder.begin()
            status = await send(session, waf_url, req, ip)
            results.append(ReplayResult(status, ip, recorder.decision, recorder.ban_rejected,
                                        recorder.ban_issued))
    return results


def chunked_client_ips(n_requests: int, client_size: int, base: str = "10") -> list[str]:
    """Assigns consecutive runs of `client_size` requests to one synthetic
    client IP each (10.x.y.z), preserving the dataset's request order."""
    ips = []
    for i in range(n_requests):
        c = i // client_size
        ips.append(f"{base}.{(c >> 16) & 255}.{(c >> 8) & 255}.{c & 255}")
    return ips


class VirtualClock:
    def __init__(self, start: float = 1_700_000_000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now


def replay_decisions(limiter, clock: VirtualClock, decisions: list[tuple[bool, int] | None],
                     client_ips: list[str], interval_seconds: float) -> dict:
    """Feeds recorded WAF decisions (refused, weight) into a rate limiter
    under virtual time, one request every `interval_seconds`, exactly as
    waf_proxy.py would: requests from a banned IP are turned away and not
    recorded; requests the WAF recorded nothing for (None) are skipped.
    Lets one live-measured refusal sequence be checked under many
    client/timing scenarios cheaply."""
    start = clock.now
    bans, rejected_while_banned = [], 0
    for i, (decision, ip) in enumerate(zip(decisions, client_ips)):
        clock.now = start + i * interval_seconds
        if limiter.is_blocked(ip):
            rejected_while_banned += 1
            continue
        if decision is not None and limiter.record_request(ip, refused=decision[0], weight=decision[1]):
            bans.append(ip)
    return {"bans": len(bans), "banned_ips": len(set(bans)), "ban_rejected_requests": rejected_while_banned}


def max_refusals_in_run(refused: list[int], k: int) -> int:
    """Largest weighted refusal count over any k consecutive requests."""
    k = min(k, len(refused))
    s = best = sum(refused[:k])
    for i in range(k, len(refused)):
        s += refused[i] - refused[i - k]
        best = max(best, s)
    return best
