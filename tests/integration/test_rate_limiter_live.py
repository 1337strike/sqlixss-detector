"""
tests/integration/test_rate_limiter_live.py
-------------------------------------------
Live tests for the WAF's behavioral rate limiter: a real WafProxy on a
loopback TCP port in front of a stub backend, driven over HTTP
(src/waf_replay.py). Client IPs are presented via X-Forwarded-For from the
trusted loopback proxy.

Detections and bans return the same 403, so ban state is read from the
WAF's own limiter (waf.rate_limiter) and counters, never inferred from
responses.

Every test runs against both limiter backends. The Redis cases need a
server at $WAF_TEST_REDIS_URL (default redis://127.0.0.1:6379/15); they are
skipped without one, unless REQUIRE_REDIS=1 (set in CI), which makes a
missing Redis a failure. The CSIC 2010 test needs the dataset
(python scripts/00b_download_csic2010.py) and is skipped without it.

Run:
    python -m pytest tests/integration/test_rate_limiter_live.py -v
"""

from __future__ import annotations

import asyncio
import os
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from aiohttp import ClientSession

from src.csic2010 import CSIC_DIR, NORMAL_FILES, CsicRequest, load_csic
from src.rate_limiter import RateLimiter, RedisRateLimiter, limiter_config_from_dict
from src.waf_proxy import load_config
from src.waf_replay import (
    VirtualClock, chunked_client_ips, live_waf, replay, replay_decisions, send,
)

REDIS_URL = os.environ.get("WAF_TEST_REDIS_URL", "redis://127.0.0.1:6379/15")
LOG_PATH = str(Path(__file__).resolve().parent.parent.parent / "logs" / "test_rate_limiter_live.log")

ATTACK = CsicRequest("GET", "/search?q=%27+UNION+SELECT+password+FROM+users--")
BENIGN = CsicRequest("GET", "/search?q=laptop&page=2")


def _redis_or_none():
    try:
        import redis as redis_lib
        client = redis_lib.from_url(REDIS_URL, socket_connect_timeout=1)
        client.ping()
        return client
    except Exception as e:
        if os.environ.get("REQUIRE_REDIS") == "1":
            pytest.fail(f"Redis required but unreachable at {REDIS_URL}: {e}")
        return None


def _redis_or_skip():
    client = _redis_or_none()
    if client is None:
        pytest.skip(f"no Redis server reachable at {REDIS_URL}")
    return client


@pytest.fixture(params=["memory", "redis"])
def rate_limit(request):
    """The shipped rate_limit config section, on the parametrized backend,
    under a unique Redis key prefix that is purged afterwards."""
    section = dict(load_config()["rate_limit"])
    prefix = f"waf-live-test:{uuid.uuid4().hex}:"
    section.update(backend=request.param, redis_url=REDIS_URL, key_prefix=prefix)
    client = _redis_or_skip() if request.param == "redis" else None
    yield section
    if client is not None:
        for key in client.scan_iter(match=f"{prefix}*"):
            client.delete(key)


def run(coro):
    return asyncio.run(coro)


async def _statuses(url, pattern: list[CsicRequest], ip: str) -> list[int]:
    async with ClientSession() as session:
        return [await send(session, url, req, ip) for req in pattern]


def test_attacker_is_banned(rate_limit):
    """offense_threshold refused requests at a high ratio ban the IP: its
    next BENIGN request is refused too, while another IP's is forwarded."""
    ip = "203.0.113.10"

    async def scenario():
        async with live_waf(rate_limit, LOG_PATH) as (url, waf):
            attacks = await _statuses(url, [ATTACK] * 4, ip)
            banned_before = waf.rate_limiter.is_blocked(ip)
            attacks += await _statuses(url, [ATTACK], ip)
            after = await _statuses(url, [BENIGN], ip)
            other = await _statuses(url, [BENIGN], "198.51.100.10")
            return (attacks, banned_before, after, other, waf.stats.get_all(),
                    waf.rate_limiter.seconds_remaining_banned(ip))

    attacks, banned_before, after, other, stats, remaining = run(scenario())
    assert attacks == [403] * 5
    assert not banned_before
    assert after == [403] and other == [200]
    assert stats["banned_ips_triggered"] == 1
    assert 295 <= remaining <= 300


def test_ban_refusal_looks_like_any_other_refusal(rate_limit):
    """The ban layer must not reintroduce an oracle: a banned IP's request
    gets the same 403 {"error", "request_id"} as a detection."""
    ip = "203.0.113.11"

    async def scenario():
        async with live_waf(rate_limit, LOG_PATH) as (url, waf):
            async with ClientSession() as session:
                async def probe(req):
                    async with session.get(url + req.path_qs, headers={"X-Forwarded-For": ip}) as resp:
                        return resp.status, sorted(await resp.json())
                detection = await probe(ATTACK)
                for _ in range(4):
                    await probe(ATTACK)
                assert waf.rate_limiter.is_blocked(ip)
                return detection, await probe(BENIGN)

    detection, banned = run(scenario())
    assert detection == banned == (403, ["error", "request_id"])


def test_client_with_occasional_false_positives_is_not_banned(rate_limit):
    """A busy legitimate client whose traffic trips the detector 1 time in
    10 is refused more than offense_threshold times, yet never banned."""
    ip = "198.51.100.30"

    async def scenario():
        async with live_waf(rate_limit, LOG_PATH) as (url, waf):
            statuses = await _statuses(url, ([BENIGN] * 9 + [ATTACK]) * 10, ip)
            return statuses, waf.rate_limiter.is_blocked(ip), waf.stats.get_all()

    statuses, blocked, stats = run(scenario())
    assert statuses == ([200] * 9 + [403]) * 10
    assert not blocked
    assert stats["banned_ips_triggered"] == 0


def test_benign_padding_cannot_hide_a_sustained_attack(rate_limit):
    """Anti-dilution: padding every payload with benign requests keeps the
    ratio low, but the hard cap still bans the IP."""
    cap = limiter_config_from_dict(rate_limit).hard_offense_threshold
    ip = "203.0.113.12"

    async def scenario():
        async with live_waf(rate_limit, LOG_PATH) as (url, waf):
            statuses = await _statuses(url, ([BENIGN] * 9 + [ATTACK]) * cap, ip)
            return statuses, waf.rate_limiter.is_blocked(ip), await _statuses(url, [BENIGN], ip)

    statuses, blocked, after = run(scenario())
    assert statuses == ([200] * 9 + [403]) * cap
    assert blocked and after == [403]


def test_repeat_offender_bans_escalate(rate_limit):
    """Drives the live WAF's limiter with a virtual clock across ban expiry:
    each new ban is ban_escalation_factor times longer than the last, and
    the IP is served again once a ban runs out."""
    config = limiter_config_from_dict(rate_limit)
    ip = "203.0.113.13"

    async def scenario():
        async with live_waf(rate_limit, LOG_PATH) as (url, waf):
            clock = VirtualClock()
            waf.rate_limiter.clock = clock
            durations, served_after = [], []
            for _ in range(3):
                assert await _statuses(url, [ATTACK] * 5, ip) == [403] * 5
                durations.append(waf.rate_limiter.seconds_remaining_banned(ip))
                clock.now += durations[-1] - 1
                assert await _statuses(url, [BENIGN], ip) == [403]      # still banned
                clock.now += 2
                served_after.append((await _statuses(url, [BENIGN], ip))[0])
            return durations, served_after, waf.rate_limiter.strikes(ip)

    durations, served_after, strikes = run(scenario())
    base, factor = config.ban_duration_seconds, config.ban_escalation_factor
    assert durations == pytest.approx([base, base * factor, base * factor ** 2])
    assert served_after == [200, 200, 200]
    assert strikes == 3


def test_ban_is_shared_across_waf_workers(rate_limit):
    """Two WAF processes sharing one Redis: offenses sprayed across both add
    up to one ban that both enforce."""
    if rate_limit["backend"] != "redis":
        pytest.skip("cross-worker state requires the Redis backend")
    ip = "203.0.113.14"

    async def scenario():
        async with live_waf(rate_limit, LOG_PATH) as (url1, w1), live_waf(rate_limit, LOG_PATH) as (url2, w2):
            async with ClientSession() as session:
                for i in range(5):
                    assert await send(session, (url1, url2)[i % 2], ATTACK, ip) == 403
                return (w1.rate_limiter.is_blocked(ip), w2.rate_limiter.is_blocked(ip),
                        await send(session, url1, BENIGN, ip), await send(session, url2, BENIGN, ip))

    assert run(scenario()) == (True, True, 403, 403)


@pytest.mark.skipif(not all((CSIC_DIR / f).exists() for f in NORMAL_FILES),
                    reason="CSIC 2010 not downloaded (python scripts/00b_download_csic2010.py)")
def test_csic2010_normal_traffic_triggers_no_bans():
    """All 72,000 CSIC 2010 normal requests, live through the WAF with the
    shipped config (Redis backend if reachable, else in-memory), as 720
    clients of 100 consecutive requests: zero bans. The limiter input
    recorded per request is then replayed into both backends as a single IP
    at 1/10/100 req/s: still zero bans.

    Runs once rather than per backend: the live pass takes ~3 minutes.
    scripts/09_csic_rate_limit_validation.py adds a noisy-detector stress
    configuration and more client/timing scenarios."""
    section = dict(load_config()["rate_limit"])
    prefix = f"waf-live-test:{uuid.uuid4().hex}:"
    client = _redis_or_none()
    section.update(backend="redis" if client else "memory", redis_url=REDIS_URL, key_prefix=prefix)

    normal = load_csic("normal")
    ips = chunked_client_ips(len(normal), 100)

    async def scenario():
        async with live_waf(section, LOG_PATH) as (url, waf):
            results = await replay(url, waf, normal, ips)
            return results, waf.stats.get_all()

    try:
        results, stats = run(scenario())
        assert len(results) == 72000
        assert all(r.status in (200, 403) for r in results)
        assert all(r.decision is not None for r in results), "every request must reach the limiter"
        assert not any(r.ban_rejected or r.ban_issued for r in results)
        assert stats["banned_ips_triggered"] == 0

        config = limiter_config_from_dict(section)
        decisions = [r.decision for r in results]
        for rps in (1, 10, 100):
            limiters = [lambda clock: RateLimiter(config, clock=clock)]
            if client is not None:
                limiters.append(lambda clock: RedisRateLimiter(client, config, key_prefix=f"{prefix}{rps}:",
                                                               clock=clock))
            for make in limiters:
                clock = VirtualClock()
                limiter = make(clock)
                res = replay_decisions(limiter, clock, decisions, ["192.0.2.1"] * len(decisions), 1.0 / rps)
                assert res["bans"] == 0, f"{type(limiter).__name__}: single IP at {rps} req/s was banned"
    finally:
        if client is not None:
            for key in client.scan_iter(match=f"{prefix}*"):
                client.delete(key)
