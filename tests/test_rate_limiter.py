"""
tests/test_rate_limiter.py
--------------------------
Unit tests for the behavioral rate limiter (src/rate_limiter.py): ratio of
refused requests per IP over a sliding window, anti-dilution cap, and
escalating bans for repeat offenders.

Every behavioral test runs against both backends with a virtual clock. The
Redis backend needs a server at $WAF_TEST_REDIS_URL (default
redis://127.0.0.1:6379/15); those cases are skipped if none is reachable,
unless REQUIRE_REDIS=1 (set in CI).

Run:
    python -m pytest tests/test_rate_limiter.py -v
"""

from __future__ import annotations

import os
import random
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.rate_limiter import (
    RateLimiter,
    RateLimiterConfig,
    RedisRateLimiter,
    build_rate_limiter,
    limiter_config_from_dict,
)

REDIS_URL = os.environ.get("WAF_TEST_REDIS_URL", "redis://127.0.0.1:6379/15")

ATTACKER = "203.0.113.7"
USER = "198.51.100.20"


class FakeClock:
    def __init__(self, start: float = 1_700_000_000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _redis_client():
    try:
        import redis as redis_lib
        client = redis_lib.from_url(REDIS_URL)
        client.ping()
        return client
    except Exception:
        return None


@pytest.fixture(scope="module")
def redis_client():
    client = _redis_client()
    if client is None:
        if os.environ.get("REQUIRE_REDIS") == "1":
            pytest.fail(f"Redis required but unreachable at {REDIS_URL}")
        pytest.skip(f"no Redis server reachable at {REDIS_URL}")
    return client


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture(params=["memory", "redis"])
def make_limiter(request, clock):
    """Returns a factory: make_limiter(**config_overrides) -> limiter."""
    prefixes = []

    def factory(**overrides):
        config = RateLimiterConfig(**overrides)
        if request.param == "memory":
            return RateLimiter(config, clock=clock)
        client = request.getfixturevalue("redis_client")
        prefix = f"waf-test:{uuid.uuid4().hex}:"
        prefixes.append((client, prefix))
        return RedisRateLimiter(client, config, key_prefix=prefix, clock=clock)

    yield factory
    for client, prefix in prefixes:
        for key in client.scan_iter(match=f"{prefix}*"):
            client.delete(key)


def _send(limiter, ip, allowed=0, refused=0, weight=1):
    """Records `allowed` allowed then `refused` refused requests; returns
    the number of bans triggered."""
    bans = 0
    for _ in range(allowed):
        bans += limiter.record_request(ip, refused=False)
    for _ in range(refused):
        bans += limiter.record_request(ip, refused=True, weight=weight)
    return bans


# ── ratio rule ───────────────────────────────────────────────────────────────

class TestRatioBan:
    def test_pure_attacker_banned_at_threshold(self, make_limiter):
        rl = make_limiter()
        for i in range(4):
            assert rl.record_offense(ATTACKER) is False, f"banned early at offense {i + 1}"
        assert rl.record_offense(ATTACKER) is True
        assert rl.is_blocked(ATTACKER)
        assert rl.seconds_remaining_banned(ATTACKER) == pytest.approx(300)

    def test_busy_client_with_occasional_refusals_not_banned(self, make_limiter):
        # 10 refusals per window is over offense_threshold, but only 5% of traffic.
        rl = make_limiter()
        bans = 0
        for _ in range(10):
            bans += _send(rl, USER, allowed=19, refused=1)
        assert bans == 0
        assert not rl.is_blocked(USER)

    def test_ban_when_ratio_crosses_threshold(self, make_limiter):
        rl = make_limiter(refusal_ratio_threshold=0.5)
        assert _send(rl, ATTACKER, allowed=6, refused=5) == 0   # 5/11 < 0.5
        assert rl.record_offense(ATTACKER) is True             # 6/12 = 0.5

    def test_ratio_alone_does_not_ban_below_offense_threshold(self, make_limiter):
        rl = make_limiter(offense_threshold=5)
        assert _send(rl, USER, refused=4) == 0                  # ratio 1.0, only 4 refused
        assert not rl.is_blocked(USER)

    def test_ips_are_independent(self, make_limiter):
        rl = make_limiter()
        _send(rl, ATTACKER, refused=5)
        assert rl.is_blocked(ATTACKER)
        assert not rl.is_blocked(USER)
        assert _send(rl, USER, allowed=50, refused=1) == 0

    def test_weight_counts_toward_threshold(self, make_limiter):
        rl = make_limiter(offense_threshold=6)
        assert rl.record_offense(ATTACKER, weight=2) is False
        assert rl.record_offense(ATTACKER, weight=2) is False
        assert rl.record_offense(ATTACKER, weight=2) is True


class TestAntiDilution:
    def test_padding_with_benign_requests_hits_hard_cap(self, make_limiter):
        rl = make_limiter(hard_offense_threshold=20)
        bans = 0
        for _ in range(19):
            bans += _send(rl, ATTACKER, allowed=10, refused=1)  # ratio ~0.09 < 0.2
        assert bans == 0
        assert rl.record_offense(ATTACKER) is True             # 20th refusal in window

    def test_hard_cap_disabled(self, make_limiter):
        rl = make_limiter(hard_offense_threshold=0)
        assert sum(_send(rl, ATTACKER, allowed=10, refused=1) for _ in range(100)) == 0


class TestSlidingWindow:
    def test_refusals_spread_beyond_window_do_not_ban(self, make_limiter, clock):
        rl = make_limiter(offense_window_seconds=60)
        for _ in range(20):
            assert rl.record_offense(ATTACKER) is False
            clock.advance(16)                                   # at most 4 per 60 s
        assert not rl.is_blocked(ATTACKER)

    def test_old_allowed_requests_stop_diluting(self, make_limiter, clock):
        rl = make_limiter()
        _send(rl, ATTACKER, allowed=100)
        assert _send(rl, ATTACKER, refused=5) == 0              # diluted: 5/105
        clock.advance(61)
        assert _send(rl, ATTACKER, refused=5) == 1              # history expired: 5/5

    def test_ban_expires(self, make_limiter, clock):
        rl = make_limiter(ban_duration_seconds=300)
        _send(rl, ATTACKER, refused=5)
        clock.advance(299)
        assert rl.is_blocked(ATTACKER)
        clock.advance(2)
        assert not rl.is_blocked(ATTACKER)
        assert rl.seconds_remaining_banned(ATTACKER) == 0.0

    def test_window_reset_after_ban(self, make_limiter, clock):
        rl = make_limiter()
        _send(rl, ATTACKER, refused=5)
        clock.advance(301)
        assert _send(rl, ATTACKER, refused=4) == 0              # pre-ban refusals were cleared


class TestEscalation:
    def _ban(self, rl, clock):
        assert _send(rl, ATTACKER, refused=5) == 1
        remaining = rl.seconds_remaining_banned(ATTACKER)
        clock.advance(remaining + 1)
        return remaining

    def test_repeat_offender_ban_durations_escalate(self, make_limiter, clock):
        rl = make_limiter(ban_duration_seconds=300, ban_escalation_factor=4,
                          max_ban_duration_seconds=86400, offender_memory_seconds=10**7)
        durations = [self._ban(rl, clock) for _ in range(6)]
        assert durations == pytest.approx([300, 1200, 4800, 19200, 76800, 86400])
        assert rl.strikes(ATTACKER) == 6

    def test_strikes_forgotten_after_memory(self, make_limiter, clock):
        rl = make_limiter(ban_duration_seconds=300, offender_memory_seconds=3600)
        self._ban(rl, clock)
        self._ban(rl, clock)
        assert rl.strikes(ATTACKER) == 2
        clock.advance(3600)
        assert rl.strikes(ATTACKER) == 0
        assert self._ban(rl, clock) == pytest.approx(300)
        assert rl.strikes(ATTACKER) == 1

    def test_escalation_survives_bans_as_long_as_the_memory(self, make_limiter, clock):
        """Memory counts from the END of a ban: a ban lasting as long as
        offender_memory_seconds must not reset the strike count it earned."""
        rl = make_limiter(ban_duration_seconds=300, max_ban_duration_seconds=600,
                          offender_memory_seconds=600)
        durations = [self._ban(rl, clock) for _ in range(4)]
        assert durations == pytest.approx([300, 600, 600, 600])
        assert rl.strikes(ATTACKER) == 4

    def test_long_lived_offender_does_not_overflow(self, make_limiter, clock):
        rl = make_limiter(ban_duration_seconds=1, max_ban_duration_seconds=1,
                          offender_memory_seconds=10**9)
        for _ in range(100):
            assert self._ban(rl, clock) == pytest.approx(1)
        assert rl.strikes(ATTACKER) == 100
        assert RateLimiterConfig().ban_duration_for(10**6) == 86400

    def test_escalation_is_per_ip(self, make_limiter, clock):
        rl = make_limiter()
        self._ban(rl, clock)
        _send(rl, USER, refused=5)
        assert rl.seconds_remaining_banned(USER) == pytest.approx(300)
        assert rl.strikes(USER) == 1

    def test_stats_report_bans_and_repeat_offenders(self, make_limiter, clock):
        rl = make_limiter(offender_memory_seconds=10**7)
        self._ban(rl, clock)
        _send(rl, ATTACKER, refused=5)
        _send(rl, "2001:db8::1", refused=5)
        stats = rl.stats()
        assert stats["active_bans"] == {ATTACKER: pytest.approx(1200), "2001:db8::1": pytest.approx(300)}
        assert stats["repeat_offenders"] == {ATTACKER: 2}


# ── backend parity / Redis specifics ─────────────────────────────────────────

def test_memory_and_redis_backends_agree(redis_client):
    """Random mixed traffic from a few IPs over virtual time: both backends
    must ban on exactly the same requests."""
    rng = random.Random(1234)
    config = RateLimiterConfig(ban_duration_seconds=30, offender_memory_seconds=600)
    clock = FakeClock()
    prefix = f"waf-test:{uuid.uuid4().hex}:"
    mem = RateLimiter(config, clock=clock)
    red = RedisRateLimiter(redis_client, config, key_prefix=prefix, clock=clock)
    ips = [f"192.0.2.{i}" for i in range(5)]
    refusal_rate = {ip: p for ip, p in zip(ips, (0.0, 0.05, 0.2, 0.5, 0.9))}
    mem_bans, red_bans = [], []
    try:
        for step in range(4000):
            clock.advance(rng.expovariate(20))
            ip = rng.choice(ips)
            refused = rng.random() < refusal_rate[ip]
            weight = rng.choice((1, 1, 2))
            if mem.is_blocked(ip) != red.is_blocked(ip):
                pytest.fail(f"is_blocked diverged at step {step} for {ip}")
            if mem.is_blocked(ip):
                continue
            if mem.record_request(ip, refused, weight):
                mem_bans.append((step, ip))
            if red.record_request(ip, refused, weight):
                red_bans.append((step, ip))
        assert mem_bans == red_bans
        assert len(mem_bans) > 5, "sequence should exercise several bans"
        assert {ip: mem.strikes(ip) for ip in ips} == {ip: red.strikes(ip) for ip in ips}
    finally:
        for key in redis_client.scan_iter(match=f"{prefix}*"):
            redis_client.delete(key)


def test_redis_state_shared_across_workers(redis_client, clock):
    """Two limiter instances (two WAF worker processes) on one Redis: offenses
    sprayed across them add up, and a ban issued by one is seen by the other."""
    prefix = f"waf-test:{uuid.uuid4().hex}:"
    w1 = RedisRateLimiter(redis_client, RateLimiterConfig(), key_prefix=prefix, clock=clock)
    w2 = RedisRateLimiter(redis_client, RateLimiterConfig(), key_prefix=prefix, clock=clock)
    try:
        results = [(w1 if i % 2 else w2).record_offense(ATTACKER) for i in range(5)]
        assert results == [False] * 4 + [True]
        assert w1.is_blocked(ATTACKER) and w2.is_blocked(ATTACKER)
    finally:
        for key in redis_client.scan_iter(match=f"{prefix}*"):
            redis_client.delete(key)


def test_redis_keys_self_expire(redis_client):
    prefix = f"waf-test:{uuid.uuid4().hex}:"
    rl = RedisRateLimiter(redis_client, RateLimiterConfig(), key_prefix=prefix)
    try:
        _send(rl, USER, allowed=3)
        _send(rl, ATTACKER, refused=5)
        for key in redis_client.scan_iter(match=f"{prefix}*"):
            assert redis_client.ttl(key) > 0, f"{key!r} has no TTL"
    finally:
        for key in redis_client.scan_iter(match=f"{prefix}*"):
            redis_client.delete(key)


def test_redis_honours_ban_from_previous_version(redis_client):
    """Bans written by the previous limiter (value "1" + TTL) stay enforced
    across an upgrade."""
    prefix = f"waf-test:{uuid.uuid4().hex}:"
    rl = RedisRateLimiter(redis_client, RateLimiterConfig(), key_prefix=prefix)
    try:
        redis_client.set(f"{prefix}banned:{ATTACKER}", "1", ex=120)
        assert rl.is_blocked(ATTACKER)
        assert 0 < rl.seconds_remaining_banned(ATTACKER) <= 120
    finally:
        for key in redis_client.scan_iter(match=f"{prefix}*"):
            redis_client.delete(key)


# ── config / factory ─────────────────────────────────────────────────────────

def test_record_offense_only_callers_keep_fixed_threshold_semantics():
    """Callers that report only malicious requests see the original rule:
    offense_threshold offenses within the window -> ban."""
    rl = RateLimiter(RateLimiterConfig(offense_threshold=3), clock=FakeClock())
    assert [rl.record_offense(ATTACKER) for _ in range(3)] == [False, False, True]


def test_config_from_yaml_section():
    cfg = limiter_config_from_dict({
        "backend": "memory", "offense_threshold": 7, "refusal_ratio_threshold": 0.3,
        "ban_escalation_factor": 2, "max_ban_duration_seconds": 3600,
    })
    assert cfg.offense_threshold == 7
    assert cfg.refusal_ratio_threshold == 0.3
    assert cfg.ban_escalation_factor == 2.0
    assert cfg.hard_offense_threshold == RateLimiterConfig().hard_offense_threshold


def test_shipped_waf_config_matches_defaults():
    import yaml
    config_path = Path(__file__).resolve().parent.parent / "config" / "waf_config.yaml"
    section = yaml.safe_load(config_path.read_text())["rate_limit"]
    assert limiter_config_from_dict(section) == RateLimiterConfig()


@pytest.mark.parametrize("bad", [
    {"refusal_ratio_threshold": 0.0}, {"refusal_ratio_threshold": 1.5},
    {"window_buckets": 0}, {"ban_escalation_factor": 0.5},
    {"ban_duration_seconds": 600, "max_ban_duration_seconds": 300},
])
def test_invalid_config_rejected(bad):
    with pytest.raises(ValueError):
        RateLimiterConfig(**bad)


def test_factory_falls_back_to_memory_when_redis_unreachable():
    rl = build_rate_limiter({"backend": "redis", "redis_url": "redis://127.0.0.1:1/0"})
    assert isinstance(rl, RateLimiter)


def test_factory_builds_redis_backend(redis_client):
    rl = build_rate_limiter({"backend": "redis", "redis_url": REDIS_URL,
                             "key_prefix": f"waf-test:{uuid.uuid4().hex}:"})
    assert isinstance(rl, RedisRateLimiter)
    assert rl.stats()["backend"] == "redis"
