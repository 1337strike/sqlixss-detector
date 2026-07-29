"""
rate_limiter.py
----------------
Real WAFs don't just block one bad request and move on -- an IP that keeps
sending malicious payloads gets temporarily banned outright (this is what
Cloudflare's "I'm Under Attack Mode", fail2ban, and ModSecurity's
mod_qos/rate-limiting all do in different ways).

Two implementations, same interface (`record_offense`, `is_blocked`,
`seconds_remaining_banned`, `stats`):

  - RateLimiter       : in-memory, sliding-window offense counter.
                        Zero dependencies, perfect for local dev/testing
                        or a genuinely single-process deployment.
  - RedisRateLimiter   : same logic, backed by Redis (INCR + EXPIRE +
                        a SET of active bans). State is shared across
                        every WAF worker process/replica, and survives a
                        WAF restart -- this is the one to use for anything
                        internet-facing running more than one process
                        (see README §4 "Running multiple workers").

`build_rate_limiter(config)` picks the right one from config so the rest
of the codebase (waf_proxy.py) doesn't need to know which backend is active.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from dataclasses import dataclass


@dataclass
class RateLimiterConfig:
    offense_window_seconds: int = 60      # sliding window to count offenses in
    offense_threshold: int = 5             # offenses within the window that triggers a ban
    ban_duration_seconds: int = 300        # how long an IP stays banned once triggered


class RateLimiter:
    """In-memory implementation. See module docstring for when to use this
    vs RedisRateLimiter."""

    def __init__(self, config: RateLimiterConfig | None = None):
        self.config = config or RateLimiterConfig()
        self._offenses: dict[str, deque[float]] = defaultdict(deque)
        self._banned_until: dict[str, float] = {}

    def is_blocked(self, ip: str) -> bool:
        banned_until = self._banned_until.get(ip)
        if banned_until is None:
            return False
        if time.time() >= banned_until:
            del self._banned_until[ip]  # ban expired, clean up
            return False
        return True

    def record_offense(self, ip: str, weight: int = 1) -> bool:
        """
        Call this once per malicious request from `ip`. Returns True if this
        offense just pushed the IP over the threshold and triggered a new ban.

        `weight` lets higher-confidence signals count for more than a single
        offense -- e.g. a known-scanner User-Agent or a probe of /.git/config
        is much stronger evidence of hostile intent than one ambiguous ML
        classification, so recon_detection.py's callers pass weight=2 to
        reach the ban threshold faster than ordinary payload matches do.
        """
        now = time.time()
        window_start = now - self.config.offense_window_seconds

        offenses = self._offenses[ip]
        for _ in range(max(1, weight)):
            offenses.append(now)
        while offenses and offenses[0] < window_start:
            offenses.popleft()

        if len(offenses) >= self.config.offense_threshold:
            self._banned_until[ip] = now + self.config.ban_duration_seconds
            offenses.clear()
            return True
        return False

    def seconds_remaining_banned(self, ip: str) -> float:
        banned_until = self._banned_until.get(ip)
        if banned_until is None:
            return 0.0
        return max(0.0, banned_until - time.time())

    def stats(self) -> dict:
        now = time.time()
        active_bans = {ip: round(t - now, 1) for ip, t in self._banned_until.items() if t > now}
        return {
            "backend": "memory",
            "tracked_ips": len(self._offenses),
            "active_bans": active_bans,
        }


class RedisRateLimiter:
    """
    Redis-backed implementation with the exact same interface as
    RateLimiter. Use this whenever the WAF runs as more than one process
    (multiple gunicorn workers, multiple machines behind a load balancer)
    -- with the in-memory version, each process/replica would track
    offenses independently, so an attacker could spray requests across
    workers and never trip any single one's threshold.

    Redis keys used (all namespaced under `key_prefix`, default "waf:"):
      {prefix}offense:{ip}  -- a Redis LIST of offense timestamps (trimmed
                               to the sliding window on every read), TTL'd
                               so it self-cleans even if never read again.
      {prefix}banned:{ip}   -- a simple key that exists iff the IP is
                               currently banned; its own TTL IS the ban
                               duration, so expiry is handled by Redis
                               itself rather than by us tracking wall-clock
                               timestamps.
    """

    def __init__(self, redis_client, config: RateLimiterConfig | None = None, key_prefix: str = "waf:"):
        self.redis = redis_client
        self.config = config or RateLimiterConfig()
        self.prefix = key_prefix

    def _offense_key(self, ip: str) -> str:
        return f"{self.prefix}offense:{ip}"

    def _banned_key(self, ip: str) -> str:
        return f"{self.prefix}banned:{ip}"

    def is_blocked(self, ip: str) -> bool:
        return bool(self.redis.exists(self._banned_key(ip)))

    def record_offense(self, ip: str, weight: int = 1) -> bool:
        now = time.time()
        window_start = now - self.config.offense_window_seconds
        key = self._offense_key(ip)

        pipe = self.redis.pipeline()
        for _ in range(max(1, weight)):
            pipe.rpush(key, now)
        pipe.expire(key, self.config.offense_window_seconds)
        pipe.execute()

        raw_timestamps = self.redis.lrange(key, 0, -1)
        timestamps = [float(t) for t in raw_timestamps if float(t) >= window_start]

        if len(timestamps) >= self.config.offense_threshold:
            self.redis.set(self._banned_key(ip), "1", ex=self.config.ban_duration_seconds)
            self.redis.delete(key)
            return True
        return False

    def seconds_remaining_banned(self, ip: str) -> float:
        ttl = self.redis.ttl(self._banned_key(ip))
        return float(ttl) if ttl and ttl > 0 else 0.0

    def stats(self) -> dict:
        banned_keys = list(self.redis.scan_iter(match=f"{self.prefix}banned:*"))
        active_bans = {}
        for key in banned_keys:
            ip = key.decode().split(":")[-1] if isinstance(key, bytes) else key.split(":")[-1]
            ttl = self.redis.ttl(key)
            active_bans[ip] = ttl
        offense_keys = list(self.redis.scan_iter(match=f"{self.prefix}offense:*"))
        return {
            "backend": "redis",
            "tracked_ips": len(offense_keys),
            "active_bans": active_bans,
        }


def build_rate_limiter(config: dict):
    """
    Factory used by waf_proxy.py. config is the `rate_limit` section of
    waf_config.yaml. If `backend: redis` is set, connects to Redis using
    `redis_url`; falls back to the in-memory limiter (with a warning) if
    the redis package isn't installed or the server isn't reachable, so a
    misconfigured Redis never takes the whole WAF down.
    """
    limiter_config = RateLimiterConfig(
        offense_window_seconds=config.get("offense_window_seconds", 60),
        offense_threshold=config.get("offense_threshold", 5),
        ban_duration_seconds=config.get("ban_duration_seconds", 300),
    )

    backend = config.get("backend", "memory")
    if backend == "redis":
        redis_url = config.get("redis_url", "redis://127.0.0.1:6379/0")
        _warn_if_redis_url_looks_insecure(redis_url)
        try:
            import redis as redis_lib
            client = redis_lib.from_url(redis_url)
            client.ping()
            print(f"[rate_limiter] connected to Redis at {redis_url}")
            return RedisRateLimiter(client, limiter_config, key_prefix=config.get("key_prefix", "waf:"))
        except Exception as e:
            print(f"[rate_limiter] WARNING: could not connect to Redis ({e}); "
                  f"falling back to in-memory rate limiting. This is fine for a "
                  f"single-process deployment, but won't share state across workers.")
            return RateLimiter(limiter_config)

    return RateLimiter(limiter_config)


def _warn_if_redis_url_looks_insecure(redis_url: str) -> None:
    """
    Loudly warns (does not block startup -- the operator may have network-
    level isolation instead of Redis auth, e.g. a firewalled private VLAN)
    when Redis is reachable at a non-loopback address without any
    credentials in the URL. `redis://127.0.0.1:6379/0` with no password is
    the expected, safe default for the single-host deployment this project
    documents; anything else deserves a human's attention before going live.
    """
    has_credentials = "@" in redis_url.split("://", 1)[-1]
    is_loopback = any(host in redis_url for host in ("127.0.0.1", "localhost", "::1"))

    if not has_credentials and not is_loopback:
        print(
            "[rate_limiter] \033[91mSECURITY WARNING\033[0m: rate_limit.redis_url "
            f"({redis_url}) points to a non-loopback address with no credentials "
            "in the URL. If this Redis instance is reachable from anywhere other "
            "than this host, set a password (`requirepass` in redis.conf) and use "
            "redis://:password@host:port/db, or restrict network access to it. "
            "Anyone who can reach an unauthenticated Redis can read/forge ban "
            "state and request counters."
        )


if __name__ == "__main__":
    print("=== In-memory limiter ===")
    rl = RateLimiter(RateLimiterConfig(offense_window_seconds=10, offense_threshold=3, ban_duration_seconds=5))
    ip = "203.0.113.7"
    for i in range(1, 5):
        triggered = rl.record_offense(ip)
        print(f"offense #{i}: banned_now={triggered} is_blocked={rl.is_blocked(ip)}")
    print("stats:", rl.stats())

    print("\n=== Redis-backed limiter ===")
    try:
        import redis as redis_lib
        client = redis_lib.from_url("redis://127.0.0.1:6379/0")
        client.ping()
        rrl = RedisRateLimiter(client, RateLimiterConfig(offense_window_seconds=10, offense_threshold=3, ban_duration_seconds=5))
        ip2 = "198.51.100.99"
        client.delete(f"waf:offense:{ip2}", f"waf:banned:{ip2}")  # clean slate for the demo
        for i in range(1, 5):
            triggered = rrl.record_offense(ip2)
            print(f"offense #{i}: banned_now={triggered} is_blocked={rrl.is_blocked(ip2)}")
        print("stats:", rrl.stats())
    except Exception as e:
        print(f"(skipped -- no Redis server reachable: {e})")

