"""
rate_limiter.py
----------------
Real WAFs don't just block one bad request and move on -- an IP that keeps
sending malicious payloads gets temporarily banned outright (this is what
Cloudflare's "I'm Under Attack Mode", fail2ban, and ModSecurity's
mod_qos/rate-limiting all do in different ways).

Behavioral model
~~~~~~~~~~~~~~~~
Every request the WAF decides on is recorded against its source IP as
either ALLOWED or REFUSED (`record_request`). Over a sliding window
(`offense_window_seconds`, approximated by `window_buckets` fixed
sub-buckets) the limiter tracks

    refused = weighted count of refused requests
    total   = allowed + refused
    ratio   = refused / total

and bans the IP when EITHER

  (a) refused >= offense_threshold  AND  ratio >= refusal_ratio_threshold
      -- the behavioral rule. A scanner or fuzzer is refused on most of
      what it sends; a legitimate client who trips an occasional detector
      false positive is refused on a tiny fraction of its traffic and is
      never banned for it, however busy it is.
  (b) refused >= hard_offense_threshold (if > 0)
      -- the anti-dilution floor. Without it an attacker could pad every
      payload with enough benign requests to keep the ratio low forever.
      It caps sustained payload throughput per IP regardless of padding.

Repeat offenders get escalating bans: the n-th ban issued within
`offender_memory_seconds` of the previous ban ENDING lasts

    min(ban_duration_seconds * ban_escalation_factor ** (n - 1),
        max_ban_duration_seconds)

e.g. 5 min -> 20 min -> 80 min -> ... capped at 24 h with the defaults.
The window is reset when a ban is issued, so after a ban expires the IP
starts with a clean ratio but keeps its strike count.

When only `record_offense` is called (every request counted as refused),
ratio is always 1.0 and rule (a) reduces to the original fixed
"offense_threshold offenses in the window" rule.

Validated on the CSIC 2010 HTTP dataset: all 72,000 normal requests trigger
zero bans (scripts/09_csic_rate_limit_validation.py).

Two implementations, same interface (`record_request`, `record_offense`,
`is_blocked`, `seconds_remaining_banned`, `strikes`, `stats`):

  - RateLimiter       : in-memory. Zero dependencies, perfect for local
                        dev/testing or a genuinely single-process deployment.
  - RedisRateLimiter   : same logic, executed atomically inside Redis by a
                        Lua script. State is shared across every WAF worker
                        process/replica, and survives a WAF restart -- this
                        is the one to use for anything internet-facing
                        running more than one process (see README §4
                        "Running multiple workers").

Both take an optional `clock` (defaults to time.time) so tests and the
CSIC replay can drive the sliding window with virtual time.

`build_rate_limiter(config)` picks the right one from config so the rest
of the codebase (waf_proxy.py) doesn't need to know which backend is active.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from typing import Callable


_MAX_ESCALATION_STEPS = 64


@dataclass
class RateLimiterConfig:
    offense_window_seconds: int = 60        # sliding window to measure behavior over
    offense_threshold: int = 5               # min refused (weighted) in the window before a ratio ban
    refusal_ratio_threshold: float = 0.2     # ban when refused/total within the window reaches this
    hard_offense_threshold: int = 60         # ban on this many refused in the window regardless of ratio (0 = off)
    ban_duration_seconds: int = 300          # length of an IP's first ban
    ban_escalation_factor: float = 4.0       # each repeat ban multiplies the previous duration by this
    max_ban_duration_seconds: int = 86400    # escalation cap
    offender_memory_seconds: int = 86400     # strikes are forgotten this long after the last ban ends
    window_buckets: int = 12                 # sub-buckets approximating the sliding window

    def __post_init__(self):
        if self.offense_window_seconds <= 0 or self.window_buckets < 1:
            raise ValueError("offense_window_seconds must be > 0 and window_buckets >= 1")
        if not 0.0 < self.refusal_ratio_threshold <= 1.0:
            raise ValueError("refusal_ratio_threshold must be in (0, 1]")
        if self.offense_threshold < 1 or self.hard_offense_threshold < 0:
            raise ValueError("offense_threshold must be >= 1 and hard_offense_threshold >= 0")
        if self.ban_escalation_factor < 1.0:
            raise ValueError("ban_escalation_factor must be >= 1")
        if not 1 <= self.ban_duration_seconds <= self.max_ban_duration_seconds:
            raise ValueError("need 1 <= ban_duration_seconds <= max_ban_duration_seconds")

    @property
    def bucket_seconds(self) -> float:
        return self.offense_window_seconds / self.window_buckets

    def ban_duration_for(self, strike: int) -> int:
        # Exponent capped so a long-lived offender can't overflow the float.
        exponent = min(max(0, strike - 1), _MAX_ESCALATION_STEPS)
        duration = self.ban_duration_seconds * self.ban_escalation_factor ** exponent
        return int(min(duration, self.max_ban_duration_seconds))

    def should_ban(self, refused: int, total: int) -> bool:
        if self.hard_offense_threshold > 0 and refused >= self.hard_offense_threshold:
            return True
        return (refused >= self.offense_threshold
                and total > 0
                and refused / total >= self.refusal_ratio_threshold)


class RateLimiter:
    """In-memory implementation. See module docstring for when to use this
    vs RedisRateLimiter."""

    def __init__(self, config: RateLimiterConfig | None = None, clock: Callable[[], float] = time.time):
        self.config = config or RateLimiterConfig()
        self.clock = clock
        # ip -> {bucket_index: [total, refused]}
        self._windows: dict[str, dict[int, list[int]]] = {}
        self._banned_until: dict[str, float] = {}
        # ip -> (strike count, forget_at)
        self._strikes: dict[str, tuple[int, float]] = {}
        self._last_sweep = self.clock()

    def _bucket(self, now: float) -> int:
        return math.floor(now / self.config.bucket_seconds)

    def is_blocked(self, ip: str) -> bool:
        banned_until = self._banned_until.get(ip)
        if banned_until is None:
            return False
        if self.clock() >= banned_until:
            del self._banned_until[ip]  # ban expired, clean up
            return False
        return True

    def record_request(self, ip: str, refused: bool, weight: int = 1) -> bool:
        """
        Call this once per request from `ip` the WAF allowed or refused.
        Returns True if this request just triggered a new ban.

        `weight` applies to refused requests: higher-confidence signals
        count for more than a single refusal -- e.g. a known-scanner
        User-Agent or a probe of /.git/config is much stronger evidence of
        hostile intent than one ambiguous ML classification, so
        recon_detection.py's callers pass weight=2 to reach the ban
        threshold faster than ordinary payload matches do.
        """
        now = self.clock()
        cfg = self.config
        weight = max(1, weight) if refused else 1
        current = self._bucket(now)

        window = self._windows.setdefault(ip, {})
        if current not in window:
            oldest = current - cfg.window_buckets + 1
            for b in [b for b in window if b < oldest]:
                del window[b]
            window[current] = [0, 0]
        counts = window[current]
        counts[0] += weight
        if refused:
            counts[1] += weight

        self._maybe_sweep(now)
        if not refused:
            return False

        total = sum(c[0] for c in window.values())
        refused_count = sum(c[1] for c in window.values())

        if not cfg.should_ban(refused_count, total):
            return False

        strike, forget_at = self._strikes.get(ip, (0, 0.0))
        strike = strike + 1 if now < forget_at else 1
        ban_until = now + cfg.ban_duration_for(strike)
        # Memory runs from the END of the ban: counted from its start, a ban
        # as long as the memory would erase the strike count it just earned.
        self._strikes[ip] = (strike, ban_until + cfg.offender_memory_seconds)
        self._banned_until[ip] = ban_until
        del self._windows[ip]
        return True

    def record_offense(self, ip: str, weight: int = 1) -> bool:
        """Records a refused request. Kept for callers that only report
        malicious requests; see record_request."""
        return self.record_request(ip, refused=True, weight=weight)

    def strikes(self, ip: str) -> int:
        strike, forget_at = self._strikes.get(ip, (0, 0.0))
        return strike if self.clock() < forget_at else 0

    def seconds_remaining_banned(self, ip: str) -> float:
        banned_until = self._banned_until.get(ip)
        if banned_until is None:
            return 0.0
        return max(0.0, banned_until - self.clock())

    def _maybe_sweep(self, now: float) -> None:
        """Drops idle IPs, expired bans and forgotten strikes once per
        window, so a long-running process doesn't grow without bound."""
        if now - self._last_sweep < self.config.offense_window_seconds:
            return
        self._last_sweep = now
        oldest = self._bucket(now) - self.config.window_buckets + 1
        for ip in [ip for ip, w in self._windows.items() if max(w, default=oldest - 1) < oldest]:
            del self._windows[ip]
        for ip in [ip for ip, t in self._banned_until.items() if t <= now]:
            del self._banned_until[ip]
        for ip in [ip for ip, (_, t) in self._strikes.items() if t <= now]:
            del self._strikes[ip]

    def stats(self) -> dict:
        now = self.clock()
        active_bans = {ip: round(t - now, 1) for ip, t in self._banned_until.items() if t > now}
        return {
            "backend": "memory",
            "tracked_ips": len(self._windows),
            "active_bans": active_bans,
            "repeat_offenders": {ip: s for ip, (s, t) in self._strikes.items() if t > now and s > 1},
        }


# Atomic record-and-decide for RedisRateLimiter. Runs entirely inside
# Redis, so concurrent workers can neither both miss a ban nor both issue
# one (which would double-count the strike and over-escalate).
#
# KEYS[1] = banned key, KEYS[2] = strikes key,
# KEYS[3..] = window bucket keys, current bucket first.
# ARGV = now, total_weight, refused_weight, bucket_ttl, offense_threshold,
#        ratio_threshold, hard_threshold, base_ban, escalation_factor,
#        max_ban, offender_memory, max_escalation_steps
# Returns {banned (0/1), ban_seconds, strike}.
_RECORD_LUA = """
local now = tonumber(ARGV[1])
local total_w = tonumber(ARGV[2])
local refused_w = tonumber(ARGV[3])

redis.call('HINCRBY', KEYS[3], 't', total_w)
if refused_w > 0 then
  redis.call('HINCRBY', KEYS[3], 'r', refused_w)
end
redis.call('EXPIRE', KEYS[3], tonumber(ARGV[4]))
if refused_w == 0 then
  return {0, 0, 0}
end

local total, refused = 0, 0
for i = 3, #KEYS do
  local v = redis.call('HMGET', KEYS[i], 't', 'r')
  total = total + (tonumber(v[1]) or 0)
  refused = refused + (tonumber(v[2]) or 0)
end

local hard = tonumber(ARGV[7])
local ban = (hard > 0 and refused >= hard)
  or (refused >= tonumber(ARGV[5]) and total > 0 and refused / total >= tonumber(ARGV[6]))
if not ban then
  return {0, 0, 0}
end

local prev = redis.call('HMGET', KEYS[2], 'n', 'forget_at')
local strike = 1
if prev[1] and now < tonumber(prev[2]) then
  strike = tonumber(prev[1]) + 1
end
local exponent = math.min(strike - 1, tonumber(ARGV[12]))
local duration = math.floor(math.min(tonumber(ARGV[8]) * tonumber(ARGV[9]) ^ exponent, tonumber(ARGV[10])))
redis.call('SET', KEYS[1], tostring(now + duration), 'EX', math.max(1, duration))
local memory = tonumber(ARGV[11])
redis.call('HSET', KEYS[2], 'n', strike, 'forget_at', tostring(now + duration + memory))
redis.call('EXPIRE', KEYS[2], duration + memory)
for i = 3, #KEYS do
  redis.call('DEL', KEYS[i])
end
return {1, duration, strike}
"""


class RedisRateLimiter:
    """
    Redis-backed implementation with the exact same interface and decision
    rule as RateLimiter. Use this whenever the WAF runs as more than one
    process (multiple gunicorn workers, multiple machines behind a load
    balancer) -- with the in-memory version, each process/replica would
    track behavior independently, so an attacker could spray requests
    across workers and never trip any single one's threshold.

    Redis keys used (all namespaced under `key_prefix`, default "waf:"):
      {prefix}win:{ip}:{bucket} -- HASH {t: total, r: refused} for one
                                   window sub-bucket; TTL'd to the window,
                                   so idle IPs self-clean.
      {prefix}banned:{ip}       -- exists iff the IP is currently banned;
                                   value is the ban-until timestamp, TTL
                                   is the ban duration.
      {prefix}strikes:{ip}      -- HASH {n, forget_at}: number of bans
                                   issued to this IP, each within
                                   offender_memory_seconds of the previous
                                   one ending; drives escalation.

    One EVALSHA round trip per request, allowed or refused.
    """

    def __init__(self, redis_client, config: RateLimiterConfig | None = None, key_prefix: str = "waf:",
                 clock: Callable[[], float] = time.time):
        self.redis = redis_client
        self.config = config or RateLimiterConfig()
        self.prefix = key_prefix
        self.clock = clock
        self._record = self.redis.register_script(_RECORD_LUA)

    def _banned_key(self, ip: str) -> str:
        return f"{self.prefix}banned:{ip}"

    def _strikes_key(self, ip: str) -> str:
        return f"{self.prefix}strikes:{ip}"

    def _window_keys(self, ip: str, now: float) -> list[str]:
        current = math.floor(now / self.config.bucket_seconds)
        return [f"{self.prefix}win:{ip}:{current - i}" for i in range(self.config.window_buckets)]

    def _ban_until(self, ip: str) -> float | None:
        raw = self.redis.get(self._banned_key(ip))
        if raw is None:
            return None
        if raw in (b"1", "1"):
            # Ban written by an older WAF version; its TTL is authoritative.
            return self.clock() + max(0, self.redis.ttl(self._banned_key(ip)))
        return float(raw)

    def is_blocked(self, ip: str) -> bool:
        until = self._ban_until(ip)
        return until is not None and self.clock() < until

    def record_request(self, ip: str, refused: bool, weight: int = 1) -> bool:
        now = self.clock()
        cfg = self.config
        weight = max(1, weight) if refused else 1
        keys = [self._banned_key(ip), self._strikes_key(ip), *self._window_keys(ip, now)]
        banned, _duration, _strike = self._record(keys=keys, args=[
            repr(now), weight, weight if refused else 0,
            math.ceil(cfg.offense_window_seconds + cfg.bucket_seconds),
            cfg.offense_threshold, repr(float(cfg.refusal_ratio_threshold)), cfg.hard_offense_threshold,
            cfg.ban_duration_seconds, repr(float(cfg.ban_escalation_factor)),
            cfg.max_ban_duration_seconds, cfg.offender_memory_seconds, _MAX_ESCALATION_STEPS,
        ])
        return bool(banned)

    def record_offense(self, ip: str, weight: int = 1) -> bool:
        return self.record_request(ip, refused=True, weight=weight)

    def _strikes_from_key(self, key) -> int:
        n, forget_at = self.redis.hmget(key, "n", "forget_at")
        return int(n) if n is not None and self.clock() < float(forget_at) else 0

    def strikes(self, ip: str) -> int:
        return self._strikes_from_key(self._strikes_key(ip))

    def seconds_remaining_banned(self, ip: str) -> float:
        until = self._ban_until(ip)
        return max(0.0, until - self.clock()) if until is not None else 0.0

    def _ip_from_key(self, key, kind: str) -> str:
        key = key.decode() if isinstance(key, bytes) else key
        return key[len(f"{self.prefix}{kind}:"):]

    def stats(self) -> dict:
        active_bans = {}
        for key in self.redis.scan_iter(match=f"{self.prefix}banned:*"):
            ip = self._ip_from_key(key, "banned")
            remaining = self.seconds_remaining_banned(ip)
            if remaining > 0:
                active_bans[ip] = round(remaining, 1)
        repeat_offenders = {}
        for key in self.redis.scan_iter(match=f"{self.prefix}strikes:*"):
            strike = self._strikes_from_key(key)
            if strike > 1:
                repeat_offenders[self._ip_from_key(key, "strikes")] = strike
        tracked = {self._ip_from_key(k, "win").rsplit(":", 1)[0]
                   for k in self.redis.scan_iter(match=f"{self.prefix}win:*")}
        return {
            "backend": "redis",
            "tracked_ips": len(tracked),
            "active_bans": active_bans,
            "repeat_offenders": repeat_offenders,
        }


def limiter_config_from_dict(config: dict) -> RateLimiterConfig:
    """Builds a RateLimiterConfig from the `rate_limit` section of
    waf_config.yaml; missing keys keep the dataclass defaults."""
    defaults = RateLimiterConfig()
    return RateLimiterConfig(**{
        name: type(getattr(defaults, name))(config.get(name, getattr(defaults, name)))
        for name in RateLimiterConfig.__dataclass_fields__
    })


def build_rate_limiter(config: dict):
    """
    Factory used by waf_proxy.py. config is the `rate_limit` section of
    waf_config.yaml. If `backend: redis` is set, connects to Redis using
    `redis_url`; falls back to the in-memory limiter (with a warning) if
    the redis package isn't installed or the server isn't reachable, so a
    misconfigured Redis never takes the whole WAF down.
    """
    limiter_config = limiter_config_from_dict(config)

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
    def demo(rl, ip):
        for i in range(1, 5):
            triggered = rl.record_offense(ip)
            print(f"offense #{i}: banned_now={triggered} is_blocked={rl.is_blocked(ip)}")
        print("stats:", rl.stats())

    demo_config = RateLimiterConfig(offense_window_seconds=10, offense_threshold=3, ban_duration_seconds=5)

    print("=== In-memory limiter ===")
    demo(RateLimiter(demo_config), "203.0.113.7")

    print("\n=== Redis-backed limiter ===")
    try:
        import redis as redis_lib
        client = redis_lib.from_url("redis://127.0.0.1:6379/0")
        client.ping()
        for key in client.scan_iter(match="waf-demo:*"):
            client.delete(key)  # clean slate for the demo
        demo(RedisRateLimiter(client, demo_config, key_prefix="waf-demo:"), "198.51.100.99")
    except Exception as e:
        print(f"(skipped -- no Redis server reachable: {e})")
