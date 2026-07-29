"""
waf_stats.py
------------
Request counters (allowed / blocked / banned_ips_triggered / static_denied)
for the WAF's /__waf/stats and /__waf/metrics endpoints.

Why this needs its own abstraction: under gunicorn with multiple workers,
each worker is a SEPARATE OS process with its own Python memory space, so
a plain `dict` counter on the WafProxy instance only counts THAT worker's
requests -- hit /__waf/stats and you get one worker's numbers, not the
whole fleet's, which is actively misleading in a load-balanced deployment.

Two implementations, same interface (`increment`, `get_all`):
  - InMemoryStats : per-process dict. Correct and sufficient for a
                    single-process deployment (scripts/05_run_waf.py).
  - RedisStats    : atomic Redis INCR per counter, shared across every
                    worker process/replica. Automatically used whenever
                    the rate limiter backend is also "redis" (if you're
                    running multiple workers, you need Redis for the rate
                    limiter to be correct anyway -- see rate_limiter.py --
                    so this piggybacks on that same connection/decision).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field


class InMemoryStats:
    def __init__(self):
        self._counters: dict[str, int] = {}
        self.started_at = time.time()

    def increment(self, name: str, amount: int = 1) -> None:
        self._counters[name] = self._counters.get(name, 0) + amount

    def get_all(self) -> dict:
        return {
            **{k: self._counters.get(k, 0) for k in ("allowed", "blocked", "banned_ips_triggered", "static_denied")},
            "started_at": self.started_at,
        }


class RedisStats:
    def __init__(self, redis_client, key_prefix: str = "waf:stat:"):
        self.redis = redis_client
        self.prefix = key_prefix
        # First worker to start wins the race to set this; that's fine --
        # it's only used to compute uptime, a few milliseconds of skew
        # between workers racing to set it doesn't matter in practice.
        self.redis.set(f"{self.prefix}started_at", time.time(), nx=True)

    def increment(self, name: str, amount: int = 1) -> None:
        self.redis.incrby(f"{self.prefix}{name}", amount)

    def get_all(self) -> dict:
        keys = ("allowed", "blocked", "banned_ips_triggered", "static_denied")
        pipe = self.redis.pipeline()
        for k in keys:
            pipe.get(f"{self.prefix}{k}")
        pipe.get(f"{self.prefix}started_at")
        values = pipe.execute()

        result = {k: int(v or 0) for k, v in zip(keys, values[:-1])}
        result["started_at"] = float(values[-1] or time.time())
        return result


def build_stats(rate_limiter) -> "InMemoryStats | RedisStats":
    """
    Reuses whichever backend the rate limiter already picked: if it's
    Redis-backed, share its connection for stats too (no separate config
    needed); otherwise fall back to a simple per-process in-memory
    counter, which is exactly correct for a single-process deployment.
    """
    redis_client = getattr(rate_limiter, "redis", None)
    if redis_client is not None:
        return RedisStats(redis_client)
    return InMemoryStats()


if __name__ == "__main__":
    print("=== InMemoryStats ===")
    s = InMemoryStats()
    s.increment("allowed")
    s.increment("allowed")
    s.increment("blocked")
    print(s.get_all())

    print("\n=== RedisStats ===")
    try:
        import redis as redis_lib
        client = redis_lib.from_url("redis://127.0.0.1:6379/0")
        client.ping()
        client.delete("waf:stat:allowed", "waf:stat:blocked", "waf:stat:started_at")
        rs = RedisStats(client)
        rs.increment("allowed")
        rs.increment("allowed")
        rs.increment("blocked")
        # simulate a second worker process incrementing the SAME counters
        rs2 = RedisStats(client)
        rs2.increment("allowed")
        print("worker1 view:", rs.get_all())
        print("worker2 view:", rs2.get_all(), "<- must match worker1, proving shared state")
    except Exception as e:
        print(f"(skipped -- no Redis server reachable: {e})")
