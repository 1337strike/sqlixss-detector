"""
09_csic_rate_limit_validation.py
--------------------------------
Validates the WAF's behavioral rate limiter (src/rate_limiter.py) on the
CSIC 2010 HTTP dataset: legitimate traffic must never get an IP banned.

  1. LIVE passes. All 72,000 CSIC normal requests (training + test files)
     are sent over HTTP through a running WafProxy (block mode, Redis-backed
     limiter if --redis-url is reachable, else in-memory) in front of a stub
     backend. Consecutive runs of --client-size requests are presented as one
     client IP each via X-Forwarded-For from a trusted loopback proxy. Run
     with two detector configurations:
       - shipped : config/waf_config.yaml as is;
       - stress  : paper models + naive_bayes (logistic_regression,
                   naive_bayes, signature_baseline; model_set: paper), the
                   noisiest configuration on CSIC -- it exercises the ban
                   layer against a detector that does misfire.
     Asserts: zero bans, zero ban-rejected requests.
  2. OFFLINE scenarios. Each pass's per-request limiter input (what the WAF
     recorded, captured by src/waf_replay.RecordingLimiter) is replayed into
     fresh limiters (both backends) under virtual time:
       - every request from ONE IP at 1, 10 and 100 req/s
         (a whole office behind one NAT address);
       - clients of 10 / 50 / 500 / 5,000 consecutive requests, each
         client's requests all inside a single window (worst case for the
         ratio rule).
     Asserts: zero bans in every scenario.
  3. --with-anomalous: the 25,065 CSIC anomalous requests, live, shipped
     config, as clients of --client-size requests -- reports how many
     attacker IPs get banned. Informational; CSIC "anomalous" includes
     non-injection tampering the detectors do not target.

The detectors are not modified; this measures the ban layer on top of
whatever the detection pipeline refuses.

Run:
    python scripts/00b_download_csic2010.py
    python scripts/09_csic_rate_limit_validation.py [--redis-url URL] [--with-anomalous]

Writes results/waf_csic2010_rate_limit.json. Exit status 1 if any
legitimate CSIC client was banned.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.csic2010 import load_csic
from src.rate_limiter import RateLimiter, RedisRateLimiter, limiter_config_from_dict
from src.waf_proxy import load_config
from src.waf_replay import (
    VirtualClock, chunked_client_ips, live_waf, max_refusals_in_run, replay, replay_decisions,
)

ROOT = Path(__file__).resolve().parent.parent
OUT_PATH = ROOT / "results" / "waf_csic2010_rate_limit.json"

DETECTOR_CONFIGS = {
    "shipped": {},
    "stress": {"models": ["logistic_regression", "naive_bayes", "signature_baseline"], "model_set": "paper"},
}
SINGLE_IP_RATES = (1, 10, 100)          # req/s from one IP
BURST_CLIENT_SIZES = (10, 50, 500, 5000)


def _redis_client(url: str | None):
    if not url:
        return None
    try:
        import redis as redis_lib
        client = redis_lib.from_url(url)
        client.ping()
        return client
    except Exception as e:
        print(f"[csic] Redis at {url} unreachable ({e}); using the in-memory backend")
        return None


def _purge(client, prefix: str) -> None:
    for key in client.scan_iter(match=f"{prefix}*"):
        client.delete(key)


async def live_pass(requests, client_size: int, rate_limit: dict, redis_client, redis_url: str,
                    ip_base: str, detectors: dict) -> tuple[dict, list]:
    prefix = f"waf-csic:{uuid.uuid4().hex}:"
    section = {**rate_limit, "key_prefix": prefix, "redis_url": redis_url,
               "backend": "redis" if redis_client is not None else "memory"}
    ips = chunked_client_ips(len(requests), client_size, base=ip_base)
    t0 = time.time()
    try:
        async with live_waf(section, str(ROOT / "logs" / "csic_replay.log"), **detectors) as (url, waf):
            results = await replay(url, waf, requests, ips)
            stats = waf.stats.get_all()
            backend = waf.rate_limiter.stats()["backend"]
            models = list(waf.detectors)
    finally:
        if redis_client is not None:
            _purge(redis_client, prefix)
    summary = {
        "backend": backend,
        "detectors": models,
        "model_set": detectors.get("model_set", load_config().get("model_set", "deploy")),
        "requests": len(requests),
        "clients": len(set(ips)),
        "client_size": client_size,
        "seconds": round(time.time() - t0, 1),
        "forwarded": sum(r.status == 200 for r in results),
        "refused": sum(r.refused for r in results),
        "ban_rejected_requests": sum(r.ban_rejected for r in results),
        "client_errors": sum(r.status == 0 for r in results),
        "bans_triggered": stats["banned_ips_triggered"],
        "banned_clients": len({r.client_ip for r in results if r.ban_issued}),
    }
    return summary, results


def offline_scenarios(decisions, rate_limit: dict, redis_client) -> list[dict]:
    config = limiter_config_from_dict(rate_limit)
    backends = ["memory"] + (["redis"] if redis_client is not None else [])
    scenarios = [(f"single_ip_{r}rps", ["192.0.2.1"] * len(decisions), 1.0 / r) for r in SINGLE_IP_RATES]
    scenarios += [(f"burst_clients_of_{k}", chunked_client_ips(len(decisions), k), 0.001)
                  for k in BURST_CLIENT_SIZES]
    out = []
    for backend in backends:
        for name, ips, interval in scenarios:
            clock = VirtualClock()
            prefix = f"waf-csic:{uuid.uuid4().hex}:"
            limiter = (RateLimiter(config, clock=clock) if backend == "memory"
                       else RedisRateLimiter(redis_client, config, key_prefix=prefix, clock=clock))
            try:
                res = replay_decisions(limiter, clock, decisions, ips, interval)
            finally:
                if backend == "redis":
                    _purge(redis_client, prefix)
            out.append({"backend": backend, "scenario": name, "clients": len(set(ips)), **res})
            print(f"  {backend:6s} {name:24s} clients={len(set(ips)):6d} bans={res['bans']}")
    return out


def refusal_profile(decisions, config) -> dict:
    weighted = [d[1] if d is not None and d[0] else 0 for d in decisions]
    runs = {str(k): max_refusals_in_run(weighted, k) for k in (10, 30, 100, 1000, 6000)}
    # Longest run of consecutive requests one IP could send inside a single
    # window without reaching the anti-dilution cap: sets the sustained
    # single-IP rate above which CSIC-like traffic would start to be banned.
    max_rate = None
    if config.hard_offense_threshold > 0 and sum(weighted) >= config.hard_offense_threshold:
        lo, hi = 1, len(weighted)
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if max_refusals_in_run(weighted, mid) < config.hard_offense_threshold:
                lo = mid
            else:
                hi = mid - 1
        max_rate = round(lo / config.offense_window_seconds, 1)
    return {"max_weighted_refusals_in_consecutive_requests": runs,
            "max_single_ip_rate_below_hard_cap_rps": max_rate}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--redis-url", default="redis://127.0.0.1:6379/0",
                        help="Redis for the Redis-backed limiter ('' = in-memory only)")
    parser.add_argument("--client-size", type=int, default=100,
                        help="consecutive requests per synthetic client IP in the live passes")
    parser.add_argument("--with-anomalous", action="store_true",
                        help="also replay the CSIC anomalous traffic and report attacker bans")
    parser.add_argument("--out", type=Path, default=OUT_PATH)
    args = parser.parse_args()

    rate_limit = load_config()["rate_limit"]
    config = limiter_config_from_dict(rate_limit)
    redis_client = _redis_client(args.redis_url)
    normal = load_csic("normal")

    report = {
        "dataset": "CSIC 2010 HTTP dataset (normalTrafficTraining + normalTrafficTest)",
        "rate_limit_config": {k: getattr(config, k) for k in config.__dataclass_fields__},
    }
    false_bans = 0
    for name, detectors in DETECTOR_CONFIGS.items():
        print(f"[csic] live pass ({name} detectors): {len(normal):,} normal requests through the WAF ...")
        live, results = asyncio.run(live_pass(normal, args.client_size, rate_limit, redis_client,
                                              args.redis_url, "10", detectors))
        print(f"[csic]   {live['detectors']} ({live['model_set']}), backend={live['backend']}: "
              f"refused={live['refused']} ({live['refused'] / len(normal):.2%}) "
              f"bans={live['bans_triggered']} ban-rejected={live['ban_rejected_requests']} "
              f"in {live['seconds']}s")
        decisions = [r.decision for r in results]
        print("[csic]   offline scenarios on this pass's recorded limiter input:")
        offline = offline_scenarios(decisions, rate_limit, redis_client)
        report[f"normal_{name}"] = {"live": live, **refusal_profile(decisions, config), "offline": offline}
        false_bans += live["bans_triggered"] + live["ban_rejected_requests"] + sum(s["bans"] for s in offline)

    if args.with_anomalous:
        anomalous = load_csic("anomalous")
        print(f"[csic] live pass (shipped detectors): {len(anomalous):,} anomalous requests ...")
        anom, _ = asyncio.run(live_pass(anomalous, args.client_size, rate_limit, redis_client,
                                        args.redis_url, "11", DETECTOR_CONFIGS["shipped"]))
        print(f"[csic]   refused={anom['refused']} banned_clients={anom['banned_clients']}/{anom['clients']} "
              f"ban-rejected={anom['ban_rejected_requests']}")
        report["anomalous_shipped"] = {"live": anom}

    report["normal_traffic_false_bans"] = false_bans
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(f"[csic] wrote {args.out}")

    if false_bans:
        print(f"[csic] FAIL: legitimate CSIC traffic triggered {false_bans} ban(s)/ban-rejections")
        return 1
    print("[csic] PASS: 0 bans on CSIC 2010 normal traffic")
    return 0


if __name__ == "__main__":
    sys.exit(main())
