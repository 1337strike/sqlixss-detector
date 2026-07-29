"""
waf_logging.py
--------------
Structured (JSON-lines) logging for the WAF proxy. Every request decision
is written as one JSON object per line -- this is the standard format for
feeding logs into a SIEM / ELK stack / Splunk / whatever your ops team
already uses, instead of inventing a bespoke text format someone has to
write a regex parser for later.

Uses a rotating file handler so a busy, internet-facing WAF doesn't
silently fill up the disk over weeks of uptime -- once a log file hits
`max_bytes` it's rotated (renamed with a numeric suffix) and a fresh file
is started, keeping at most `backup_count` old files around.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import time
from pathlib import Path


class WafLogger:
    def __init__(
        self,
        log_path: str | Path,
        also_print: bool = True,
        max_bytes: int = 10 * 1024 * 1024,   # rotate at 10 MB by default
        backup_count: int = 5,                 # keep 5 old rotated files
    ):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.also_print = also_print

        self._logger = logging.getLogger("waf")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False
        if not self._logger.handlers:
            handler = logging.handlers.RotatingFileHandler(
                self.log_path, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8",
            )
            handler.setFormatter(logging.Formatter("%(message)s"))
            self._logger.addHandler(handler)

    def log_event(
        self,
        decision: str,          # "allowed" | "blocked" | "blocked_ratelimit"
        client_ip: str,
        method: str,
        path: str,
        label: str,
        triggered_by: list[str],
        latency_ms: float,
    ) -> None:
        event = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
            "decision": decision,
            "client_ip": client_ip,
            "method": method,
            "path": path[:300],   # cap length so a giant payload doesn't blow up the log line
            "label": label,
            "triggered_by": triggered_by,
            "latency_ms": round(latency_ms, 3),
        }
        line = json.dumps(event, ensure_ascii=False)
        self._logger.info(line)
        if self.also_print:
            tag = {
                "allowed": "\033[92mALLOW\033[0m",
                "blocked": "\033[91mBLOCK\033[0m",
                "blocked_static_deny": "\033[91mDENY \033[0m",
                "blocked_recon": "\033[95mRECON\033[0m",
                "blocked_ratelimit": "\033[93mBAN  \033[0m",
            }.get(decision, decision)
            print(f"{tag} {client_ip:>15} {method:6} {path[:60]:60} "
                  f"label={label:8} latency={latency_ms:6.2f}ms")


if __name__ == "__main__":
    logger = WafLogger("logs/waf_test.log")
    logger.log_event("allowed", "127.0.0.1", "GET", "/search?q=laptop", "benign", [], 0.42)
    logger.log_event("blocked", "203.0.113.7", "GET", "/search?q=%27%20OR%201%3D1", "sqli",
                      ["logistic_regression", "signature_baseline"], 1.83)
    print(f"\nWrote to {Path('logs/waf_test.log').resolve()}")
