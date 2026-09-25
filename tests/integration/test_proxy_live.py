"""
tests/integration/test_proxy_live.py
-------------------------------------
Live proxy tests: the WAF and a backend run as REAL processes on free local
ports and are driven with real HTTP, the way they are deployed:

  * single process  -- scripts/05_run_waf.py (block and monitor mode)
  * multi-worker    -- gunicorn + aiohttp.GunicornWebWorker with a
                       Redis-backed rate limiter (the deploy/waf.service
                       topology): ban state must be shared across workers.

The Redis test needs a Redis server on REDIS_URL (default
redis://127.0.0.1:6379/0). It is skipped when none is reachable, unless
REQUIRE_REDIS=1 (set in CI), in which case a missing Redis is a failure.

Run:
    python -m pytest tests/integration/test_proxy_live.py -v
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import textwrap
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent.parent
REDIS_URL = os.environ.get("REDIS_URL", "redis://127.0.0.1:6379/0")

BACKEND_SRC = textwrap.dedent('''
    import sys
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Echo(BaseHTTPRequestHandler):
        def _reply(self):
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n) if n else b""
            out = b"backend-ok " + self.path.encode() + b" " + body
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)
        do_GET = do_POST = _reply
        def log_message(self, *args):
            pass

    ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Echo).serve_forever()
''')

SQLI = "/search?q=%27%20OR%201%3D1--"
XSS = "/search?q=%3Csvg/onload=alert(1)%3E"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_http(url: str, timeout: float = 30.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=1)
            return
        except urllib.error.HTTPError:
            return
        except OSError:
            time.sleep(0.2)
    raise TimeoutError(f"{url} did not come up within {timeout}s")


def _request(url: str, data: bytes | None = None, headers: dict | None = None) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=data, headers={"User-Agent": "Mozilla/5.0", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


class _Stack:
    """Backend + WAF as child processes; stopped on exit."""

    def __init__(self, tmp: Path, mode: str = "block", workers: int = 0, redis: bool = False,
                 threshold: int = 10**6):
        self.tmp, self.procs = tmp, []
        backend_port, self.port = _free_port(), _free_port()
        (tmp / "backend.py").write_text(BACKEND_SRC)
        self._spawn([sys.executable, str(tmp / "backend.py"), str(backend_port)])
        _wait_http(f"http://127.0.0.1:{backend_port}/")

        config = yaml.safe_load((ROOT / "config" / "waf_config.yaml").read_text())
        config.update(mode=mode, listen_host="127.0.0.1", listen_port=self.port,
                      backend_url=f"http://127.0.0.1:{backend_port}", log_path=str(tmp / "waf.log"))
        config["rate_limit"].update(backend="redis" if redis else "memory", redis_url=REDIS_URL,
                                    offense_threshold=threshold)
        cfg = tmp / "waf.yaml"
        cfg.write_text(yaml.safe_dump(config))

        if workers:
            self._spawn([sys.executable, "-m", "gunicorn", "src.waf_proxy:make_gunicorn_app",
                         "--worker-class", "aiohttp.GunicornWebWorker", "--workers", str(workers),
                         "--bind", f"127.0.0.1:{self.port}"], env={"WAF_CONFIG": str(cfg)})
        else:
            self._spawn([sys.executable, "scripts/05_run_waf.py", "--config", str(cfg)])
        _wait_http(self.url("/__waf/health"), timeout=60)

    def _spawn(self, cmd: list[str], env: dict | None = None) -> None:
        log = open(self.tmp / f"proc{len(self.procs)}.log", "w")
        self.procs.append(subprocess.Popen(cmd, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                                           env={**os.environ, **(env or {})}))

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def log_events(self) -> list[dict]:
        path = self.tmp / "waf.log"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        for p in reversed(self.procs):
            p.terminate()
        for p in self.procs:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()


def test_single_process_block_mode(tmp_path):
    with _Stack(tmp_path) as s:
        status, body = _request(s.url("/search?q=laptop+camera"))
        assert status == 200 and body.startswith(b"backend-ok /search")
        assert _request(s.url("/"))[0] == 200
        assert _request(s.url("/login"), b"username=alice&password=hunter2",
                        {"Content-Type": "application/x-www-form-urlencoded"})[0] == 200
        assert _request(s.url("/api/profile"), json.dumps({"name": "O'Neil", "sort": "order"}).encode(),
                        {"Content-Type": "application/json"})[0] == 200

        refusals = [_request(s.url(SQLI)), _request(s.url(XSS)),
                    _request(s.url("/search?q=1"), headers={"User-Agent": "sqlmap/1.8"})]
        for status, body in refusals:
            assert status == 403
            assert sorted(json.loads(body)) == ["error", "request_id"]

        decisions = [e["decision"] for e in s.log_events()]
        assert decisions.count("allowed") >= 4
        assert decisions.count("blocked") == 2 and "blocked_recon" in decisions


def test_single_process_monitor_mode(tmp_path):
    with _Stack(tmp_path, mode="monitor") as s:
        for path in (SQLI, XSS):
            status, body = _request(s.url(path))
            assert status == 200 and body.startswith(b"backend-ok")
        assert [e["decision"] for e in s.log_events()].count("would_block") == 2


def test_gunicorn_workers_share_bans_via_redis(tmp_path):
    try:
        import redis
        client = redis.Redis.from_url(REDIS_URL, socket_connect_timeout=1)
        client.ping()
    except Exception as e:
        if os.environ.get("REQUIRE_REDIS") == "1":
            pytest.fail(f"Redis required but unreachable at {REDIS_URL}: {e}")
        pytest.skip(f"no Redis at {REDIS_URL}")
    client.flushdb()

    with _Stack(tmp_path, workers=3, redis=True, threshold=3) as s:
        assert _request(s.url("/search?q=laptop"))[0] == 200
        for _ in range(4):                       # spread over workers by the kernel
            assert _request(s.url(SQLI))[0] == 403
        status, body = _request(s.url("/search?q=laptop"))   # benign, now banned
        assert status == 403 and sorted(json.loads(body)) == ["error", "request_id"]

        stats = json.loads(_request(s.url("/__waf/stats"))[1])
        assert stats["rate_limiter"]["backend"] == "redis"
        assert stats["banned_ips_triggered"] >= 1
        assert "blocked_ratelimit" in {e["decision"] for e in s.log_events()}
    client.flushdb()
