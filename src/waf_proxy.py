"""
waf_proxy.py
------------
A real inline Web Application Firewall: an async reverse proxy that sits
IN FRONT of your actual backend application. Every request is classified
BEFORE it reaches the backend; malicious requests are blocked with a 403
and never forwarded at all.

This is architecturally the same pattern as production WAFs (Cloudflare,
AWS WAF, NGINX+ModSecurity): the WAF terminates the client connection
(including TLS, if configured), inspects the request, and only proxies it
onward if it's clean.

Pipeline per request:
  0. Static allow/deny list check -- config-level IP allowlist/denylist,
                                      checked before anything else.
  1. Rate limiter check       -- is this source IP currently banned? if so,
                                  403/429 immediately, don't even run the
                                  model (drop known-bad IPs as cheaply as
                                  possible -- this is what real WAFs do).
  2. Extract inspectable text -- URL path + query string, and body (form or
                                  JSON) if present.
  3. Ensemble classification   -- run every configured detector, combine
                                  via the configured voting policy.
  4. Decision:
       - malicious -> log, record offense against the IP (may trigger an
                      auto-ban), return 403 with a JSON error body.
       - benign    -> forward the request to the real backend unmodified,
                      stream the backend's response back to the client.

Production hardening in this version:
  - Correct client-IP resolution behind a trusted reverse proxy/load
    balancer (X-Forwarded-For), instead of trusting it blindly.
  - Static IP allow/deny lists (config-level, independent of the dynamic
    rate-limiter bans).
  - Security response headers on every response.
  - Redis-backed rate limiting option, for correctness across multiple
    worker processes/replicas (see src/rate_limiter.py).
  - Prometheus-format /__waf/metrics endpoint.
  - Fail-fast config validation with clear error messages.

Run (single process, fine for dev/low traffic):
    python scripts/05_run_waf.py --config config/waf_config.yaml

Run (production, multiple workers -- see README "Production deployment"):
    gunicorn src.waf_proxy:make_gunicorn_app \\
        --worker-class aiohttp.GunicornWebWorker \\
        --workers 4 --bind 127.0.0.1:8443
"""

from __future__ import annotations

import ipaddress
import ssl
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml
from aiohttp import web, ClientSession, ClientTimeout

from src.models import load_model
from src.baseline_signature import SignatureBaseline
from src.ensemble import EnsembleDetector, Verdict
from src.rate_limiter import build_rate_limiter
from src.waf_stats import build_stats
from src.waf_logging import WafLogger
from src.recon_detection import classify_recon
from src.request_validation import validate_request_integrity, is_websocket_upgrade
from src.json_extraction import extract_json_string_values
from src.anomaly_detection import AnomalyDetector

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "waf_config.yaml"

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Server": "waf",
}


_REQUIRED_KEYS = ["listen_host", "listen_port", "backend_url"]


def load_config(path: Path = DEFAULT_CONFIG_PATH) -> dict:
    if not path.exists():
        raise SystemExit(f"[waf] config file not found: {path}")
    with open(path) as f:
        config = yaml.safe_load(f) or {}

    missing = [k for k in _REQUIRED_KEYS if k not in config]
    if missing:
        raise SystemExit(f"[waf] config {path} is missing required keys: {missing}")

    tls_cfg = config.get("tls", {})
    if tls_cfg.get("enabled"):
        for key in ("certfile", "keyfile"):
            cert_path = Path(tls_cfg.get(key, ""))
            if not cert_path.exists():
                raise SystemExit(
                    f"[waf] tls.enabled is true but {key}={cert_path} does not exist. "
                    f"Run scripts/generate_self_signed_cert.py for a local dev cert, "
                    f"or point to a real certificate for production."
                )

    models = config.get("models", [])
    if not models:
        raise SystemExit("[waf] config.models is empty -- need at least one detector.")

    return config


def build_detectors(model_names: list[str]) -> dict[str, Any]:
    detectors = {}
    for name in model_names:
        if name == "signature_baseline":
            detectors[name] = SignatureBaseline()
        elif name == "anomaly":
            detectors[name] = AnomalyDetector()
        else:
            try:
                detectors[name] = load_model(name)
            except FileNotFoundError as e:
                raise SystemExit(
                    f"[waf] {e}\nTrain models first: python scripts/02_train_models.py"
                )
    return detectors


def resolve_client_ip(request: web.Request, trusted_proxies: list[str]) -> str:
    """
    If the WAF is deployed behind a trusted load balancer/CDN (e.g. Caddy,
    an internal nginx, a cloud LB), `request.remote` is that proxy's IP,
    not the real client's -- and blindly trusting the client-supplied
    X-Forwarded-For header instead would let any attacker spoof their
    source IP and dodge the rate limiter entirely.

    The correct middle ground: only trust X-Forwarded-For when the
    IMMEDIATE connection (request.remote) is itself one of our configured
    trusted_proxies. Otherwise, request.remote IS the real client and is
    used as-is.
    """
    direct_ip = request.remote or "unknown"

    if not trusted_proxies or direct_ip not in trusted_proxies:
        return direct_ip

    forwarded_for = request.headers.get("X-Forwarded-For")
    if not forwarded_for:
        return direct_ip

    candidate = forwarded_for.split(",")[0].strip()
    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        return direct_ip


def extract_inspectable_texts(path_qs: str, body_bytes: bytes, content_type: str) -> list[str]:
    """
    Returns a list of separate strings to classify individually: the
    URL path+query string, and (if present) the request body. Keeping
    them separate rather than concatenated means the WAF log can tell you
    exactly WHICH part of the request was malicious.
    """
    texts = [urllib.parse.unquote(path_qs)]

    if not body_bytes:
        return texts

    if "application/x-www-form-urlencoded" in content_type:
        texts.append(urllib.parse.unquote(body_bytes.decode("utf-8", errors="replace")))
    elif "application/json" in content_type:
        texts.append(body_bytes.decode("utf-8", errors="replace"))
    else:
        texts.append(body_bytes.decode("utf-8", errors="replace"))

    return texts


# Headers some SQLi scanners deliberately target once past the basic
# URL-parameter test level -- e.g. sqlmap's `--level 3` explicitly adds
# User-Agent and Referer as injection points, and `--level 5` adds Cookie.
# A hand-written app almost never puts SQL/JS-special characters in these
# headers, so classifying them costs little and closes a real gap in a
# query/body-only WAF.
_INSPECTABLE_HEADERS = ("User-Agent", "Referer", "Cookie", "X-Forwarded-For")


def extract_header_texts(headers) -> list[str]:
    return [headers[h] for h in _INSPECTABLE_HEADERS if h in headers and headers[h]]


class WafProxy:
    def __init__(self, config: dict):
        self.config = config
        self.backend_url = config["backend_url"].rstrip("/")
        self.policy = config.get("voting_policy", "any")

        self.detectors = build_detectors(config.get("models", ["logistic_regression", "signature_baseline"]))
        self.ensemble = EnsembleDetector(self.detectors, policy=self.policy)

        # Header content (User-Agent, Referer, Cookie, X-Forwarded-For) is
        # classified with the SIGNATURE baseline only, never the full ML
        # ensemble. The ML models were trained on query/body-shaped text
        # (e.g. "id=5&sort=asc") and were never shown legitimate
        # header-shaped text during training -- in testing, a completely
        # ordinary browser User-Agent like "Mozilla/5.0 (Windows NT 10.0;
        # Win64; x64)" got misclassified as SQLi by all three ML models,
        # purely because of its punctuation density, not its content. The
        # signature baseline has no such domain-shift problem since it
        # matches actual injection syntax (UNION SELECT, <script>, sleep(),
        # etc.) regardless of what kind of string it's embedded in, so it's
        # the safe, false-positive-resistant choice specifically for
        # inspecting header values.
        self._header_detector = SignatureBaseline()

        self.rate_limiter = build_rate_limiter(config.get("rate_limit", {}))

        self.trusted_proxies = config.get("trusted_proxies", [])
        self.static_allow = set(config.get("static_allow_ips", []))
        self.static_deny = set(config.get("static_deny_ips", []))
        self.allow_websocket_paths = set(config.get("allow_websocket_paths", []))

        self.admin_allowed_ips = set(config.get("admin_allowed_ips", ["127.0.0.1", "::1"]))
        self.logger = WafLogger(
            config.get("log_path", "logs/waf.log"),
            max_bytes=config.get("log_max_bytes", 10 * 1024 * 1024),
            backup_count=config.get("log_backup_count", 5),
        )

        self.stats = build_stats(self.rate_limiter)
        self._session: ClientSession | None = None

    async def start_session(self):
        self._session = ClientSession(timeout=ClientTimeout(total=self.config.get("backend_timeout_seconds", 10)))

    async def stop_session(self):
        if self._session:
            await self._session.close()

    def _is_admin_request(self, request: web.Request) -> bool:
        return request.path.startswith("/__waf/")

    async def _handle_admin(self, request: web.Request) -> web.Response:
        client_ip = resolve_client_ip(request, self.trusted_proxies)
        if client_ip not in self.admin_allowed_ips:
            return web.json_response({"error": "forbidden"}, status=403)

        if request.path == "/__waf/health":
            return web.json_response({"status": "ok"})

        if request.path == "/__waf/stats":
            current = self.stats.get_all()
            uptime = time.time() - current["started_at"]
            return web.json_response({
                **current,
                "uptime_seconds": round(uptime, 1),
                "policy": self.policy,
                "detectors": list(self.detectors.keys()),
                "rate_limiter": self.rate_limiter.stats(),
            })

        if request.path == "/__waf/metrics":
            return web.Response(text=self._prometheus_metrics(), content_type="text/plain")

        return web.json_response({"error": "not found"}, status=404)

    def _prometheus_metrics(self) -> str:
        """Minimal Prometheus text-exposition format -- scrape this with
        Prometheus/Grafana Agent/whatever your ops stack already uses,
        instead of polling /stats and reinventing a metrics pipeline."""
        current = self.stats.get_all()
        uptime = time.time() - current["started_at"]
        lines = [
            "# HELP waf_requests_allowed_total Requests forwarded to the backend",
            "# TYPE waf_requests_allowed_total counter",
            f"waf_requests_allowed_total {current['allowed']}",
            "# HELP waf_requests_blocked_total Requests blocked by the WAF",
            "# TYPE waf_requests_blocked_total counter",
            f"waf_requests_blocked_total {current['blocked']}",
            "# HELP waf_static_denied_total Requests rejected by the static deny list",
            "# TYPE waf_static_denied_total counter",
            f"waf_static_denied_total {current['static_denied']}",
            "# HELP waf_bans_triggered_total Times an IP crossed the auto-ban threshold",
            "# TYPE waf_bans_triggered_total counter",
            f"waf_bans_triggered_total {current['banned_ips_triggered']}",
            "# HELP waf_uptime_seconds Seconds since this WAF process started",
            "# TYPE waf_uptime_seconds gauge",
            f"waf_uptime_seconds {uptime:.1f}",
        ]
        return "\n".join(lines) + "\n"

    @web.middleware
    async def security_headers_middleware(self, request: web.Request, handler):
        response = await handler(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers[k] = v
        return response

    async def handle_request(self, request: web.Request) -> web.Response:
        if self._is_admin_request(request):
            return await self._handle_admin(request)

        try:
            return await self._handle_request_inner(request)
        except Exception as e:
            # Safety net for any unexpected bug in the classification/proxy
            # path: never let a Python traceback or exception string reach
            # the client (that's itself an information-disclosure bug in a
            # piece of software whose whole job is to be a security
            # control). Full detail is logged server-side only.
            import traceback
            print(f"[waf] UNEXPECTED ERROR handling request: {type(e).__name__}: {e}")
            traceback.print_exc()
            return web.json_response({"error": "Internal error"}, status=500)

    async def _handle_request_inner(self, request: web.Request) -> web.Response:
        client_ip = resolve_client_ip(request, self.trusted_proxies)
        t0 = time.perf_counter()

        if client_ip in self.static_allow:
            pass
        elif client_ip in self.static_deny:
            self.stats.increment("static_denied")
            self.logger.log_event(
                decision="blocked_static_deny", client_ip=client_ip, method=request.method,
                path=str(request.rel_url), label="denylisted", triggered_by=["static_deny_list"],
                latency_ms=(time.perf_counter() - t0) * 1000,
            )
            return web.json_response({"error": "Forbidden"}, status=403)

        if self.rate_limiter.is_blocked(client_ip):
            remaining = self.rate_limiter.seconds_remaining_banned(client_ip)
            self.stats.increment("blocked")
            self.logger.log_event(
                decision="blocked_ratelimit", client_ip=client_ip, method=request.method,
                path=str(request.rel_url), label="banned_ip", triggered_by=["rate_limiter"],
                latency_ms=(time.perf_counter() - t0) * 1000,
            )
            return web.json_response(
                {"error": "Too many malicious requests from this address", "retry_after_seconds": round(remaining)},
                status=429,
            )

        # 1.5. Recon/scanner pre-filter -- cheap (no body read needed),
        #      catches known pentest-tool signatures, sensitive-path
        #      probing, and IP-spoofing attempts BEFORE spending a model
        #      inference on the request. High-confidence recon signals
        #      count double toward the ban threshold (see rate_limiter.py).
        recon_verdict = classify_recon(str(request.rel_url), request.headers, client_ip, self.trusted_proxies)
        if recon_verdict.flagged:
            self.stats.increment("blocked")
            just_banned = self.rate_limiter.record_offense(client_ip, weight=2)
            if just_banned:
                self.stats.increment("banned_ips_triggered")
            self.logger.log_event(
                decision="blocked_recon", client_ip=client_ip, method=request.method,
                path=str(request.rel_url), label="recon", triggered_by=recon_verdict.reasons,
                latency_ms=(time.perf_counter() - t0) * 1000,
            )
            return web.json_response({"error": "Request blocked by WAF", "reason": "recon"}, status=403)

        # 1.6. Request-smuggling-class header validation -- ambiguous
        #      Content-Length/Transfer-Encoding combinations are rejected
        #      outright rather than guessed at (see request_validation.py
        #      for why this matters specifically in a Caddy -> WAF ->
        #      backend topology).
        integrity = validate_request_integrity(request.headers)
        if not integrity.valid:
            self.stats.increment("blocked")
            self.rate_limiter.record_offense(client_ip, weight=2)
            self.logger.log_event(
                decision="blocked_malformed", client_ip=client_ip, method=request.method,
                path=str(request.rel_url), label="malformed_request", triggered_by=[integrity.reason],
                latency_ms=(time.perf_counter() - t0) * 1000,
            )
            return web.json_response({"error": "Malformed request"}, status=400)

        # 1.7. WebSocket upgrades are explicitly rejected by default -- this
        #      WAF inspects request/response BODIES, which has no meaning
        #      once a connection upgrades to a binary WS frame stream.
        #      Silently proxying it through would give a false impression
        #      of protection. Add specific paths to
        #      config.allow_websocket_paths if you need WS support (those
        #      paths are then proxied WITHOUT payload inspection).
        if is_websocket_upgrade(request.headers):
            path = request.path
            if path not in self.allow_websocket_paths:
                self.stats.increment("blocked")
                self.logger.log_event(
                    decision="blocked_websocket", client_ip=client_ip, method=request.method,
                    path=path, label="websocket_not_allowed", triggered_by=["websocket_upgrade"],
                    latency_ms=(time.perf_counter() - t0) * 1000,
                )
                return web.json_response(
                    {"error": "WebSocket not supported on this path"}, status=400
                )
            # Explicitly allow-listed: proxy through untouched, no
            # payload inspection (documented gap, operator opt-in only).
            self.stats.increment("allowed")
            self.logger.log_event(
                decision="allowed_websocket_passthrough", client_ip=client_ip, method=request.method,
                path=path, label="benign", triggered_by=[],
                latency_ms=(time.perf_counter() - t0) * 1000,
            )
            return await self._proxy_to_backend(request, b"")

        body_bytes = await request.read()
        content_type = request.headers.get("Content-Type", "")

        if "application/json" in content_type:
            json_result = extract_json_string_values(body_bytes)
            body_texts = [urllib.parse.unquote(str(request.rel_url))] + json_result.string_values
            if not json_result.was_valid_json:
                # Malformed JSON despite the declared Content-Type -- log
                # it as a distinct signal without auto-blocking (plenty of
                # legitimate clients send slightly wrong JSON).
                self.logger.log_event(
                    decision="note_malformed_json", client_ip=client_ip, method=request.method,
                    path=str(request.rel_url), label="malformed_json", triggered_by=["json_extraction"],
                    latency_ms=0.0,
                )
        else:
            body_texts = extract_inspectable_texts(str(request.rel_url), body_bytes, content_type)

        header_texts = extract_header_texts(request.headers)

        worst_verdict = None
        for text in body_texts:
            if not text:
                continue
            verdict = self.ensemble.classify(text)
            if verdict.blocked:
                worst_verdict = verdict
                break

        if worst_verdict is None:
            for text in header_texts:
                if not text:
                    continue
                label = self._header_detector.predict([text])[0]
                if label != "benign":
                    worst_verdict = Verdict(blocked=True, final_label=label, votes={"signature_baseline": label},
                                             triggered_by=["signature_baseline"])
                    break

        latency_ms = (time.perf_counter() - t0) * 1000

        if worst_verdict is not None:
            self.stats.increment("blocked")
            just_banned = self.rate_limiter.record_offense(client_ip)
            if just_banned:
                self.stats.increment("banned_ips_triggered")

            self.logger.log_event(
                decision="blocked", client_ip=client_ip, method=request.method,
                path=str(request.rel_url), label=worst_verdict.final_label,
                triggered_by=worst_verdict.triggered_by, latency_ms=latency_ms,
            )
            return web.json_response(
                {"error": "Request blocked by WAF", "reason": worst_verdict.final_label},
                status=403,
            )

        self.stats.increment("allowed")
        self.logger.log_event(
            decision="allowed", client_ip=client_ip, method=request.method,
            path=str(request.rel_url), label="benign", triggered_by=[], latency_ms=latency_ms,
        )
        return await self._proxy_to_backend(request, body_bytes)

    async def _proxy_to_backend(self, request: web.Request, body_bytes: bytes) -> web.Response:
        target_url = f"{self.backend_url}{request.rel_url}"
        forward_headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in ("host", "content-length")
        }
        try:
            async with self._session.request(
                request.method, target_url, headers=forward_headers, data=body_bytes,
            ) as backend_resp:
                body = await backend_resp.read()
                return web.Response(
                    body=body, status=backend_resp.status,
                    headers={k: v for k, v in backend_resp.headers.items() if k.lower() != "content-length"},
                )
        except Exception as e:
            # Deliberately generic message to the CLIENT -- the exception
            # string can contain internal hostnames, ports, or stack
            # details (e.g. connection-refused to a backend IP) that have
            # no business being visible to whoever sent the request.
            # Full detail still goes to the server-side log for debugging.
            print(f"[waf] backend request failed: {type(e).__name__}: {e}")
            return web.json_response({"error": "Upstream server error"}, status=502)


def build_ssl_context(config: dict) -> ssl.SSLContext | None:
    tls_cfg = config.get("tls", {})
    if not tls_cfg.get("enabled", False):
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=tls_cfg["certfile"], keyfile=tls_cfg["keyfile"])
    return ctx


def create_app(config: dict) -> tuple[web.Application, WafProxy]:
    waf = WafProxy(config)
    app = web.Application(
        client_max_size=config.get("max_request_size_bytes", 10 * 1024 * 1024),
        middlewares=[waf.security_headers_middleware],
    )

    async def on_startup(_app):
        await waf.start_session()

    async def on_cleanup(_app):
        await waf.stop_session()

    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    app.router.add_route("*", "/{tail:.*}", waf.handle_request)
    return app, waf


async def make_gunicorn_app():
    """
    Entry point for production multi-worker deployment:

        gunicorn src.waf_proxy:make_gunicorn_app \\
            --worker-class aiohttp.GunicornWebWorker \\
            --workers 4 --bind 127.0.0.1:8443

    Reads config from the path in the WAF_CONFIG env var (defaults to
    config/waf_config.yaml). TLS is expected to be terminated by whatever
    sits in front of gunicorn in this mode (see README "Production
    deployment" -- typically Caddy or nginx).

    Must be `async def` (returning the Application, not just constructing
    it) -- aiohttp.GunicornWebWorker specifically requires either an
    Application instance or an async factory function; a plain sync
    function raises RuntimeError at worker boot.
    """
    import os
    config_path = Path(os.environ.get("WAF_CONFIG", str(DEFAULT_CONFIG_PATH)))
    config = load_config(config_path)
    app, _waf = create_app(config)
    return app


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Inline reverse-proxy WAF")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    args = parser.parse_args()

    config = load_config(args.config)
    app, waf = create_app(config)
    ssl_context = build_ssl_context(config)

    scheme = "https" if ssl_context else "http"
    print(f"[waf] listening on {scheme}://{config['listen_host']}:{config['listen_port']}")
    print(f"[waf] forwarding clean traffic to {config['backend_url']}")
    print(f"[waf] detectors: {list(waf.detectors.keys())}  policy={waf.policy}")
    print(f"[waf] rate limiter backend: {waf.rate_limiter.stats()['backend']}")
    if waf.trusted_proxies:
        print(f"[waf] trusting X-Forwarded-For from: {waf.trusted_proxies}")
    print(f"[waf] admin endpoints: /__waf/health /__waf/stats /__waf/metrics "
          f"(allowed from {waf.admin_allowed_ips})")
    print("[waf] NOTE: single-process mode. For production traffic, run via gunicorn "
          "with multiple workers -- see README 'Production deployment'.")

    web.run_app(app, host=config["listen_host"], port=config["listen_port"], ssl_context=ssl_context)


if __name__ == "__main__":
    main()
