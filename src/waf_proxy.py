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
       - malicious -> log, record a refusal against the IP (may trigger an
                      auto-ban), return 403 with a JSON error body.
       - benign    -> record an allowed request against the IP, forward it
                      to the real backend unmodified, stream the backend's
                      response back to the client.
     The rate limiter bans on each IP's ratio of refused to total requests
     over a sliding window, with escalating bans for repeat offenders
     (see src/rate_limiter.py).

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
import secrets
import ssl
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import yaml
from aiohttp import web, ClientSession, ClientTimeout

from src.models import MODELS_DIR, AbstainOnUnknown, load_model
from src.baseline_signature import WAF_EXTRA_SQLI_PATTERNS, WAF_EXTRA_XSS_PATTERNS, SignatureBaseline
from src.baseline_normalized import NormalizedSignatureBaseline
from src.ensemble import EnsembleDetector, Verdict
from src.rate_limiter import build_rate_limiter
from src.waf_stats import build_stats
from src.waf_logging import WafLogger
from src.recon_detection import classify_recon
from src.request_validation import validate_request_integrity, is_websocket_upgrade
from src.json_extraction import extract_json_string_values
from src.waf_canonical import waf_views
from src.anomaly_detection import AnomalyDetector
from src.agent_defense import agent_config_from_dict, build_agent_defense

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "waf_config.yaml"

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    # Neutral value: "waf" announced the WAF to every fingerprinting tool
    # (wafw00f, and the first recon step of AI pentest agents).
    "Server": "httpd",
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

    if config.get("model_set", "deploy") not in ("deploy", "paper"):
        raise SystemExit(f"[waf] config.model_set must be 'deploy' or 'paper', got {config.get('model_set')!r}")

    if config.get("mode", "block") not in ("block", "monitor"):
        raise SystemExit(f"[waf] config.mode must be 'block' or 'monitor', got {config.get('mode')!r}")

    try:
        agent_config_from_dict(config.get("agent_defense"))
    except (TypeError, ValueError) as e:
        raise SystemExit(f"[waf] invalid agent_defense section: {e}")

    return config


def build_detectors(model_names: list[str], model_set: str = "deploy") -> dict[str, Any]:
    # "deploy": models/deploy/ (scripts/train_deploy_models.py) -- trained on
    #           the paper's training split plus diverse real-world benign
    #           inputs; the default for live traffic.
    # "paper" : models/*.joblib, exactly as evaluated in the paper.
    models_dir = MODELS_DIR / "deploy" if model_set == "deploy" else MODELS_DIR
    detectors = {}
    for name in model_names:
        if name == "signature_baseline":
            detectors[name] = SignatureBaseline(extra_sqli_patterns=WAF_EXTRA_SQLI_PATTERNS,
                                                extra_xss_patterns=WAF_EXTRA_XSS_PATTERNS)
        elif name == "anomaly":
            detectors[name] = AnomalyDetector()
        else:
            try:
                # Abstain on out-of-vocabulary input instead of voting the
                # class prior (see AbstainOnUnknown) -- otherwise bare paths
                # like "/login" are blocked as SQLi.
                detectors[name] = AbstainOnUnknown(load_model(name, models_dir))
            except FileNotFoundError as e:
                script = "train_deploy_models.py" if model_set == "deploy" else "02_train_models.py"
                raise SystemExit(f"[waf] {e}\nTrain models first: python scripts/{script}")
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


def extract_url_path(path_qs: str) -> str:
    """The decoded URL path, which is classified by signature rules only.

    The ML models were trained on parameter strings ("id=5&sort=asc") and
    never saw a URL path; bare paths like "/login" or "/api/users" land on
    the prior or on a single SQL-ish token ("users") and were blocked as
    SQLi. Paths get the same signature-only treatment as headers.
    """
    return urllib.parse.unquote(urllib.parse.urlsplit(path_qs).path)


def extract_inspectable_texts(path_qs: str, body_bytes: bytes, content_type: str) -> list[str]:
    """
    Returns a list of separate strings for the ML ensemble to classify
    individually: the query string (if any), and (if present) the request
    body. Keeping them separate rather than concatenated means the WAF log
    can tell you exactly WHICH part of the request was malicious. The URL
    path is handled separately, see extract_url_path().
    """
    query = urllib.parse.urlsplit(path_qs).query
    texts = [urllib.parse.unquote(query)] if query else []

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
        # "monitor": detection verdicts are logged as would_block_* and the
        # request is forwarded (no ban offenses). Protocol-safety rejections
        # (smuggling ambiguity, WebSocket, static deny) are still enforced.
        self.monitor = config.get("mode", "block") == "monitor"

        self.detectors = build_detectors(config.get("models", ["logistic_regression", "signature_baseline"]),
                                         config.get("model_set", "deploy"))
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
        # R5 FIX: use NormalizedSignatureBaseline so encoded header values
        # (e.g. URL-encoded SQLi) are canonicalized before rule matching.
        # Raw strings are passed in; canonicalization happens once inside.
        self._header_detector = NormalizedSignatureBaseline(extra_sqli_patterns=WAF_EXTRA_SQLI_PATTERNS,
                                                            extra_xss_patterns=WAF_EXTRA_XSS_PATTERNS)

        self.rate_limiter = build_rate_limiter(config.get("rate_limit", {}))
        # AI-agent defense (src/agent_defense.py): probation for clients that
        # showed attack intent, cross-client payload-family memory, suspicion
        # score (honeypots, enumeration, fingerprint), error-oracle removal.
        self.agent = build_agent_defense(config.get("agent_defense"), self.rate_limiter)
        self.deny_notice = (config.get("agent_defense") or {}).get("deny_notice")

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
            "# HELP waf_requests_would_block_total Requests monitor mode forwarded but would have blocked",
            "# TYPE waf_requests_would_block_total counter",
            f"waf_requests_would_block_total {current['would_block']}",
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

    def _deny(self, request_id: str) -> web.Response:
        """The single response for every detection-based refusal (payload,
        recon, agent, ban, static deny, inspection limit). Identical bodies
        and status deny an adaptive attacker the feedback of which layer
        fired or whether it is banned: once banned, every probe looks
        blocked. request_id lets a legitimate user report a false positive;
        it is logged with the full reason. The optional deny_notice (same on
        every refusal) is text addressed to LLM agents reading the response."""
        body = {"error": "Forbidden", "request_id": request_id}
        if self.deny_notice:
            body["notice"] = self.deny_notice
        return web.json_response(body, status=403)

    @staticmethod
    def inspection_texts(path_qs: str, headers, body_bytes: bytes, content_type: str,
                         json_result=None) -> tuple[list[str], list[str], list[str]]:
        """Splits a request into (ml_texts, signature_texts, header_texts):
        query/form/JSON "key=value" leaves for the ML ensemble; URL path,
        bare JSON strings and headers for the signature rules only (the
        last also returned separately)."""
        if "application/json" in content_type:
            if json_result is None:
                json_result = extract_json_string_values(body_bytes)
            # ML sees "key=value" leaves (its training shape); every bare key
            # and value still goes through the signature rules below.
            ml_texts = extract_inspectable_texts(path_qs, b"", "") + json_result.pairs
            json_signature_texts = json_result.string_values
        else:
            ml_texts = extract_inspectable_texts(path_qs, body_bytes, content_type)
            json_signature_texts = []
        header_texts = extract_header_texts(headers)
        signature_texts = [extract_url_path(path_qs)] + json_signature_texts + header_texts
        return ml_texts, signature_texts, header_texts

    def classify_payload(self, path_qs: str, headers, body_bytes: bytes, content_type: str,
                         json_result=None) -> Verdict | None:
        """Content inspection for one request; returns the blocking Verdict
        or None. Pure (no I/O, logging or rate limiting), so offline
        evaluation (scripts/evaluate_waf_realworld.py) runs exactly the
        decision the live proxy makes."""
        body_texts, signature_only_texts, _ = self.inspection_texts(path_qs, headers, body_bytes,
                                                                    content_type, json_result)

        for text in body_texts:
            if not text:
                continue
            # Canonicalize before the ensemble (the paper's recommended
            # configuration), plus the WAF-only evasion views -- see
            # waf_canonical.py. Block if any view is malicious.
            for view in waf_views(text):
                verdict = self.ensemble.classify(view)
                if verdict.blocked:
                    verdict.matched_text = text
                    return verdict

        for text in signature_only_texts:
            if not text:
                continue
            for view in waf_views(text):
                label = self._header_detector.predict([view])[0]
                if label != "benign":
                    return Verdict(blocked=True, final_label=label, votes={"signature_baseline": label},
                                   triggered_by=["signature_baseline"], matched_text=text)
        return None

    @web.middleware
    async def security_headers_middleware(self, request: web.Request, handler):
        response = await handler(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers[k] = v
        return response

    def _record_behavior(self, client_ip: str, refused: bool, weight: int = 1) -> None:
        """Feeds one decision into the behavioral rate limiter, which bans
        on the RATIO of refused to total requests per IP (plus an absolute
        anti-dilution cap) and escalates ban length for repeat offenders --
        so allowed requests must be recorded too (see rate_limiter.py)."""
        if not self.rate_limiter.record_request(client_ip, refused=refused, weight=weight):
            return
        self.stats.increment("banned_ips_triggered")
        strike = self.rate_limiter.strikes(client_ip)
        self.logger.log_event(
            decision="ip_banned", client_ip=client_ip, method="-", path="-",
            label=f"strike_{strike}",
            triggered_by=[f"ban_seconds={round(self.rate_limiter.seconds_remaining_banned(client_ip))}"],
            latency_ms=0.0,
        )

    async def handle_request(self, request: web.Request) -> web.Response:
        if self._is_admin_request(request):
            return await self._handle_admin(request)

        try:
            return await self._handle_request_inner(request)
        except web.HTTPRequestEntityTooLarge:
            # R4 FIX (proper location): body read at line 420 raises this
            # before reaching _proxy_to_backend; catch it here so the client
            # gets 413, not 500 from the generic handler below.
            return web.Response(status=413, text="Request body too large")
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
        # R2 FIX: keep both the connection address and the resolved client IP.
        # classify_recon() needs the DIRECT connection address (request.remote)
        # to decide whether X-Forwarded-For is trusted or spoofed.
        # rate_limiter, banning, and logging use client_ip (the resolved value).
        connection_ip = request.remote or "unknown"
        client_ip = resolve_client_ip(request, self.trusted_proxies)
        t0 = time.perf_counter()
        request_id = secrets.token_hex(8)

        if client_ip in self.static_allow:
            pass
        elif client_ip in self.static_deny:
            self.stats.increment("static_denied")
            self.logger.log_event(
                decision="blocked_static_deny", client_ip=client_ip, method=request.method,
                path=str(request.rel_url), label="denylisted", triggered_by=["static_deny_list"],
                latency_ms=(time.perf_counter() - t0) * 1000, request_id=request_id,
            )
            return self._deny(request_id)

        if self.rate_limiter.is_blocked(client_ip):
            # Same 403 as a detection (not 429 + remaining seconds): a banned
            # attacker cannot tell a ban from a block, nor pace around it.
            self.stats.increment("blocked")
            self.logger.log_event(
                decision="blocked_ratelimit", client_ip=client_ip, method=request.method,
                path=str(request.rel_url), label="banned_ip", triggered_by=["rate_limiter"],
                latency_ms=(time.perf_counter() - t0) * 1000, request_id=request_id,
            )
            return self._deny(request_id)

        # 1.4. AI-agent client assessment -- decoy (honeypot) paths, client
        #      fingerprint, and the client's accumulated suspicion score
        #      (enumeration, backend error leaks it provoked, probation
        #      refusals). See src/agent_defense.py.
        assessment = None
        if self.agent is not None:
            assessment = self.agent.assess(client_ip, extract_url_path(str(request.rel_url)), request.headers)
            if assessment.flagged:
                blocked = self._refuse_or_note(client_ip, request, "agent", assessment.reasons,
                                               request_id, t0, weight=2)
                if blocked is not None:
                    return blocked

        # 1.5. Recon/scanner pre-filter -- cheap (no body read needed),
        #      catches known pentest-tool signatures, sensitive-path
        #      probing, and IP-spoofing attempts BEFORE spending a model
        #      inference on the request. High-confidence recon signals
        #      count double toward the ban threshold (see rate_limiter.py).
        recon_verdict = classify_recon(str(request.rel_url), request.headers, connection_ip, self.trusted_proxies)
        if recon_verdict.flagged and self.monitor:
            self.stats.increment("would_block")
            self.logger.log_event(
                decision="would_block_recon", client_ip=client_ip, method=request.method,
                path=str(request.rel_url), label="recon", triggered_by=recon_verdict.reasons,
                latency_ms=(time.perf_counter() - t0) * 1000,
            )
        elif recon_verdict.flagged:
            self.stats.increment("blocked")
            self._record_behavior(client_ip, refused=True, weight=2)
            self.logger.log_event(
                decision="blocked_recon", client_ip=client_ip, method=request.method,
                path=str(request.rel_url), label="recon", triggered_by=recon_verdict.reasons,
                latency_ms=(time.perf_counter() - t0) * 1000, request_id=request_id,
            )
            return self._deny(request_id)

        # 1.6. Request-smuggling-class header validation -- ambiguous
        #      Content-Length/Transfer-Encoding combinations are rejected
        #      outright rather than guessed at (see request_validation.py
        #      for why this matters specifically in a Caddy -> WAF ->
        #      backend topology).
        integrity = validate_request_integrity(request.headers)
        if not integrity.valid:
            self.stats.increment("blocked")
            self._record_behavior(client_ip, refused=True, weight=2)
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
            # R4 FIX: implement proper two-way WebSocket relay instead of
            # routing through HTTP proxy (which strips Upgrade headers).
            self.stats.increment("allowed")
            self.logger.log_event(
                decision="allowed_websocket_relay", client_ip=client_ip, method=request.method,
                path=path, label="benign", triggered_by=[],
                latency_ms=(time.perf_counter() - t0) * 1000,
            )
            return await self._relay_websocket(request)

        body_bytes = await request.read()
        content_type = request.headers.get("Content-Type", "")

        if "application/json" in content_type:
            json_result = extract_json_string_values(body_bytes)
            # R1 FIX: reject if traversal hit a limit — uninspected tail
            # may contain a payload (documented in json_extraction.py).
            if json_result.truncated and self.monitor:
                self.stats.increment("would_block")
                self.logger.log_event(
                    decision="would_block", client_ip=client_ip, method=request.method,
                    path=str(request.rel_url), label="incomplete_json_inspection",
                    triggered_by=["json_truncation"],
                    latency_ms=(time.perf_counter() - t0) * 1000,
                )
            elif json_result.truncated:
                self.stats.increment("blocked")
                self.logger.log_event(
                    decision="blocked", client_ip=client_ip, method=request.method,
                    path=str(request.rel_url), label="incomplete_json_inspection",
                    triggered_by=["json_truncation"],
                    latency_ms=(time.perf_counter() - t0) * 1000, request_id=request_id,
                )
                return self._deny(request_id)
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
            json_result = None

        worst_verdict = self.classify_payload(str(request.rel_url), request.headers,
                                              body_bytes, content_type, json_result)
        ml_texts, _, header_texts = self.inspection_texts(str(request.rel_url), request.headers,
                                                          body_bytes, content_type, json_result)
        strict_texts = ml_texts + [extract_url_path(str(request.rel_url))]

        if self.agent is not None:
            if worst_verdict is not None:
                self.agent.remember_block(client_ip, worst_verdict.matched_text)
            else:
                # Content the ensemble passed: probation rules for clients
                # that showed attack intent, and the cross-client payload-
                # family memory (catches the bypass an agent found by
                # mutating, even from a fresh IP).
                agent_reasons, offending = self.agent.check_content(client_ip, assessment,
                                                                    strict_texts, header_texts)
                if agent_reasons:
                    self.agent.remember_block(client_ip, offending)
                    blocked = self._refuse_or_note(client_ip, request, "agent_content", agent_reasons,
                                                   request_id, t0, weight=1)
                    if blocked is not None:
                        return blocked

        latency_ms = (time.perf_counter() - t0) * 1000

        if worst_verdict is not None and self.monitor:
            self.stats.increment("would_block")
            self.logger.log_event(
                decision="would_block", client_ip=client_ip, method=request.method,
                path=str(request.rel_url), label=worst_verdict.final_label,
                triggered_by=worst_verdict.triggered_by, latency_ms=latency_ms,
            )
            return await self._proxy_to_backend(request, body_bytes, client_ip, strict_texts)

        if worst_verdict is not None:
            self.stats.increment("blocked")
            self._record_behavior(client_ip, refused=True)

            self.logger.log_event(
                decision="blocked", client_ip=client_ip, method=request.method,
                path=str(request.rel_url), label=worst_verdict.final_label,
                triggered_by=worst_verdict.triggered_by, latency_ms=latency_ms, request_id=request_id,
            )
            return self._deny(request_id)

        self.stats.increment("allowed")
        self._record_behavior(client_ip, refused=False)
        self.logger.log_event(
            decision="allowed", client_ip=client_ip, method=request.method,
            path=str(request.rel_url), label="benign", triggered_by=[], latency_ms=latency_ms,
        )
        return await self._proxy_to_backend(request, body_bytes, client_ip, strict_texts)

    def _refuse_or_note(self, client_ip: str, request: web.Request, label: str, reasons: list[str],
                        request_id: str, t0: float, weight: int) -> web.Response | None:
        """Agent-defense refusal: the uniform 403 in block mode (recorded
        as a refusal for the rate limiter), or only a would_block log line
        in monitor mode (returns None; the caller carries on)."""
        latency_ms = (time.perf_counter() - t0) * 1000
        if self.monitor:
            self.stats.increment("would_block")
            self.logger.log_event(
                decision=f"would_block_{label}", client_ip=client_ip, method=request.method,
                path=str(request.rel_url), label=label, triggered_by=reasons, latency_ms=latency_ms,
            )
            return None
        self.stats.increment("blocked")
        self._record_behavior(client_ip, refused=True, weight=weight)
        self.logger.log_event(
            decision=f"blocked_{label}", client_ip=client_ip, method=request.method,
            path=str(request.rel_url), label=label, triggered_by=reasons, latency_ms=latency_ms,
            request_id=request_id,
        )
        return self._deny(request_id)

    async def _relay_websocket(self, request: web.Request) -> web.WebSocketResponse:
        """Two-way WebSocket relay for allow-listed paths (R4 fix).

        Opens a server-side WebSocket to the client and a client-side
        WebSocket to the backend, then relays frames in both directions
        until either side closes.
        """
        import aiohttp
        ws_client = web.WebSocketResponse()
        await ws_client.prepare(request)

        backend_ws_url = self.backend_url.replace("http://", "ws://").replace("https://", "wss://")
        backend_ws_url += str(request.rel_url)

        try:
            async with self._session.ws_connect(backend_ws_url) as ws_backend:
                async def client_to_backend():
                    async for msg in ws_client:
                        if msg.type == aiohttp.WSMsgType.TEXT:
                            await ws_backend.send_str(msg.data)
                        elif msg.type == aiohttp.WSMsgType.BINARY:
                            await ws_backend.send_bytes(msg.data)
                        elif msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.ERROR):
                            break

                async def backend_to_client():
                    async for msg in ws_backend:
                        if msg.type == aiohttp.WSMsgType.TEXT:
                            await ws_client.send_str(msg.data)
                        elif msg.type == aiohttp.WSMsgType.BINARY:
                            await ws_client.send_bytes(msg.data)
                        elif msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.ERROR):
                            break

                import asyncio
                done, pending = await asyncio.wait(
                    [asyncio.ensure_future(client_to_backend()),
                     asyncio.ensure_future(backend_to_client())],
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for task in pending:
                    task.cancel()
        except Exception as e:
            print(f"[waf] WebSocket relay error: {type(e).__name__}: {e}")
        finally:
            if not ws_client.closed:
                await ws_client.close()
        return ws_client

    async def _proxy_to_backend(self, request: web.Request, body_bytes: bytes,
                                client_ip: str | None = None,
                                request_texts: list[str] | None = None) -> web.Response:
        target_url = f"{self.backend_url}{request.rel_url}"
        # R3 FIX: strip hop-by-hop and encoding headers that must be
        # rebuilt from the actual body sent.  aiohttp reads the full body
        # so we must not forward Transfer-Encoding or Content-Encoding
        # to the backend (it will receive raw bytes, not chunked/gzip).
        _HOP_BY_HOP = {
            "transfer-encoding", "te", "trailers", "upgrade",
            "connection", "keep-alive", "proxy-authenticate",
            "proxy-authorization",
        }
        forward_headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in _HOP_BY_HOP
            and k.lower() not in ("host", "content-length", "content-encoding")
        }
        try:
            async with self._session.request(
                request.method, target_url,
                headers=forward_headers,
                data=body_bytes,
                allow_redirects=False,   # R4 FIX: pass 3xx to client, don't follow
            ) as backend_resp:
                body = await backend_resp.read()
                if self.agent is not None and client_ip is not None and self.agent.observe_response(
                        client_ip, request.path, backend_resp.status,
                        backend_resp.headers.get("Content-Type", ""), body, request_texts or []):
                    # The backend leaked a DB error / stack trace: the
                    # feedback error-based SQLi and agent reasoning run on.
                    decision = "would_scrub_error_leak" if self.monitor else "scrubbed_error_leak"
                    self.logger.log_event(
                        decision=decision, client_ip=client_ip, method=request.method,
                        path=str(request.rel_url), label="error_leak",
                        triggered_by=[f"backend_status={backend_resp.status}"], latency_ms=0.0,
                    )
                    if not self.monitor:
                        return web.json_response({"error": "Internal error"}, status=500)
                # R3 FIX: preserve multi-value response headers (e.g. Set-Cookie)
                # and strip hop-by-hop + encoding headers from the response too.
                _RESP_HOP_BY_HOP = _HOP_BY_HOP | {"content-encoding", "content-length"}
                resp_headers = {}
                for k, v in backend_resp.headers.items():
                    if k.lower() in _RESP_HOP_BY_HOP:
                        continue
                    # Accumulate multi-value headers (e.g. multiple Set-Cookie)
                    if k.lower() in resp_headers:
                        # aiohttp flattens them; use comma join for most,
                        # but Set-Cookie must be separate — signal via list
                        existing = resp_headers[k.lower()]
                        if not isinstance(existing, list):
                            resp_headers[k.lower()] = [existing]
                        resp_headers[k.lower()].append(v)
                    else:
                        resp_headers[k.lower()] = v

                response = web.Response(body=body, status=backend_resp.status)
                for k, v in resp_headers.items():
                    if isinstance(v, list):
                        for item in v:
                            response.headers.add(k, item)
                    else:
                        response.headers[k] = v
                return response
        except web.HTTPRequestEntityTooLarge:
            # R4 FIX: preserve 413 status instead of letting it become 500
            return web.Response(status=413, text="Request body too large")
        except Exception as e:
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
    print(f"[waf] AI-agent defense: "
          f"{'on (' + waf.agent.store.backend + ')' if waf.agent else 'off'}")
    if waf.trusted_proxies:
        print(f"[waf] trusting X-Forwarded-For from: {waf.trusted_proxies}")
    print(f"[waf] admin endpoints: /__waf/health /__waf/stats /__waf/metrics "
          f"(allowed from {waf.admin_allowed_ips})")
    print("[waf] NOTE: single-process mode. For production traffic, run via gunicorn "
          "with multiple workers -- see README 'Production deployment'.")

    web.run_app(app, host=config["listen_host"], port=config["listen_port"], ssl_context=ssl_context)


if __name__ == "__main__":
    main()
