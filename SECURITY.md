# Security Posture & Self-Audit

This document exists so anyone evaluating this project (a reviewer, a
supervisor, a future employer, or you in six months) can see exactly what
was checked, what was found and fixed, and — just as importantly — what
was **not** checked, without having to take a marketing-style "production
ready!" claim at face value.

**Bottom line, stated plainly:** this project is architecturally sound —
the same request-inspection, rate-limiting, and deployment patterns real
WAFs use — and has had a real internal security self-review with several
concrete bugs found and fixed as a result (documented below). It has
**not** had an independent, professional security audit, and has **not**
been battle-tested against real, sustained internet traffic. Treat it as
one security layer, not the only one — see "Recommended posture" at the
end.

---

## Threat model

### In scope (this WAF is designed to defend against)
- SQL Injection and Cross-Site Scripting payloads in the URL query string,
  URL path, POST body (form-urlencoded and JSON), and select headers
  (User-Agent, Referer, Cookie, X-Forwarded-For).
- Obfuscated variants of the above (URL/double encoding, whitespace
  manipulation, case toggling, comment insertion, Unicode substitution —
  see Chapter 3's Table 3.1 for the full list this was benchmarked against).
- Reconnaissance and automated-scanner traffic: known pentest-tool User-Agent
  signatures (sqlmap, nikto, nuclei, gobuster/dirb/ffuf/dirsearch/
  feroxbuster, wpscan, dalfox/xsstrike, wafw00f, and orchestrators that wrap
  them, e.g. HexStrike AI), sensitive-path probing (`.git`, `.env`, backup
  files, etc.), and forwarded-IP header spoofing.
- Repeat-offender IPs (rate-limited and auto-banned, shared correctly
  across multiple worker processes via Redis).
- Request-smuggling-class header ambiguity (conflicting/malformed
  Content-Length and Transfer-Encoding).
- A non-ML statistical anomaly check as a second, independent signal
  against adversarial payloads crafted specifically to sit outside the
  ML models' training distribution.

### Explicitly out of scope (documented gaps, not silent ones)
- **HTTP/2 and HTTP/3 end-to-end.** The WAF itself speaks HTTP/1.1; in the
  recommended production topology, Caddy (in front) handles HTTP/2/3 with
  clients and speaks HTTP/1.1 to the WAF, which is an accepted, deliberate
  design choice, not an oversight.
- **WebSocket payload inspection.** Upgrade requests are detected and
  rejected by default (not silently mis-proxied); if you explicitly
  allow-list a path for WebSocket, that traffic is proxied through with
  **no** payload inspection at all, since a binary WS frame stream doesn't
  fit this WAF's text-classification model.
- **CSRF, business-logic vulnerabilities, authentication/authorization
  bugs, deserialization attacks, file-upload malware scanning, DDoS/
  volumetric attack mitigation, TLS/JA3 fingerprinting.** None of these
  are payload-classification problems this WAF's architecture addresses;
  they need their own dedicated controls.
- **Guaranteed robustness against adversarial ML evasion.** See "Accepted
  limitations" below — this is a fundamental property of trained
  classifiers in general, not something this project claims to have
  solved.

---

## Self-audit: what was specifically checked

This is not a professional penetration test of the WAF itself (see
"Accepted limitations"), but a deliberate internal review pass looking for
common classes of bugs in security-critical code, done while building the
hardening features. Three real, concrete bugs were found and fixed as a
direct result — documented here rather than quietly folded in, since a
security tool that's honest about its own bug history is more credible
than one that claims to have been perfect from the start:

| # | Finding | Fix |
|---|---|---|
| 1 | ML ensemble misclassified an ordinary browser User-Agent string as SQLi when header content was fed through it (domain shift — models were trained only on query/body-shaped text) | Header content is now checked with the signature baseline **only**, never the ML ensemble. Regression test added (`test_header_content_uses_signature_only_not_ml_ensemble`). |
| 2 | `make_gunicorn_app` was a plain sync function; `aiohttp.GunicornWebWorker` requires an async factory and fails at worker boot otherwise | Changed to `async def`. |
| 3 | Per-worker request counters (`/__waf/stats`, `/__waf/metrics`) were process-local under gunicorn, silently under-reporting totals across multiple workers | Counters now go through `waf_stats.py`, which is Redis-backed (shared, accurate) whenever the rate limiter is Redis-backed too. Verified with two independent instances proving shared state. |

Additional hardening applied during self-review (not bugs in the sense of
"broken," but gaps that a more adversarial review turned up):

- **Backend-error information disclosure**: a 502 response used to include
  the raw exception string from the failed backend connection (potentially
  leaking internal hostnames/ports). Now returns a generic message to the
  client; full detail is logged server-side only.
- **Unhandled-exception information disclosure**: `handle_request` is now
  wrapped in a top-level safety net that guarantees no Python traceback or
  exception string ever reaches the client, regardless of what bug might
  exist elsewhere in the classification/proxy path — logged server-side,
  generic `500` to the client.
- **Log injection**: log lines are built with `json.dumps()`, which
  properly escapes embedded newlines/control characters in any
  attacker-supplied string (User-Agent, path, etc.), so a crafted header
  can't forge additional fake log lines. Verified this is the case rather
  than assumed.
- **Request-smuggling-class ambiguity** (conflicting/malformed
  Content-Length + Transfer-Encoding combinations): explicitly rejected
  rather than relying on aiohttp's parser behavior matching Caddy's by
  coincidence — see `src/request_validation.py`.
- **Redis without authentication**: `build_rate_limiter()` now prints a
  loud, explicit warning at startup if `redis_url` points to a
  non-loopback address with no credentials, rather than staying silent
  about a plausible misconfiguration.
- **JSON body evasion via escaping**: raw-text classification of a JSON
  body can miss a payload that's only present after JSON's own unescaping
  (e.g. `\u0027` never appears as a literal `'` in the raw bytes).
  `src/json_extraction.py` parses the JSON properly and classifies the
  actual decoded string values.
- **Regex complexity**: the signature baseline, recon-detection, and
  tokenizer patterns were reviewed for catastrophic-backtracking shapes
  (nested quantifiers like `(a+)+`) — none were found; all patterns are
  simple alternations/character classes with linear worst-case behavior.
- **Resource exhaustion via deeply nested JSON**: `json_extraction.py`
  caps recursion depth (25) and the number of string values classified per
  request (200), so a pathological JSON body can't be used to burn
  arbitrary CPU during classification.

---

## Accepted limitations (open, not fixed, and here's why)

- **No independent professional security audit.** This is the single most
  important gap. Software whose job is to protect other software, but
  which hasn't itself been audited, is a plausible new attack surface
  (a WAF bypass, or a bug in the WAF that's worse than having no WAF at
  all). Nothing above substitutes for a qualified third party actually
  trying to break it.
- **No sustained battle-testing against real, adversarial internet
  traffic.** Every test in this repository (including the ones described
  as "verified end-to-end") was run manually, against a small number of
  deliberately crafted requests, over a short period. That is meaningfully
  different from months of real traffic, including the false positives
  and creative evasion attempts real usage surfaces that a short test
  session cannot.
- **ML evasion is a fundamental property of trained classifiers, not
  something this project claims to have solved.** The anomaly-detection
  heuristic (`src/anomaly_detection.py`) adds an independent, non-learned
  signal that catches some classes of evasion (extreme encoding density,
  absurd length), but a sufficiently careful attacker who stays within
  "normal-looking" statistics can still potentially evade both it and the
  trained models. This is inherent to the approach, not a bug to be
  patched.
- **HTTP/2/3 and WebSocket support are deliberately incomplete**, not
  because they're impossible to add, but because doing so correctly is a
  substantial amount of additional work with its own attack surface;
  deferring HTTP/2/3 to Caddy and rejecting WebSocket by default are the
  honest trade-offs given the scope of this project.

---

## Recommended posture

Use this as one security layer in a defense-in-depth stack: keep your
backend's own input validation, parameterized queries, and output
encoding regardless of whether this WAF is in front of it. For anything
genuinely internet-facing and holding sensitive data, pair this with (or
defer to) a professionally audited commercial WAF, and treat this project
as a complementary layer, a research/learning artifact, or a component of
a lab/staging/portfolio deployment — not as the sole thing standing
between the internet and production data.
