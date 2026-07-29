"""
recon_detection.py
-------------------
Detects the reconnaissance/scanning phase of an attack -- BEFORE a
malicious payload even shows up in a query string or body. This closes a
real gap in a payload-only WAF: automated pentest frameworks (e.g.
HexStrike AI, which orchestrates sqlmap, nikto, nuclei, gobuster/ffuf/
dirsearch/feroxbuster, wpscan, dalfox/xsstrike, wafw00f) generate a lot of
traffic that is not itself a SQLi/XSS string, but is still clearly hostile:

  1. Known scanner/tool signatures in the User-Agent header. Most
     pentesting tools identify themselves by default unless the operator
     deliberately spoofs a browser UA (sqlmap, nikto, nuclei, wpscan,
     dalfox, xsstrike, wafw00f, whatweb, hydra, and HexStrike's own two
     hardcoded UAs "HexStrike-HTTP-Framework/1.0 ..." and "Mozilla/5.0
     (Compatible Exploit)" all match here).

  2. Requests to well-known SENSITIVE PATHS that a real user or a
     legitimate application almost never requests, but that every
     directory-brute-force tool (gobuster/dirb/ffuf/dirsearch/
     feroxbuster) and vulnerability scanner (nikto/nuclei) always probes:
     .git/config, .env, wp-config.php.bak, id_rsa, .htpasswd, etc.

  3. Forwarded-IP header spoofing attempts. Some frameworks (again,
     HexStrike is a documented example) deliberately send
     X-Forwarded-For / X-Real-IP / X-Originating-IP set to 127.0.0.1 or
     similar, hoping a naive app/WAF trusts the header and treats the
     request as coming from localhost (bypassing IP allowlists, admin
     checks, or rate limits). A request carrying these headers from a
     source that ISN'T one of our configured trusted_proxies is itself a
     red flag, independent of whatever else the request contains.

None of this replaces the TF-IDF/ML payload classification -- it runs
BEFORE it, as a cheap, high-confidence pre-filter for "this traffic is
from a scanner/pentest tool," which is a different (and often earlier)
signal than "this specific request contains a SQLi/XSS string."
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class ReconVerdict:
    flagged: bool
    reasons: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# 1. Known scanner / pentest-tool User-Agent signatures
# --------------------------------------------------------------------------
# Deliberately matches literal, documented default UA strings from public
# tools rather than anything guessed -- keeps false positives low (a real
# browser UA never matches these).
_SCANNER_UA_PATTERNS = [
    r"sqlmap",
    r"Nikto",
    r"Nuclei",
    r"wpscan",
    r"dalfox",
    r"XSStrike",
    r"wafw00f",
    r"WhatWeb",
    r"Hydra",
    r"dirsearch",
    r"gobuster",
    r"feroxbuster",
    r"ffuf",
    r"HexStrike-HTTP-Framework",     # HexStrike's own hardcoded custom UA
    r"Compatible Exploit",           # HexStrike's other hardcoded "Mozilla/5.0 (Compatible Exploit)"
    r"masscan",
    r"Nessus",
    r"OpenVAS",
    r"acunetix",
    r"Qualys",
    r"^python-requests",             # default python-requests UA -- flagged but scored low, see NOTE below
    r"^curl/",                       # default curl UA -- flagged but scored low, see NOTE below
]
_SCANNER_UA_RE = re.compile("|".join(_SCANNER_UA_PATTERNS), re.IGNORECASE)

# NOTE on curl/python-requests: these are also used by countless legitimate
# API clients, health checks, and internal services -- matching them alone
# is NOT treated as an automatic block (see LOW_CONFIDENCE_UA_PATTERNS
# below); they only nudge the recon score up rather than triggering a hard
# block by themselves, unlike the tool-specific signatures above.
_LOW_CONFIDENCE_UA_PATTERNS = [r"^python-requests", r"^curl/"]
_LOW_CONFIDENCE_UA_RE = re.compile("|".join(_LOW_CONFIDENCE_UA_PATTERNS), re.IGNORECASE)


# --------------------------------------------------------------------------
# 2. Sensitive paths every recon/brute-force tool probes
# --------------------------------------------------------------------------
_SENSITIVE_PATH_PATTERNS = [
    r"/\.git(/|$)",
    r"/\.env(\.|$)",
    r"/\.svn(/|$)",
    r"/\.hg(/|$)",
    r"wp-config\.php",
    r"/\.htpasswd",
    r"/\.htaccess",
    r"id_rsa",
    r"/\.aws/credentials",
    r"/\.ssh/",
    r"/phpinfo\.php",
    r"/config\.php\.(bak|swp|old|orig)",
    r"/backup\.(zip|sql|tar\.gz|tar)",
    r"/\.DS_Store",
    r"/server-status",
    r"/\.well-known/(?!security\.txt)",  # .well-known is legit (ACME etc.); exclude the one real subpath
    r"/xmlrpc\.php",
    r"/\.idea/",
    r"/\.vscode/",
]
_SENSITIVE_PATH_RE = re.compile("|".join(_SENSITIVE_PATH_PATTERNS), re.IGNORECASE)


# --------------------------------------------------------------------------
# 3. Spoofed forwarded-IP headers
# --------------------------------------------------------------------------
_FORWARDING_HEADERS = ("X-Forwarded-For", "X-Real-IP", "X-Originating-IP", "X-Client-IP")


def classify_recon(
    path: str,
    headers,                      # anything dict-like / aiohttp CIMultiDict
    direct_ip: str,
    trusted_proxies: list[str],
) -> ReconVerdict:
    """
    Cheap, pre-payload-classification check. Call this BEFORE running the
    TF-IDF/ML ensemble -- if it flags the request, you can skip the more
    expensive classification entirely (same principle as checking the
    rate-limiter ban list first).
    """
    reasons: list[str] = []

    user_agent = headers.get("User-Agent", "")
    if _SCANNER_UA_RE.search(user_agent):
        if _LOW_CONFIDENCE_UA_RE.match(user_agent) and not re.search(
            "|".join(p for p in _SCANNER_UA_PATTERNS if p not in _LOW_CONFIDENCE_UA_PATTERNS),
            user_agent, re.IGNORECASE,
        ):
            reasons.append(f"low_confidence_ua:{user_agent[:40]}")
        else:
            reasons.append(f"scanner_user_agent:{user_agent[:60]}")

    if _SENSITIVE_PATH_RE.search(path):
        reasons.append(f"sensitive_path:{path[:80]}")

    if direct_ip not in trusted_proxies:
        for header_name in _FORWARDING_HEADERS:
            if header_name in headers:
                reasons.append(f"spoofed_forwarding_header:{header_name}={headers[header_name][:40]}")

    # Only the high-confidence reasons trigger a hard block; a lone
    # low-confidence UA match by itself does not (too many legitimate
    # curl/python-requests clients exist to block on that alone).
    high_confidence = [r for r in reasons if not r.startswith("low_confidence_ua:")]
    return ReconVerdict(flagged=bool(high_confidence), reasons=reasons)


if __name__ == "__main__":
    cases = [
        ("normal browser", "/search?q=laptop", {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}, "203.0.113.5", []),
        ("sqlmap default UA", "/search?q=1", {"User-Agent": "sqlmap/1.7.2#stable (http://sqlmap.org)"}, "203.0.113.5", []),
        ("HexStrike custom UA", "/login", {"User-Agent": "HexStrike-HTTP-Framework/1.0 (Advanced Security Testing)"}, "203.0.113.5", []),
        (".git probe", "/.git/config", {"User-Agent": "Mozilla/5.0"}, "203.0.113.5", []),
        ("spoofed XFF, untrusted source", "/admin", {"User-Agent": "Mozilla/5.0", "X-Forwarded-For": "127.0.0.1"}, "203.0.113.5", []),
        ("spoofed XFF, but source IS trusted proxy", "/admin", {"User-Agent": "Mozilla/5.0", "X-Forwarded-For": "198.51.100.9"}, "127.0.0.1", ["127.0.0.1"]),
        ("bare curl (low confidence only)", "/api/status", {"User-Agent": "curl/8.4.0"}, "203.0.113.5", []),
    ]
    for name, path, headers, ip, trusted in cases:
        verdict = classify_recon(path, headers, ip, trusted)
        print(f"{name:38} flagged={verdict.flagged!s:5} reasons={verdict.reasons}")
