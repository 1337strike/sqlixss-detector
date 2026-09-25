"""
baseline_normalized.py
-----------------------
A stronger signature baseline that applies canonicalization BEFORE
regex matching, addressing a methodological gap noted in peer review:
real production WAFs such as ModSecurity with the OWASP Core Rule Set
run a transformation chain (urlDecodeUni, lowercase, removeComments,
compressWhitespace, ...) before any rule is evaluated.

Comparing a TF-IDF classifier against a naive regex engine that does
NOT canonicalize understates the signature baseline's capability and
therefore overstates the ML advantage. This module provides the fair
comparison: same rule set, same canonical form.

The canonicalization pipeline implemented here mirrors the commonly
used subset of that transformation chain:
  1. Repeated percent-decoding (handles double/triple URL encoding)
  2. HTML entity and \\uXXXX unescaping
  3. SQL comment removal   (/* ... */ and -- inline)
  4. Whitespace compression
  5. Case folding (lowercase)

This is a reimplementation of the rule *logic pattern*, not of
ModSecurity or the OWASP CRS themselves. Any paper using it should
describe it as "a normalizing signature baseline" and not claim
equivalence to a full production rule set.

Usage:
    from src.baseline_normalized import NormalizedSignatureBaseline
    nb = NormalizedSignatureBaseline()
    nb.predict(["' OR 1=1 --", "%27%20OR%201%3D1%20--"])
    # → ['sqli', 'sqli']   (naive baseline misses the encoded form)
"""

from __future__ import annotations

import html
import re
import urllib.parse

from src.baseline_signature import _SQLI_PATTERNS, _XSS_PATTERNS

# SQL inline comments used to split keywords  (e.g. UN/**/ION)
_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
# JavaScript \uXXXX escape sequences
_UNICODE_ESC_RE = re.compile(r"\\u([0-9a-fA-F]{4})")


def canonicalize(payload: str, max_decode_rounds: int = 3) -> str:
    """Apply a ModSecurity-style transformation chain to a payload string.

    Parameters
    ----------
    payload:
        Raw input string exactly as received from the HTTP layer.
    max_decode_rounds:
        Upper bound on repeated percent-decoding.  Attackers use double-
        or triple-encoding specifically to survive a single decode pass;
        iterating until a fixed point (bounded to avoid pathological
        input) neutralises that technique.

    Returns
    -------
    str
        Canonicalized form suitable for signature matching.
    """
    text = payload

    # 1. Repeated percent-decoding.
    for _ in range(max_decode_rounds):
        decoded = urllib.parse.unquote_plus(text)
        if decoded == text:
            break
        text = decoded

    # 2. HTML entities (&lt; &#60; &#x3c;) and JS escapes (\u003c).
    text = html.unescape(text)
    text = _UNICODE_ESC_RE.sub(lambda m: chr(int(m.group(1), 16)), text)

    # 3. Inline SQL comments that split keywords  (UNI/**/ON → UNION).
    text = _COMMENT_RE.sub("", text)

    # 4. Whitespace compression (tabs / newlines used as space proxies).
    text = re.sub(r"\s+", " ", text)

    # 5. Case folding.
    return text.strip().lower()


class NormalizedSignatureBaseline:
    """Signature baseline with pre-match canonicalization.

    Identical rule set to SignatureBaseline, but each payload is
    canonicalized before any rule is applied.  This is the fair
    comparison against TF-IDF classifiers that also see the raw string.

    The class intentionally exposes the same ``fit`` / ``predict``
    interface as the scikit-learn pipelines so it can be used
    interchangeably with the ML models.
    """

    def __init__(self, extra_sqli_patterns: list[str] = ()) -> None:
        self._sqli_re = [re.compile(p, re.IGNORECASE)
                         for p in [*_SQLI_PATTERNS, *extra_sqli_patterns]]
        self._xss_re  = [re.compile(p, re.IGNORECASE) for p in _XSS_PATTERNS]

    def _classify_one(self, payload: str) -> str:
        norm = canonicalize(payload)
        if any(p.search(norm) for p in self._sqli_re):
            return "sqli"
        if any(p.search(norm) for p in self._xss_re):
            return "xss"
        return "benign"

    def predict(self, payloads: list[str]) -> list[str]:
        return [self._classify_one(p) for p in payloads]

    def fit(self, *_args, **_kwargs):   # no-op — rules are not learned
        return self


# ---------------------------------------------------------------------------
# Quick self-test — run:  python -m src.baseline_normalized
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    from src.baseline_signature import SignatureBaseline

    naive      = SignatureBaseline()
    normalized = NormalizedSignatureBaseline()

    cases = [
        ("clean SQLi",          "' OR 1=1 --"),
        ("URL-encoded",         "%27%20OR%201%3D1%20--"),
        ("double-encoded",      "%2527%2520OR%25201%253D1%2520--"),
        ("comment-split",       "UNI/**/ON SEL/**/ECT password FROM users"),
        ("HTML-entity XSS",     "&lt;script&gt;alert(1)&lt;/script&gt;"),
        ("\\u-escaped XSS",     "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"),
        ("whitespace variant",  "'\tOR\n1\t=\t1\t--"),
        ("benign",              "id=5&sort=asc&q=laptop"),
    ]

    print(f"{'case':26} {'naive':>10} {'normalized':>12}  note")
    print("-" * 64)
    for name, payload in cases:
        n = naive.predict([payload])[0]
        r = normalized.predict([payload])[0]
        note = "← fixed" if n == "benign" and r != "benign" else ""
        print(f"{name:26} {n:>10} {r:>12}  {note}")
