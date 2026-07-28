"""
baseline_signature.py
----------------------
Signature-based detector (Chapter 3, Section 3.6): a regular-expression
ruleset modeled on the publicly documented rule logic of ModSecurity / the
OWASP Core Rule Set, in the spirit of Snort-style misuse detection
(Roesch, 1999). This is the comparative baseline the TF-IDF + ML models are
benchmarked against.

By design this is "dumb" exact/pattern matching -- no statistical
weighting, no learning. It is expected to perform well on clean payloads
and degrade sharply on obfuscated payloads, which is precisely the
contrast this thesis sets out to measure.
"""

from __future__ import annotations

import re

# Deliberately simple, readable rules -- NOT trying to be exhaustive.
# These mirror the well-known rule *families* used in CRS/ModSecurity
# (keyword + syntax matching), not a copy of any specific vendor ruleset.
_SQLI_PATTERNS = [
    r"(\bunion\b.{0,40}\bselect\b)",
    r"(\bor\b\s+1\s*=\s*1)",
    r"('|\")\s*or\s*('|\")?\d+\s*=\s*\d+",
    r"(--|\#)\s*$",
    r"(\bdrop\b\s+\btable\b)",
    r"(\bselect\b.{0,40}\bfrom\b)",
    r"(\bsleep\s*\()",
    r"(\bexec\b\s+\bxp_cmdshell\b)",
    r"(\binformation_schema\b)",
    r"(;\s*--)",
    r"(\bhaving\b\s+\d+\s*=\s*\d+)",
]

_XSS_PATTERNS = [
    r"(<\s*script\b)",
    r"(on\w+\s*=\s*['\"]?\s*alert\s*\()",
    r"(javascript\s*:)",
    r"(<\s*img\b[^>]*\bonerror\b)",
    r"(<\s*svg\b[^>]*\bonload\b)",
    r"(<\s*iframe\b)",
    r"(document\.cookie)",
    r"(<\s*body\b[^>]*\bonload\b)",
]


class SignatureBaseline:
    """Drop-in-compatible with the ML pipelines: exposes .predict(list[str])."""

    def __init__(self):
        self._sqli_re = [re.compile(p, re.IGNORECASE) for p in _SQLI_PATTERNS]
        self._xss_re = [re.compile(p, re.IGNORECASE) for p in _XSS_PATTERNS]

    def _classify_one(self, payload: str) -> str:
        if any(p.search(payload) for p in self._sqli_re):
            return "sqli"
        if any(p.search(payload) for p in self._xss_re):
            return "xss"
        return "benign"

    def predict(self, payloads: list[str]) -> list[str]:
        return [self._classify_one(p) for p in payloads]

    # for API symmetry with the sklearn pipelines used elsewhere
    def fit(self, *_args, **_kwargs) -> "SignatureBaseline":
        return self  # nothing to train -- rules are hand-written, not learned


if __name__ == "__main__":
    baseline = SignatureBaseline()
    samples = [
        "id=5&sort=asc",
        "' OR 1=1 --",
        "<script>alert(1)</script>",
        "%2527%20OR%201%3D1%20--",          # obfuscated SQLi (double-encoded)
        "UNI/*!50000ON*/ SELECT username FROM users",  # obfuscated via comment insertion
    ]
    for s, pred in zip(samples, baseline.predict(samples)):
        print(f"{pred:8} <- {s}")
