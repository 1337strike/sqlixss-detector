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

# Extra rules for the live WAF only. Kept out of _SQLI_PATTERNS so the
# research baseline (and every paper number derived from it) is unchanged.
WAF_EXTRA_SQLI_PATTERNS = [
    # tautology with identical operands, quoted or not: ' OR '1'='1 / or a=a
    r"\bor\b\s+['\"]?(\w+)['\"]?\s*=\s*['\"]?\1\b",
    # MSSQL command execution, any qualifier: exec master..xp_cmdshell
    r"\bxp_cmdshell\b",
    # server fingerprinting via system variables: select @@version
    r"@@(version|servername|hostname|datadir|basedir|spid|language)\b",
    # string break followed by a comment opener: admin'/*  admin"/*
    r"['\"]\s*/\*",
    # boolean probe on numeric operands: 1 AND 2726=5917 / 1 OR 3=3
    r"\b(and|or)\s+\d+\s*=\s*\d+\b",
    # blind-inference probes: IIF(1=1,1,1/0)  (CASE WHEN 1=1 THEN 1 ELSE NULL END)
    r"\biif\s*\(",
    r"\(\s*case\s+when\b",
]

WAF_EXTRA_XSS_PATTERNS = [
    # any tag carrying an event handler: <x onfoo=1>, <details open ontoggle=...>
    r"<\s*[a-z][\w:-]*\b[^>]*?\bon[a-z]+\s*=",
    # dialog call without parentheses: alert`1`
    r"\b(alert|prompt|confirm)\s*`",
    # UTF-7 encoded "<" (legacy charset-sniffing bypass): +ADw-
    r"\+ADw-",
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

    def __init__(self, extra_sqli_patterns: list[str] = (), extra_xss_patterns: list[str] = ()):
        self._sqli_re = [re.compile(p, re.IGNORECASE)
                         for p in [*_SQLI_PATTERNS, *extra_sqli_patterns]]
        self._xss_re = [re.compile(p, re.IGNORECASE)
                        for p in [*_XSS_PATTERNS, *extra_xss_patterns]]

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
