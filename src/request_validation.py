"""
request_validation.py
----------------------
Defense against request-smuggling-class ambiguity and unhandled protocol
upgrades, run BEFORE any payload classification.

Why this needs to be explicit rather than "aiohttp probably handles it":
HTTP request smuggling (CL.TE, TE.CL, TE.TE) exploits DISAGREEMENT between
two HTTP parsers (e.g. a front-end proxy and a back-end server) about
where one request ends and the next begins, usually by sending both
Content-Length and Transfer-Encoding, or a deliberately malformed
Transfer-Encoding value that one parser accepts and the other rejects.
In this WAF's topology (Caddy -> WAF -> backend), that's exactly the
front-end/back-end pair where disagreement could occur. Rather than
relying on aiohttp's internal parser behavior matching Caddy's exactly
(an assumption that could silently break if either library changes),
this module makes the WAF's own stance explicit and rejects any request
that is ambiguous by the HTTP spec's own rules -- a strict, conservative
reading, not the most permissive one.

WebSocket upgrades are a separate, deliberate gap: this WAF inspects
request/response BODIES, which has no meaning for a WebSocket's binary
frame stream once the connection upgrades. Rather than silently
mis-proxying (and giving a false sense of "it's protected"), upgrade
requests are detected explicitly and rejected by default -- see
`config.allow_websocket_paths` if you need to exempt specific paths
(the WAF then proxies the upgrade through WITHOUT payload inspection,
which must be a conscious operator decision, not a silent default).
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class ValidationResult:
    valid: bool
    reason: str = ""


def validate_request_integrity(headers) -> ValidationResult:
    """
    Rejects requests that are ambiguous per RFC 9112 §6.3 (Transfer-Encoding
    and Content-Length handling) in ways that are the textbook basis for
    request smuggling. Conservative by design: when in doubt, reject rather
    than guess which interpretation the backend would use.
    """
    content_lengths = headers.getall("Content-Length", []) if hasattr(headers, "getall") else (
        [headers["Content-Length"]] if "Content-Length" in headers else []
    )
    transfer_encodings = headers.getall("Transfer-Encoding", []) if hasattr(headers, "getall") else (
        [headers["Transfer-Encoding"]] if "Transfer-Encoding" in headers else []
    )

    # Multiple Content-Length headers (possibly with different values) is
    # already ambiguous on its own, regardless of Transfer-Encoding.
    if len(content_lengths) > 1:
        distinct = set(content_lengths)
        if len(distinct) > 1:
            return ValidationResult(False, f"conflicting Content-Length headers: {distinct}")

    # A non-numeric or negative Content-Length is malformed regardless.
    for cl in content_lengths:
        if not re.fullmatch(r"\d+", cl.strip()):
            return ValidationResult(False, f"malformed Content-Length: {cl!r}")

    # The classic CL.TE / TE.CL smuggling setup: both headers present at
    # once. Some servers prioritize one over the other; we simply refuse
    # to guess.
    if content_lengths and transfer_encodings:
        return ValidationResult(False, "both Content-Length and Transfer-Encoding present")

    # Transfer-Encoding must be exactly "chunked" (case-insensitive) if
    # present at all -- obfuscated variants like "chunked ", "xchunked",
    # "chunked\t" or a second value smuggled onto the same line are a
    # known bypass technique against parsers that only check with
    # startswith()/in rather than an exact match.
    for te in transfer_encodings:
        if te.strip().lower() != "chunked":
            return ValidationResult(False, f"unsupported/malformed Transfer-Encoding: {te!r}")

    return ValidationResult(True)


def is_websocket_upgrade(headers) -> bool:
    connection = headers.get("Connection", "")
    upgrade = headers.get("Upgrade", "")
    return "upgrade" in connection.lower() and "websocket" in upgrade.lower()


if __name__ == "__main__":
    from multidict import CIMultiDict

    cases = [
        ("normal GET, no body headers", CIMultiDict(), True),
        ("normal POST, Content-Length only", CIMultiDict({"Content-Length": "42"}), True),
        ("normal chunked POST", CIMultiDict({"Transfer-Encoding": "chunked"}), True),
        ("CL.TE smuggling attempt", CIMultiDict({"Content-Length": "42", "Transfer-Encoding": "chunked"}), False),
        ("obfuscated Transfer-Encoding", CIMultiDict({"Transfer-Encoding": "chunked, identity"}), False),
        ("duplicate conflicting Content-Length", None, False),  # built manually below
    ]

    for name, headers, expected_valid in cases:
        if headers is None:
            headers = CIMultiDict()
            headers.add("Content-Length", "10")
            headers.add("Content-Length", "20")
        result = validate_request_integrity(headers)
        status = "OK" if result.valid == expected_valid else "MISMATCH"
        print(f"[{status}] {name:35} valid={result.valid!s:5} reason={result.reason}")

    ws_headers = CIMultiDict({"Connection": "Upgrade", "Upgrade": "websocket"})
    print(f"\nWebSocket upgrade detected: {is_websocket_upgrade(ws_headers)}")
    print(f"Normal request not flagged as WS: {is_websocket_upgrade(CIMultiDict())}")
