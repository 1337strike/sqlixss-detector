"""
json_extraction.py
-------------------
JSON-aware alternative to raw-text body classification.

The original approach (still used as a fallback) decodes a JSON body and
classifies the raw text directly. That catches the common case (a SQLi/XSS
string sitting inside a JSON field value) but has a real blind spot: JSON's
OWN escaping can reshape how special characters appear in the raw byte
stream. For example, a payload embedded as "\\u0027 OR 1=1--" in the raw
JSON text contains no literal "'" character at all until the JSON is
actually parsed and unescaped -- a raw-text tokenizer never sees the
apostrophe, and a deeply nested or unusually-escaped payload can slip
through purely because of representation, not because the attack itself
is novel.

`extract_json_string_values()` parses the JSON properly and walks the
resulting structure, returning every leaf STRING value (not keys, not
numbers/booleans, not structure) as its actual decoded Python string --
so "\\u0027 OR 1=1--" is returned as "' OR 1=1--", which the existing
tokenizer/classifiers handle exactly like any other payload.

Falls back to raw-text classification if the body isn't valid JSON at all
(some clients send malformed JSON, or lie about Content-Type) -- an
invalid-JSON-but-claims-to-be-JSON body is itself mildly suspicious and is
flagged as such in the return value, though not auto-blocked purely for
being malformed (plenty of buggy legitimate clients send slightly wrong
JSON; this is a signal for the log, not an automatic verdict).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field


@dataclass
class JsonExtractionResult:
    string_values: list[str] = field(default_factory=list)
    was_valid_json: bool = True
    max_depth: int = 0
    truncated: bool = False   # True if limit hit before full traversal


_MAX_STRINGS = 200      # cap how many leaf strings we classify per request
_MAX_DEPTH = 25          # guard against pathological nesting


def _walk(node, depth: int, out: list[str], depth_tracker: list[int],
          truncated: list[bool]) -> None:
    """Walk JSON tree. Sets truncated[0]=True if any limit is hit."""
    if depth > _MAX_DEPTH:
        truncated[0] = True
        return
    if len(out) >= _MAX_STRINGS:
        truncated[0] = True
        return
    depth_tracker[0] = max(depth_tracker[0], depth)

    if isinstance(node, str):
        out.append(node)
    elif isinstance(node, dict):
        for key, value in node.items():
            if isinstance(key, str):
                out.append(key)
            _walk(value, depth + 1, out, depth_tracker, truncated)
            if truncated[0]:
                return   # stop early — already flagged
    elif isinstance(node, list):
        for item in node:
            _walk(item, depth + 1, out, depth_tracker, truncated)
            if truncated[0]:
                return


def extract_json_string_values(body_bytes: bytes) -> JsonExtractionResult:
    """Extract all leaf string values from a JSON body.

    If the body exceeds _MAX_STRINGS or _MAX_DEPTH, sets result.truncated=True.
    The WAF proxy should REJECT (not forward) truncated requests because
    inspection was incomplete — the unexamined portion may contain a payload.
    """
    try:
        text = body_bytes.decode("utf-8")
        parsed = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raw = body_bytes.decode("utf-8", errors="replace")
        return JsonExtractionResult(
            string_values=[raw] if raw else [],
            was_valid_json=False,
            truncated=False,
        )

    out: list[str] = []
    depth_tracker = [0]
    truncated = [False]
    _walk(parsed, 0, out, depth_tracker, truncated)
    return JsonExtractionResult(
        string_values=out,
        was_valid_json=True,
        max_depth=depth_tracker[0],
        truncated=truncated[0],
    )


if __name__ == "__main__":
    cases = [
        (b'{"username": "admin", "password": "hunter2"}', "flat, benign"),
        (b'{"q": "\\u0027 OR 1=1--"}', "unicode-escaped SQLi -- must decode to a literal apostrophe"),
        (b'{"filters": {"nested": {"payload": "<script>alert(1)</script>"}}}', "nested XSS"),
        (b'{"items": ["a", "b", "<script>alert(1)</script>"]}', "SQLi/XSS inside a list"),
        (b"not json at all { broken", "malformed JSON despite Content-Type"),
    ]
    for body, desc in cases:
        result = extract_json_string_values(body)
        print(f"{desc}")
        print(f"  valid_json={result.was_valid_json} depth={result.max_depth} strings={result.string_values}")
