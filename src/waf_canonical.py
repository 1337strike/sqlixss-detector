"""
waf_canonical.py
-----------------
Deployment-only preprocessing layered on top of the paper's canonicalize().

canonicalize() is the research pipeline evaluated in the paper and is left
untouched. Driving the live WAF with sqlmap tamper scripts exposed three
evasions it does not cover:

  * charunicodeencode   -- IIS-style "%u0027" escapes are not percent-
                           decoding, so the payload stayed fully encoded
                           (0% detection).
  * versionedkeywords   -- MySQL EXECUTES "/*!UNION*/"; stripping it as a
                           comment deleted the keyword instead of exposing it.
  * space2comment       -- "1/**/and/**/1=1": deleting the comment glues
                           tokens ("1and1=1"); ModSecurity's
                           replaceComments uses a space instead.

waf_views() returns the canonical form(s) to inspect. The live proxy blocks
if ANY view is malicious; a second view is only produced when the input
contains a comment, so ordinary requests are classified once.
"""

from __future__ import annotations

import html
import re
import urllib.parse

from src.baseline_normalized import canonicalize

_PERCENT_U = re.compile(r"%u([0-9a-f]{4})", re.IGNORECASE)
_VERSIONED_OPEN = re.compile(r"/\*!\d*")
_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)


def _unwrap_versioned(text: str) -> str:
    """MySQL executes the body of /*!NNNNN ... */, and sqlmap nests them
    ("/*!/*!0AND*/"). Replace each versioned opener with a space, then drop
    the closers they leave behind, keeping closers of ordinary comments."""
    out, depth, i = [], 0, 0
    while i < len(text):
        m = _VERSIONED_OPEN.match(text, i)
        if m:
            depth += 1
            out.append(" ")
            i = m.end()
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            end = len(text) if end < 0 else end + 2
            out.append(text[i:end])      # ordinary comment, kept whole
            i = end
        elif depth and text.startswith("*/", i):
            depth -= 1
            out.append(" ")
            i += 2
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def _expand(text: str) -> str:
    """Decode %uXXXX and unwrap MySQL versioned comments to their content."""
    text = _PERCENT_U.sub(lambda m: chr(int(m.group(1), 16)), text)
    return _unwrap_versioned(text) if "/*!" in text else text


def _decode(text: str, rounds: int = 3) -> str:
    """Percent/entity decoding only (no comment removal), bounded like
    canonicalize(), with %u and versioned comments expanded each round."""
    for _ in range(rounds):
        decoded = _expand(html.unescape(urllib.parse.unquote_plus(text)))
        if decoded == text:
            break
        text = decoded
    return _expand(text)


def waf_views(text: str) -> list[str]:
    """Canonical view(s) of one inspected string for the live WAF."""
    decoded = _decode(text)
    views = [canonicalize(decoded)]                 # comments removed (paper behavior)
    if _COMMENT.search(decoded):
        spaced = canonicalize(_COMMENT.sub(" ", decoded))   # comments as spaces
        if spaced != views[0]:
            views.append(spaced)
    return views
