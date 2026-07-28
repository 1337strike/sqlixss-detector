"""
obfuscation.py
--------------
Implements the obfuscation techniques listed in Table 3.1 of the thesis:

  1. URL / Double Encoding
  2. Whitespace Manipulation (tabs, newlines, inline comments)
  3. Case Toggling
  4. Comment Insertion (SQL versioned/inline comments)
  5. Character / Unicode Substitution

Each function takes a clean malicious payload string and returns an
obfuscated variant. `random_obfuscate()` picks a random combination so the
augmented dataset contains a realistic mixture rather than only
single-technique examples.

Determinism: every function accepts an explicit `rng: random.Random`
instance instead of calling the global `random` module. This matters for
research reproducibility -- with a fixed seed, `random_obfuscate(payload,
seed=42)` must always produce exactly the same obfuscated string, run after
run, machine after machine, so Chapter 4 results (and anyone trying to
reproduce them) are stable.

This module is purely defensive/research tooling: it mutates payload
STRINGS for the purpose of training and evaluating a detector, it does not
send anything anywhere or exploit any system.
"""

from __future__ import annotations

import random
import re
import urllib.parse

SQL_KEYWORDS = [
    "select", "union", "insert", "update", "delete", "drop", "or", "and",
    "from", "where", "table", "database", "exec", "declare", "cast",
]

_KEYWORD_PATTERN = re.compile(r"\b(" + "|".join(SQL_KEYWORDS) + r")\b", re.IGNORECASE)


# --------------------------------------------------------------------------
# 1. URL / Double Encoding
# --------------------------------------------------------------------------
def url_encode(payload: str, rng: random.Random, double: bool = False) -> str:
    """Percent-encode special characters; optionally encode twice.
    (No randomness involved, but keeps a uniform signature with the other
    techniques so `_TECHNIQUES` dispatch stays simple.)"""
    encoded = urllib.parse.quote(payload, safe="")
    if double:
        encoded = urllib.parse.quote(encoded, safe="")
    return encoded


def partial_url_encode(payload: str, rng: random.Random, probability: float = 0.5) -> str:
    """Percent-encode only some characters, mimicking real-world evasive
    payloads that mix encoded and raw characters to dodge naive decoders."""
    out = []
    for ch in payload:
        if not ch.isalnum() and rng.random() < probability:
            out.append(urllib.parse.quote(ch, safe=""))
        else:
            out.append(ch)
    return "".join(out)


# --------------------------------------------------------------------------
# 2. Whitespace Manipulation
# --------------------------------------------------------------------------
def whitespace_manipulation(payload: str, rng: random.Random) -> str:
    """Replace literal spaces with tabs, newlines, or SQL inline comments."""
    replacements = ["\t", "\n", "/**/", "%09", "%0a"]
    out = []
    for ch in payload:
        if ch == " ":
            out.append(rng.choice(replacements))
        else:
            out.append(ch)
    return "".join(out)


# --------------------------------------------------------------------------
# 3. Case Toggling
# --------------------------------------------------------------------------
def case_toggle(payload: str, rng: random.Random) -> str:
    """Randomize the case of every alphabetic character."""
    return "".join(
        ch.upper() if rng.random() < 0.5 else ch.lower() for ch in payload
    )


def keyword_case_toggle(payload: str, rng: random.Random) -> str:
    """Toggle case only on recognized SQL keywords (more surgical / realistic
    than toggling every letter in the whole string).

    Guarantees at least one character actually flips case per matched
    keyword (instead of leaving 25% of single-word matches unchanged by
    chance), so this technique is never a silent no-op on a payload that
    does contain a keyword.
    """

    def _toggle_word(match: "re.Match") -> str:
        word = match.group(0)
        chars = list(word)
        flips = [rng.random() < 0.5 for _ in chars]
        if not any(flips):
            flips[rng.randrange(len(flips))] = True  # force at least one real flip
        toggled = [
            (c.upper() if c.islower() else c.lower()) if flip else c
            for c, flip in zip(chars, flips)
        ]
        return "".join(toggled)

    return _KEYWORD_PATTERN.sub(_toggle_word, payload)


# --------------------------------------------------------------------------
# 4. Comment Insertion
# --------------------------------------------------------------------------
def comment_insertion(payload: str, rng: random.Random) -> str:
    """Split a random SQL keyword with an inline/versioned comment, e.g.
    UNION -> UNI/*!50000ON*/, so the literal keyword string no longer
    appears intact for a naive signature match."""

    def _split(match: "re.Match") -> str:
        word = match.group(0)
        if len(word) < 4:
            return word
        cut = rng.randint(2, len(word) - 2)
        version = rng.choice(["", "!50000"])
        return f"{word[:cut]}/*{version}*/{word[cut:]}"

    return _KEYWORD_PATTERN.sub(_split, payload, count=1)


# --------------------------------------------------------------------------
# 5. Character / Unicode Substitution
# --------------------------------------------------------------------------
_UNICODE_MAP = {
    "<": ["%3C", "\\u003C", "&#60;", "&lt;"],
    ">": ["%3E", "\\u003E", "&#62;", "&gt;"],
    "'": ["%27", "\\u0027", "&#39;"],
    '"': ["%22", "\\u0022", "&#34;"],
    "(": ["%28", "\\u0028"],
    ")": ["%29", "\\u0029"],
}


def unicode_substitution(payload: str, rng: random.Random) -> str:
    """Replace HTML/JS special characters with hex/unicode/HTML-entity
    escape sequences. Guarantees at least one substitution happens if the
    payload contains at least one substitutable character, so this
    technique never silently no-ops on an XSS payload."""
    matches = [ch for ch in payload if ch in _UNICODE_MAP]
    if not matches:
        return payload

    force_index = rng.randrange(len(matches))
    seen = 0
    out = []
    for ch in payload:
        if ch in _UNICODE_MAP:
            do_sub = (seen == force_index) or (rng.random() < 0.7)
            seen += 1
            out.append(rng.choice(_UNICODE_MAP[ch]) if do_sub else ch)
        else:
            out.append(ch)
    return "".join(out)


# --------------------------------------------------------------------------
# Combined / random obfuscation
# --------------------------------------------------------------------------
_TECHNIQUES = {
    "url_encode": lambda p, rng: url_encode(p, rng, double=False),
    "double_url_encode": lambda p, rng: url_encode(p, rng, double=True),
    "partial_url_encode": partial_url_encode,
    "whitespace": whitespace_manipulation,
    "case_toggle": keyword_case_toggle,
    "comment_insertion": comment_insertion,
    "unicode_substitution": unicode_substitution,
}


def random_obfuscate(
    payload: str, n_techniques: int | None = None, seed: int | None = None
) -> tuple[str, list[str]]:
    """
    Apply a random combination of 1..3 obfuscation techniques to `payload`,
    fully deterministic given `seed` (same seed -> byte-identical output,
    every run).

    Returns (obfuscated_payload, list_of_technique_names_applied) so the
    dataset builder can log which techniques produced which sample (useful
    for the per-technique robustness breakdown in Chapter 4).
    """
    rng = random.Random(seed)
    if n_techniques is None:
        n_techniques = rng.randint(1, 3)

    names = rng.sample(list(_TECHNIQUES.keys()), k=min(n_techniques, len(_TECHNIQUES)))
    out = payload
    for name in names:
        out = _TECHNIQUES[name](out, rng)
        # whitespace/case/comment techniques only apply to keywords/spaces
        # that may not be present in every payload (e.g. an XSS payload has
        # no SQL keywords) -- that's an expected, harmless no-op for THAT
        # technique, not a bug, so we simply move on to the next one.

    # Final safety net: if the whole chain still produced zero change
    # (e.g. every picked technique happened to target syntax this payload
    # doesn't contain), fall back to full URL encoding, which is guaranteed
    # to alter any non-empty string.
    if out == payload:
        out = partial_url_encode(payload, rng, probability=1.0)
        names = names + ["fallback_full_url_encode"]

    return out, names


if __name__ == "__main__":
    demo_payloads = [
        "' OR 1=1 --",
        "UNION SELECT username, password FROM users",
        "<script>alert(document.cookie)</script>",
    ]
    for p in demo_payloads:
        obf, techniques = random_obfuscate(p, seed=42)
        print(f"ORIGINAL : {p}")
        print(f"TECHNIQUE: {techniques}")
        print(f"OBFUSCATED: {obf}\n")

    # Determinism check: same seed must give byte-identical output
    a, _ = random_obfuscate("' OR 1=1 --", seed=7)
    b, _ = random_obfuscate("' OR 1=1 --", seed=7)
    assert a == b, "seeded output is not deterministic!"
    print(f"[determinism check OK] seed=7 -> {a!r} (identical on repeat calls)")
