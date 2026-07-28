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

This module is purely defensive/research tooling: it mutates payload
STRINGS for the purpose of training and evaluating a detector, it does not
send anything anywhere or exploit any system.
"""

import random
import string
import urllib.parse

SQL_KEYWORDS = [
    "select", "union", "insert", "update", "delete", "drop", "or", "and",
    "from", "where", "table", "database", "exec", "declare", "cast",
]

# --------------------------------------------------------------------------
# 1. URL / Double Encoding
# --------------------------------------------------------------------------
def url_encode(payload: str, double: bool = False) -> str:
    """Percent-encode special characters; optionally encode twice."""
    encoded = urllib.parse.quote(payload, safe="")
    if double:
        encoded = urllib.parse.quote(encoded, safe="")
    return encoded


def partial_url_encode(payload: str, probability: float = 0.5) -> str:
    """Percent-encode only some characters, mimicking real-world evasive
    payloads that mix encoded and raw characters to dodge naive decoders."""
    out = []
    for ch in payload:
        if not ch.isalnum() and random.random() < probability:
            out.append(urllib.parse.quote(ch, safe=""))
        else:
            out.append(ch)
    return "".join(out)


# --------------------------------------------------------------------------
# 2. Whitespace Manipulation
# --------------------------------------------------------------------------
def whitespace_manipulation(payload: str) -> str:
    """Replace literal spaces with tabs, newlines, or SQL inline comments."""
    replacements = ["\t", "\n", "/**/", "%09", "%0a"]
    out = []
    for ch in payload:
        if ch == " ":
            out.append(random.choice(replacements))
        else:
            out.append(ch)
    return "".join(out)


# --------------------------------------------------------------------------
# 3. Case Toggling
# --------------------------------------------------------------------------
def case_toggle(payload: str) -> str:
    """Randomize the case of every alphabetic character."""
    return "".join(
        ch.upper() if random.random() < 0.5 else ch.lower() for ch in payload
    )


def keyword_case_toggle(payload: str) -> str:
    """Toggle case only on recognized SQL keywords (more surgical / realistic
    than toggling every letter in the whole string)."""

    def _toggle_word(match: "re.Match") -> str:
        word = match.group(0)
        return "".join(
            c.upper() if random.random() < 0.5 else c.lower() for c in word
        )

    import re

    pattern = re.compile(
        r"\b(" + "|".join(SQL_KEYWORDS) + r")\b", flags=re.IGNORECASE
    )
    return pattern.sub(_toggle_word, payload)


# --------------------------------------------------------------------------
# 4. Comment Insertion
# --------------------------------------------------------------------------
def comment_insertion(payload: str) -> str:
    """Split a random SQL keyword with an inline/versioned comment, e.g.
    UNION -> UNI/*!50000ON*/, so the literal keyword string no longer
    appears intact for a naive signature match."""
    import re

    pattern = re.compile(r"\b(" + "|".join(SQL_KEYWORDS) + r")\b", re.IGNORECASE)

    def _split(match: "re.Match") -> str:
        word = match.group(0)
        if len(word) < 4:
            return word
        cut = random.randint(2, len(word) - 2)
        version = random.choice(["", "!50000"])
        return f"{word[:cut]}/*{version}*/{word[cut:]}"

    return pattern.sub(_split, payload, count=1)


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


def unicode_substitution(payload: str) -> str:
    """Replace HTML/JS special characters with hex/unicode/HTML-entity
    escape sequences."""
    out = []
    for ch in payload:
        if ch in _UNICODE_MAP and random.random() < 0.7:
            out.append(random.choice(_UNICODE_MAP[ch]))
        else:
            out.append(ch)
    return "".join(out)


# --------------------------------------------------------------------------
# Combined / random obfuscation
# --------------------------------------------------------------------------
_TECHNIQUES = {
    "url_encode": lambda p: url_encode(p, double=False),
    "double_url_encode": lambda p: url_encode(p, double=True),
    "partial_url_encode": partial_url_encode,
    "whitespace": whitespace_manipulation,
    "case_toggle": keyword_case_toggle,
    "comment_insertion": comment_insertion,
    "unicode_substitution": unicode_substitution,
}


def random_obfuscate(payload: str, n_techniques: int = None, seed: int = None) -> tuple[str, list[str]]:
    """
    Apply a random combination of 1..3 obfuscation techniques to `payload`.

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
        out = _TECHNIQUES[name](out)
    return out, names


if __name__ == "__main__":
    demo_payloads = [
        "' OR 1=1 --",
        "UNION SELECT username, password FROM users",
        "<script>alert(document.cookie)</script>",
    ]
    random.seed(42)
    for p in demo_payloads:
        obf, techniques = random_obfuscate(p)
        print(f"ORIGINAL : {p}")
        print(f"TECHNIQUE: {techniques}")
        print(f"OBFUSCATED: {obf}\n")
