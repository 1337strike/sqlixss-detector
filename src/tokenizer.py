"""
tokenizer.py
------------
Custom tokenizer for HTTP payload text (Chapter 3, Section 3.5).

Standard NLP tokenizers throw away punctuation like ' = < > / ; -- because
they're "not words". For SQLi/XSS detection that's exactly the wrong move:
those characters ARE the attack signal (' OR 1=1, <script>, /*comment*/).

This tokenizer keeps:
  - words/identifiers (SELECT, UNION, script, alert, ...)
  - SQL/JS special characters as their own tokens (' = < > ( ) ; / -- )
  - HTML-ish tags as whole tokens (<script>, </script>, <img)
  - percent-encoded bytes as their own tokens (%27, %3C, ...) so that
    encoded and non-encoded variants still show up as distinguishable
    statistical features instead of being silently merged or dropped.

It is deliberately simple (regex-based) and dependency-free so it can be
pickled inside a scikit-learn Pipeline without any import surprises.
"""

import re

# Order matters: longer / more specific patterns must come first so that
# re.findall's alternation doesn't greedily split them into smaller pieces.
_TOKEN_PATTERN = re.compile(
    r"""
    %[0-9A-Fa-f]{2}          # percent-encoded byte, e.g. %27, %3C
    | </?[a-zA-Z][\w-]*      # opening/closing HTML-ish tag start, e.g. <script, </script
    | -{2,}                  # SQL inline comment start --
    | /\*!?\d*               # SQL versioned/inline comment open /* or /*!50000
    | \*/                    # SQL comment close
    | \b[a-zA-Z_][a-zA-Z0-9_]*\b   # ordinary word / identifier / keyword
    | \d+                    # standalone numeric literal, e.g. the "1" in 1=1
    | [='"<>();]             # single meaningful special characters
    """,
    re.VERBOSE,
)


def tokenize(payload: str) -> list[str]:
    """
    Tokenize a raw HTTP payload string (already URL-decoded upstream if you
    want decoded tokens, or left encoded if you want the raw wire form).

    Lowercasing is intentionally NOT applied here for keywords like SELECT
    vs select, because case-toggling is one of the obfuscation techniques
    we specifically want the model to learn to see through statistically.
    We DO lowercase only the alphabetic *word* tokens to reduce sparsity,
    while leaving special-character tokens untouched.
    """
    if not isinstance(payload, str):
        payload = str(payload)

    raw_tokens = _TOKEN_PATTERN.findall(payload)

    tokens = []
    for tok in raw_tokens:
        if re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", tok):
            tokens.append(tok.lower())
        else:
            tokens.append(tok)
    return tokens


if __name__ == "__main__":
    samples = [
        "id=5&sort=asc",
        "' OR 1=1 --",
        "UNI/*!50000ON*/ SELECT username,password FROM users",
        "<script>alert(document.cookie)</script>",
        "%27%20OR%201%3D1%20--",
        "SeLeCt * FrOm users WHERE id=1",
    ]
    for s in samples:
        print(f"{s!r:55} -> {tokenize(s)}")
