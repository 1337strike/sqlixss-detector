"""
scripts/validate_semantics.py
------------------------------
D3 / G4: Semantic payload validation using a local isolated oracle.

For each payload in the corpus, verifies whether the payload is
semantically valid (actually changes query behavior) in its intended
attack context, using a local SQLite database as the oracle for SQLi
and regex pattern matching for XSS.

This addresses the checklist requirement that detection results be
separated into: valid (oracle confirms attack), invalid (payload does
not alter behavior), unchanged (obfuscation produced identical string),
and uncertain (oracle cannot determine).

Run:
    python scripts/validate_semantics.py
    python scripts/validate_semantics.py --label sqli   # SQLi only
    python scripts/validate_semantics.py --label xss    # XSS only
    python scripts/validate_semantics.py --obfuscated   # test obfuscated
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.baseline_normalized import canonicalize
from src.obfuscation import random_obfuscate

PROCESSED = Path(__file__).resolve().parent.parent / "data" / "processed"
RESULTS   = Path(__file__).resolve().parent.parent / "results"
SEED      = 42


def build_oracle_db() -> tuple[sqlite3.Connection, str]:
    """Create an isolated SQLite database that mimics a login form."""
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER, username TEXT, password TEXT, role TEXT)")
    conn.execute("INSERT INTO users VALUES (1,'admin','secret','admin')")
    conn.execute("INSERT INTO users VALUES (2,'alice','pass123','user')")
    conn.execute("INSERT INTO users VALUES (3,'bob','qwerty','user')")
    template = "SELECT * FROM users WHERE username = '{payload}' AND password = 'x'"
    return conn, template


def oracle_sqli(payload: str) -> str:
    """
    Oracle for SQLi: run the payload in a template query and compare
    against the baseline (empty string).

    Returns: 'valid' | 'invalid' | 'error'
    """
    conn, template = build_oracle_db()
    baseline_sql  = template.format(payload="safe_baseline_xyz")
    attack_sql    = template.format(payload=payload.replace("'", "''__LITERAL__"))

    # For oracle purposes, inject directly (we WANT to see the effect)
    attack_sql_raw = template.format(payload=payload)

    try:
        baseline_rows = conn.execute(baseline_sql).fetchall()
    except Exception:
        baseline_rows = []

    try:
        attack_rows = conn.execute(attack_sql_raw).fetchall()
        if len(attack_rows) > len(baseline_rows):
            return "valid"       # payload caused additional rows — SQLi confirmed
        if len(attack_rows) == len(baseline_rows) == 0:
            return "invalid"    # no effect on baseline either
        return "invalid"
    except sqlite3.OperationalError:
        return "error"          # syntax error — malformed payload
    except Exception:
        return "uncertain"


# XSS sink patterns that indicate script execution context
_XSS_PATTERNS = [
    re.compile(r"<script[^>]*>", re.IGNORECASE),
    re.compile(r"on\w+\s*=", re.IGNORECASE),          # event handlers
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"<iframe[^>]*>", re.IGNORECASE),
    re.compile(r"<svg[^>]*onload", re.IGNORECASE),
    re.compile(r"<img[^>]+onerror", re.IGNORECASE),
]


def oracle_xss(payload: str) -> str:
    """
    Oracle for XSS: checks if the payload contains a valid execution
    context (script tag, event handler, JS URI, etc.).

    Note: this is a static oracle, not a browser runtime. It cannot
    confirm actual execution, only structural validity.
    """
    if any(p.search(payload) for p in _XSS_PATTERNS):
        return "valid"
    return "invalid"


def validate_corpus(
    payloads: list[dict],
    obfuscated: bool,
    seed: int,
) -> list[dict]:
    """Validate each payload and return results with oracle outcomes."""
    import random
    rng = random.Random(seed)
    results = []
    for row in payloads:
        label   = row["label"]
        payload = row["payload"]

        if label not in ("sqli", "xss"):
            results.append({**row, "oracle": "n/a", "obf_payload": "",
                            "techniques": "", "unchanged": False})
            continue

        obf_payload = payload
        techniques  = ""
        unchanged   = False

        if obfuscated:
            obf_payload, techs = random_obfuscate(payload, seed=rng.randint(0, 10**6))
            techniques = "+".join(techs)
            unchanged  = (obf_payload == payload)

        # run oracle on canonical form (what the classifier sees)
        canon = canonicalize(obf_payload)
        if label == "sqli":
            oracle = oracle_sqli(canon)
        else:
            oracle = oracle_xss(canon)

        results.append({
            "label":       label,
            "payload":     payload,
            "obf_payload": obf_payload if obfuscated else "",
            "techniques":  techniques,
            "unchanged":   unchanged,
            "oracle":      oracle,
        })
    return results


def print_summary(results: list[dict]) -> None:
    for label in ("sqli", "xss"):
        rows = [r for r in results if r["label"] == label]
        if not rows:
            continue
        counts: dict[str, int] = {}
        for r in rows:
            counts[r["oracle"]] = counts.get(r["oracle"], 0) + 1
        unchanged = sum(1 for r in rows if r.get("unchanged"))
        total = len(rows)
        print(f"\n{label.upper()} ({total} payloads):")
        for outcome, n in sorted(counts.items()):
            pct = 100 * n / total
            print(f"  {outcome:12} {n:4} ({pct:.1f}%)")
        if unchanged:
            print(f"  unchanged    {unchanged:4} ({100*unchanged/total:.1f}%)  "
                  f"← obfuscation had no effect")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--label",      choices=["sqli","xss","all"], default="all")
    ap.add_argument("--obfuscated", action="store_true")
    ap.add_argument("--seed",       type=int, default=SEED)
    args = ap.parse_args()

    # load corpus
    rows = []
    for fname in ("test_clean.csv",):
        path = PROCESSED / fname
        if path.exists():
            with open(path) as f:
                for r in csv.DictReader(f):
                    if args.label == "all" or r["label"] == args.label:
                        rows.append(r)

    if not rows:
        sys.exit("No data found — run scripts/01c_build_grouped_dataset.py first.")

    print(f"[validate_semantics] {len(rows)} payloads, "
          f"obfuscated={args.obfuscated}, seed={args.seed}")

    results = validate_corpus(rows, args.obfuscated, args.seed)
    print_summary(results)

    # save
    RESULTS.mkdir(exist_ok=True)
    suffix = "_obf" if args.obfuscated else "_clean"
    out_path = RESULTS / f"semantic_validation{suffix}.csv"
    with open(out_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        w.writeheader(); w.writerows(results)

    # summary JSON
    summary: dict[str, dict] = {}
    for label in ("sqli","xss"):
        subset = [r for r in results if r["label"] == label]
        if subset:
            counts: dict[str, int] = {}
            for r in subset:
                counts[r["oracle"]] = counts.get(r["oracle"], 0) + 1
            summary[label] = {"total": len(subset), "outcomes": counts,
                              "unchanged": sum(1 for r in subset if r.get("unchanged"))}
    Path(out_path.with_suffix(".json")).write_text(json.dumps(
        {"config": vars(args), "summary": summary}, indent=2))

    print(f"\n[validate_semantics] saved → {out_path}")
