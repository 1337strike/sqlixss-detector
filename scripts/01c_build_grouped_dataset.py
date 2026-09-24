"""
01c_build_grouped_dataset.py
-----------------------------
Builds the dataset with a GROUP-AWARE split that prevents payload-family
leakage between training and test partitions.  This addresses a
methodological issue raised in peer review (reviewer point 3):

    "A source- or template-grouped split is preferable because closely
     related payload variants in both training and test partitions could
     inflate performance."

Why this matters
----------------
The upstream SQLi payload corpus contains large families of near-identical
variants, e.g. "ORDER BY 1--", "ORDER BY 2--", ... "ORDER BY 31337--" is
31 payloads that differ only in one integer. Under a random split, members
of the same family land on both sides of the boundary. A classifier then
scores highly on test samples by recognising a pattern it has effectively
memorised from a near-duplicate in training, not by generalising.

This script instead:
  1. Normalises each payload to a structural family key (digit literals
     replaced by N, quoted literals by 'S', whitespace collapsed).
  2. Splits on FAMILIES rather than on individual payloads, so every
     variant of a given family lands entirely in one partition.
  3. Verifies with an assertion that no family appears on both sides.
  4. Applies obfuscation only to the test partition, so no obfuscated
     variant of a training payload is ever tested against.

The resulting scores are lower than a random split would give. That is
the correct result: the random-split figure was optimistic.

Run:
    python scripts/00_download_payloads.py  # once, to get real payloads
    python scripts/01c_build_grouped_dataset.py
"""

from __future__ import annotations

import argparse
import random
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd
from src.dataset import _BENIGN_TEMPLATES, _fill_template, save_partitions
from src.obfuscation import random_obfuscate

RAW_DIR = Path(__file__).resolve().parent.parent / "data" / "raw"


def family_key(payload: str) -> str:
    """Normalise a payload to its structural family.

    Aggressively collapses variants that differ only in literal values
    so that near-duplicates are treated as the same family.
    """
    f = re.sub(r"\d+", "N", payload)
    f = re.sub(r"'[^']*'", "'S'", f)
    f = re.sub(r'"[^"]*"', '"S"', f)
    return re.sub(r"\s+", " ", f).strip().lower()


def load_payload_file(path: Path, label: str) -> pd.DataFrame:
    if not path.exists():
        raise SystemExit(
            f"{path} not found.\nRun: python scripts/00_download_payloads.py"
        )
    lines = [
        l.strip()
        for l in path.read_text(encoding="utf-8").splitlines()
        if l.strip()
    ]
    # de-duplicate
    lines = list(dict.fromkeys(lines))
    df = pd.DataFrame({"payload": lines, "label": label})
    df["family"] = df["payload"].map(family_key)
    return df


def grouped_split(
    df: pd.DataFrame, test_size: float, rng: random.Random
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Split a DataFrame by family, not by row."""
    families = sorted(df["family"].unique())
    rng.shuffle(families)
    n_test = max(1, int(len(families) * test_size))
    test_fams = set(families[:n_test])
    test  = df[df["family"].isin(test_fams)].reset_index(drop=True)
    train = df[~df["family"].isin(test_fams)].reset_index(drop=True)
    return train, test


def build(test_size: float, seed: int, benign_extra: int) -> dict:
    rng = random.Random(seed)

    sqli = load_payload_file(RAW_DIR / "real_sqli_payloads.txt", "sqli")
    xss  = load_payload_file(RAW_DIR / "real_xss_payloads.txt",  "xss")

    print(f"[01c] SQLi: {len(sqli)} payloads → {sqli['family'].nunique()} families")
    print(f"[01c] XSS : {len(xss)} payloads → {xss['family'].nunique()} families")

    # Benign samples — generated rather than collected because no production
    # traffic is available. Count chosen to keep the corpus roughly balanced.
    n_benign = len(sqli) + len(xss) + benign_extra
    rows = []
    for _ in range(n_benign):
        combo = rng.sample(_BENIGN_TEMPLATES, k=rng.randint(1, 3))
        rows.append({
            "payload": "&".join(_fill_template(t, rng) for t in combo),
            "label": "benign",
        })
    benign = (
        pd.DataFrame(rows)
        .drop_duplicates(subset="payload")
        .reset_index(drop=True)
    )
    benign["family"] = benign["payload"].map(family_key)
    print(f"[01c] benign: {len(benign)} samples → {benign['family'].nunique()} families")

    # Split each class separately to preserve approximate class balance.
    train_parts, test_parts = [], []
    for part in (benign, sqli, xss):
        tr, te = grouped_split(part, test_size, rng)
        train_parts.append(tr)
        test_parts.append(te)

    train_df = (
        pd.concat(train_parts, ignore_index=True)
        .sample(frac=1.0, random_state=seed)
        .reset_index(drop=True)
    )
    test_df = (
        pd.concat(test_parts, ignore_index=True)
        .sample(frac=1.0, random_state=seed)
        .reset_index(drop=True)
    )

    # Anti-leakage assertion: no family on both sides.
    overlap = set(train_df["family"]) & set(test_df["family"])
    assert not overlap, f"LEAKAGE: {len(overlap)} families in both partitions"
    print(f"[01c] leakage check: 0 shared families between train and test  ✓")

    # Build the obfuscated test partition.
    obf_rows = []
    for _, row in test_df.iterrows():
        if row["label"] in ("sqli", "xss"):
            obf, techs = random_obfuscate(
                row["payload"], seed=rng.randint(0, 10**6)
            )
            obf_rows.append({
                "payload": obf,
                "label": row["label"],
                "techniques": "+".join(techs),
            })
        else:
            obf_rows.append({
                "payload": row["payload"],
                "label": row["label"],
                "techniques": "",
            })

    return {
        "train":           train_df[["payload", "label"]],
        "test_clean":      test_df[["payload", "label"]],
        "test_obfuscated": pd.DataFrame(obf_rows),
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--test-size",    type=float, default=0.25)
    ap.add_argument("--seed",         type=int,   default=42)
    ap.add_argument("--benign-extra", type=int,   default=200,
                    help="benign samples added above the malicious count")
    args = ap.parse_args()

    parts = build(args.test_size, args.seed, args.benign_extra)
    for name, df in parts.items():
        print(f"\n{name}: {len(df)} rows")
        print(df["label"].value_counts().to_string())
    save_partitions(parts)
