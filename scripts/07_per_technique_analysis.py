"""
07_per_technique_analysis.py
-----------------------------
Addresses reviewer point 4: "Results should also be reported separately
for URL encoding, double encoding, whitespace manipulation, case toggling,
comment insertion, and Unicode substitution."

Each technique is applied in ISOLATION (not combined), so its individual
contribution to detector degradation can be attributed. Five seeds per
technique give a standard deviation rather than a single draw.

Run:
    python scripts/07_per_technique_analysis.py
    python scripts/07_per_technique_analysis.py --repeats 5
"""

from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import numpy as np
import pandas as pd
from sklearn.metrics import precision_recall_fscore_support

from src.models import get_model_definitions
from src.baseline_signature import SignatureBaseline
from src.baseline_normalized import NormalizedSignatureBaseline
from src import obfuscation as obf

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"
PROCESSED_DIR = Path(__file__).resolve().parent.parent / "data" / "processed"
LABELS = ["benign", "sqli", "xss"]

TECHNIQUES = {
    "url_encoding":         lambda p, rng: obf.url_encode(p, rng, double=False),
    "double_url_encoding":  lambda p, rng: obf.url_encode(p, rng, double=True),
    "whitespace_manipulation": obf.whitespace_manipulation,
    "case_toggling":        obf.keyword_case_toggle,
    "comment_insertion":    obf.comment_insertion,
    "unicode_substitution": obf.unicode_substitution,
}


def macro_f1(y_true, y_pred) -> float:
    _, _, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, labels=LABELS, average="macro", zero_division=0
    )
    return float(f1)


def apply_single(X, y, tech_fn, seed: int) -> list[str]:
    rng = random.Random(seed)
    out = []
    for payload, label in zip(X, y):
        if label in ("sqli", "xss"):
            try:
                out.append(tech_fn(payload, rng))
            except Exception:
                out.append(payload)
        else:
            out.append(payload)
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeats", type=int, default=5)
    ap.add_argument("--seed",    type=int, default=42)
    args = ap.parse_args()

    train = pd.read_csv(PROCESSED_DIR / "train.csv").dropna(subset=["payload","label"])
    clean = pd.read_csv(PROCESSED_DIR / "test_clean.csv").dropna(subset=["payload","label"])
    Xtr, ytr = train.payload.astype(str).tolist(), train.label.tolist()
    Xc,  yc  = clean.payload.astype(str).tolist(), clean.label.tolist()

    print(f"[07] {len(TECHNIQUES)} techniques × {args.repeats} seeds")

    detectors = {}
    for name, pipe in get_model_definitions().items():
        pipe.fit(Xtr, ytr); detectors[name] = pipe
    detectors["signature_baseline"]       = SignatureBaseline()
    detectors["signature_normalized"]     = NormalizedSignatureBaseline()

    clean_f1 = {n: macro_f1(yc, d.predict(Xc)) for n, d in detectors.items()}

    rows = []
    for tech_name, tech_fn in TECHNIQUES.items():
        print(f"  {tech_name}", flush=True)
        per_det = {n: [] for n in detectors}
        for r in range(args.repeats):
            Xo = apply_single(Xc, yc, tech_fn, seed=args.seed + r)
            for n, d in detectors.items():
                per_det[n].append(macro_f1(yc, d.predict(Xo)))
        for n, vals in per_det.items():
            arr = np.array(vals)
            rows.append({
                "technique":          tech_name,
                "detector":           n,
                "f1_clean":           round(clean_f1[n], 4),
                "f1_obfuscated_mean": round(float(arr.mean()), 4),
                "f1_obfuscated_sd":   round(float(arr.std(ddof=1)) if len(arr)>1 else 0., 4),
                "f1_drop":            round(clean_f1[n] - float(arr.mean()), 4),
            })

    results = pd.DataFrame(rows)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    results.to_csv(RESULTS_DIR / "per_technique_results.csv", index=False)

    pivot = results.pivot(index="technique", columns="detector", values="f1_drop")
    pivot.to_csv(RESULTS_DIR / "per_technique_f1_drop.csv")

    pd.set_option("display.width", 160)
    print(f"\n{'='*72}")
    print("F1 DROP PER TECHNIQUE (higher = more effective evasion)")
    print(f"{'='*72}")
    print(pivot.round(4).to_string())
    print(f"\n[07] saved → {RESULTS_DIR/'per_technique_results.csv'}")
