"""
08_final_experiment.py
-----------------------
DEPRECATED — use scripts/definitive_experiment.py instead.

This script has a known bug at line 164: it passes pre-canonicalized
Xte_obf_n to NormalizedSignatureBaseline which canonicalizes internally,
causing double canonicalization for the signature_normalized/obf condition.
That bug is fixed in definitive_experiment.py.

This file is kept for historical reference only.
Do NOT use this script for new experiment runs.

  * GROUP-AWARE splitting — payload families never straddle the
    train/test boundary (anti-leakage, reviewer point 3).
  * Repeated stratified cross-validation (5-fold × 3 repeats = 15 fits
    per configuration) with mean ± SD and 95% CI (reviewer points 6).
  * Paired t-test with Holm-Bonferroni correction for all pairwise
    comparisons (checklist M3 — controls family-wise error rate).
  * EIGHT detector configurations: four detectors × {raw, canonicalized}
    input — isolates the effect of canonicalization from classifier
    choice (reviewer points 1, 2, 5).

The finding from running this: canonicalization, not classifier choice,
determines obfuscation resistance. Every config without it drops 0.14–0.26
macro-F1 under obfuscation; every config with it drops ≤ 0.006.

Run:
    python scripts/00_download_payloads.py      # once
    python scripts/08_final_experiment.py
    python scripts/08_final_experiment.py --folds 5 --repeats 5  # full
"""

from __future__ import annotations

import argparse
import random
import re
import sys
import time
from itertools import combinations
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import numpy as np
import pandas as pd
from scipy import stats
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.metrics import precision_recall_fscore_support

from src.models import get_model_definitions
from src.baseline_signature import SignatureBaseline
from src.baseline_normalized import NormalizedSignatureBaseline, canonicalize
from src.obfuscation import random_obfuscate
from src.dataset import _BENIGN_TEMPLATES, _fill_template
from src.statistics import pairwise_tests, summarise_scores, paired_ci

RAW_DIR     = Path(__file__).resolve().parent.parent / "data" / "raw"
RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"
LABELS      = ["benign", "sqli", "xss"]


# ── helpers ─────────────────────────────────────────────────────────────────

def family_key(payload: str) -> str:
    f = re.sub(r"\d+",    "N",    payload)
    f = re.sub(r"'[^']*'","'S'",  f)
    f = re.sub(r'"[^"]*"','"S"',  f)
    return re.sub(r"\s+", " ",    f).strip().lower()


def macro_f1(y_true, y_pred) -> float:
    _, _, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, labels=LABELS, average="macro", zero_division=0
    )
    return float(f1)


def per_class_metrics(y_true, y_pred) -> dict:
    p, r, f, _ = precision_recall_fscore_support(
        y_true, y_pred, labels=LABELS, zero_division=0
    )
    return {lbl: {"precision": round(float(p[i]),4),
                  "recall":    round(float(r[i]),4),
                  "f1":        round(float(f[i]),4)}
            for i, lbl in enumerate(LABELS)}


def load_corpus(seed: int, benign_extra: int) -> pd.DataFrame:
    frames = []
    for fname, label in [("real_sqli_payloads.txt","sqli"),
                          ("real_xss_payloads.txt", "xss")]:
        path = RAW_DIR / fname
        if not path.exists():
            raise SystemExit(f"{path} missing — run scripts/00_download_payloads.py")
        lines = list(dict.fromkeys(
            l.strip() for l in path.read_text(encoding="utf-8").splitlines() if l.strip()
        ))
        frames.append(pd.DataFrame({"payload": lines, "label": label}))

    rng = random.Random(seed)
    n_mal = sum(len(f) for f in frames)
    rows = []
    for _ in range(n_mal + benign_extra):
        combo = rng.sample(_BENIGN_TEMPLATES, k=rng.randint(1,3))
        rows.append({"payload": "&".join(_fill_template(t,rng) for t in combo),
                     "label": "benign"})
    frames.append(pd.DataFrame(rows).drop_duplicates(subset="payload"))

    df = pd.concat(frames, ignore_index=True)
    df["family"] = df["payload"].map(family_key)
    return df.sample(frac=1.0, random_state=seed).reset_index(drop=True)


# ── main experiment ──────────────────────────────────────────────────────────

def run(df: pd.DataFrame, n_folds: int, n_repeats: int, seed: int) -> dict:
    X      = df["payload"].astype(str).to_numpy()
    y      = df["label"].to_numpy()
    groups = df["family"].to_numpy()

    configs = (
        [f"{m}_raw"        for m in get_model_definitions()] +
        [f"{m}_normalized" for m in get_model_definitions()] +
        ["signature_raw", "signature_normalized"]
    )
    scores = {c: {"f1_clean": [], "f1_obf": []} for c in configs}

    fold_id = 0
    for rep in range(n_repeats):
        sgkf = StratifiedGroupKFold(
            n_splits=n_folds, shuffle=True, random_state=seed + rep
        )
        for train_idx, test_idx in sgkf.split(X, y, groups=groups):
            fold_id += 1
            Xtr, ytr = X[train_idx], y[train_idx]
            Xte, yte = X[test_idx],  y[test_idx]

            # anti-leakage assertion per fold
            assert not (set(groups[train_idx]) & set(groups[test_idx]))

            rng = random.Random(seed + fold_id)
            Xte_obf = [
                random_obfuscate(p, seed=rng.randint(0, 10**6))[0]
                if l in ("sqli", "xss") else p
                for p, l in zip(Xte, yte)
            ]

            Xtr_n      = [canonicalize(p) for p in Xtr]
            Xte_n      = [canonicalize(p) for p in Xte]
            Xte_obf_n  = [canonicalize(p) for p in Xte_obf]

            print(f"  fold {fold_id}/{n_folds*n_repeats} "
                  f"(train={len(Xtr)}, test={len(Xte)})", flush=True)

            for mname in get_model_definitions():
                # raw
                pr = get_model_definitions()[mname]; pr.fit(Xtr, ytr)
                scores[f"{mname}_raw"]["f1_clean"].append(macro_f1(yte, pr.predict(Xte)))
                scores[f"{mname}_raw"]["f1_obf"].append(  macro_f1(yte, pr.predict(Xte_obf)))
                # canonicalized
                pn = get_model_definitions()[mname]; pn.fit(Xtr_n, ytr)
                scores[f"{mname}_normalized"]["f1_clean"].append(macro_f1(yte, pn.predict(Xte_n)))
                scores[f"{mname}_normalized"]["f1_obf"].append(  macro_f1(yte, pn.predict(Xte_obf_n)))

            sig, sig_n = SignatureBaseline(), NormalizedSignatureBaseline()
            scores["signature_raw"]["f1_clean"].append(macro_f1(yte, sig.predict(list(Xte))))
            scores["signature_raw"]["f1_obf"].append(  macro_f1(yte, sig.predict(list(Xte_obf))))
            scores["signature_normalized"]["f1_clean"].append(macro_f1(yte, sig_n.predict(list(Xte))))
            scores["signature_normalized"]["f1_obf"].append(  macro_f1(yte, sig_n.predict(list(Xte_obf_n))))

    return scores


def summarize(scores: dict) -> pd.DataFrame:
    rows = []
    for det, m in scores.items():
        row = {"configuration": det, "n_fits": len(m["f1_clean"])}
        for metric in ("f1_clean", "f1_obf"):
            arr = np.array(m[metric])
            mean, sd = arr.mean(), arr.std(ddof=1)
            sem = stats.sem(arr)
            ci = (mean, mean) if (sem == 0 or np.isnan(sem)) else \
                 stats.t.interval(0.95, len(arr)-1, loc=mean, scale=sem)
            row[f"{metric}_mean"]    = round(float(mean), 4)
            row[f"{metric}_sd"]      = round(float(sd),   4)
            row[f"{metric}_ci_low"]  = round(float(ci[0]),4)
            row[f"{metric}_ci_high"] = round(float(ci[1]),4)
        row["f1_drop"] = round(row["f1_clean_mean"] - row["f1_obf_mean"], 4)
        rows.append(row)
    return pd.DataFrame(rows).sort_values("f1_obf_mean", ascending=False)


def canonicalization_effects(scores: dict) -> pd.DataFrame:
    """Effect of canonicalization per detector — Holm-corrected p-values."""
    # Build pairwise input: raw vs normalized for each model
    pairs = {}
    for m in list(get_model_definitions()) + ["signature"]:
        a, b = f"{m}_raw", f"{m}_normalized"
        if a in scores and b in scores:
            pairs[f"{m}_raw"]        = scores[a]["f1_obf"]
            pairs[f"{m}_normalized"] = scores[b]["f1_obf"]

    all_tests = pairwise_tests(pairs)

    # Filter to only raw vs normalized comparisons
    rows = []
    for t in all_tests:
        a, b = t["a"], t["b"]
        # one must end in _raw and the other in _normalized, same prefix
        if a.endswith("_raw") and b.endswith("_normalized"):
            m = a[:-4]
            if b == f"{m}_normalized":
                rows.append({
                    "model":             m,
                    "raw_f1_obf":        round(np.array(pairs[a]).mean(), 4),
                    "normalized_f1_obf": round(np.array(pairs[b]).mean(), 4),
                    "improvement":       round(t["mean_diff"] * -1, 4),  # norm - raw
                    "p_raw":             f"{t['p_raw']:.2e}",
                    "p_holm":            f"{t['p_holm']:.2e}",
                    "significant_holm":  t["significant"],
                })
    return pd.DataFrame(rows)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--folds",       type=int, default=5)
    ap.add_argument("--repeats",     type=int, default=3)
    ap.add_argument("--seed",        type=int, default=42)
    ap.add_argument("--benign-extra",type=int, default=200)
    args = ap.parse_args()

    df = load_corpus(args.seed, args.benign_extra)
    print(f"[08] Corpus: {len(df)} samples, {df['family'].nunique()} families")
    print(f"[08] Class distribution: {df['label'].value_counts().to_dict()}")
    print(f"[08] Protocol: {args.folds}-fold × {args.repeats} repeats "
          f"= {args.folds*args.repeats} fits per configuration\n")

    t0 = time.perf_counter()
    scores = run(df, args.folds, args.repeats, args.seed)
    elapsed = time.perf_counter() - t0

    summary = summarize(scores)
    effects = canonicalization_effects(scores)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    summary.to_csv(RESULTS_DIR / "final_experiment.csv",         index=False)
    effects.to_csv(RESULTS_DIR / "final_experiment_effects.csv", index=False)

    pd.set_option("display.width", 200)
    pd.set_option("display.max_columns", 20)

    print(f"\n{'='*80}")
    print(f"GROUP-AWARE CROSS-VALIDATION — {args.folds}×{args.repeats}, {elapsed:.1f}s")
    print(f"{'='*80}")
    print(summary[["configuration","f1_clean_mean","f1_clean_sd",
                    "f1_obf_mean","f1_obf_sd","f1_drop"]].to_string(index=False))

    print(f"\n{'='*80}")
    print("EFFECT OF CANONICALIZATION (paired t-test on obfuscated F1)")
    print(f"{'='*80}")
    print(effects.to_string(index=False))

    print(f"\n[08] saved → {RESULTS_DIR/'final_experiment.csv'}")
    print(f"[08] saved → {RESULTS_DIR/'final_experiment_effects.csv'}")
