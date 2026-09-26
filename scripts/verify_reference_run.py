"""
verify_reference_run.py
------------------------
Checks that a fresh definitive_experiment.py run reproduces the paper's
reference run (results/definitive_20260923T094339Z_42) exactly.

Compared: all 240 fold-level F1 scores (Tables I, IV), the 16 single-split
confusion matrices (Table II), the 35 per-technique drops (Table III), and
the inferential statistics (Table I gains, 95% CIs and p_Holm; §IV-B pairwise
tests) against the archived full_statistics.json and the paper's printed values.
Latency (Table V) is wall-clock and is not compared.

Run (pinned environment from requirements.lock):
    python scripts/definitive_experiment.py --seed 42 --folds 5 --repeats 3
    python scripts/verify_reference_run.py            # newest run vs reference
    python scripts/verify_reference_run.py results/definitive_<ts>_42

Exits 1 on any mismatch.
"""

from __future__ import annotations

import csv
import json
import math
import sys
from pathlib import Path

RESULTS = Path(__file__).resolve().parent.parent / "results"
REFERENCE = RESULTS / "definitive_20260923T094339Z_42"
TOL = 1e-12


def _per_technique(run: Path) -> dict[tuple[str, str], float]:
    with open(run / "per_technique.csv") as f:
        # the reference run labels one technique "..._UNDISCLOSED" (see its NOTE.md)
        return {(r["technique"].replace("_UNDISCLOSED", ""), r["detector"]): float(r["f1_drop"])
                for r in csv.DictReader(f)}


# Inferential statistics as printed in the paper (PDF v17, Table I and §IV-B).
PAPER_TABLE_I = {  # label: (gain, CI low, CI high, p_holm)
    "logistic_regression": (0.2029, 0.1597, 0.2461, 3.42e-7),
    "naive_bayes": (0.1717, 0.1291, 0.2142, 1.65e-6),
    "svm": (0.1327, 0.0892, 0.1762, 1.30e-5),
    "signature": (0.2527, 0.1896, 0.3158, 1.65e-6),
}
PAPER_PAIRWISE = {  # label: (mean difference, p_holm)
    "LR-MNB": (0.0096, 0.2784), "LR-SVM": (0.0015, 0.5154), "SVM-MNB": (0.0081, 0.4091),
}
PAPER_SVM_MNB_CI = (-0.0050, 0.0213)


def _sig3(x: float) -> float:
    return float(f"{x:.3g}")


def _statistics_structure_errors(data: object) -> list[str]:
    """Reject incomplete results before any numerical comparison can pass."""
    if not isinstance(data, dict):
        return ["full_statistics must be a JSON object"]
    errors = []
    for section, expected, ci_key in (
        ("comparisons", PAPER_TABLE_I, "ci95_gain"),
        ("pairwise_canonicalized_ml", PAPER_PAIRWISE, "ci95_diff"),
    ):
        rows = data.get(section)
        if not isinstance(rows, list):
            errors.append(f"{section} must be a list with {len(expected)} rows")
            continue
        labels = [r.get("label") for r in rows if isinstance(r, dict)]
        if (len(rows) != len(expected) or len(labels) != len(rows)
                or any(labels.count(label) != 1 for label in expected)):
            errors.append(f"{section} must contain each expected label exactly once: {list(expected)}")
        for i, row in enumerate(rows):
            if not isinstance(row, dict):
                continue
            for key in ("mean_diff", "sd_diff", "se_corr", "t", "p_raw", "p_holm"):
                value = row.get(key)
                if type(value) not in (int, float) or not math.isfinite(value):
                    errors.append(f"{section}[{i}].{key} must be a finite number")
            ci = row.get(ci_key)
            if (not isinstance(ci, list) or len(ci) != 2
                    or any(type(x) not in (int, float) or not math.isfinite(x) for x in ci)):
                errors.append(f"{section}[{i}].{ci_key} must contain two finite numbers")
    return errors


def verify_statistics(run: Path) -> list[str]:
    """full_statistics.json of the new run vs the archived reference file
    (full precision) and vs every value printed in the paper."""
    errors = []
    path = run / "full_statistics.json"
    if not path.exists():
        return [f"{path.name} missing (scripts/export_statistics.py)"]
    try:
        new = json.loads(path.read_text())
    except (ValueError, UnicodeError) as exc:
        return [f"{path.name} invalid JSON: {exc}"]
    errors = _statistics_structure_errors(new)
    if errors:
        return errors
    ref = json.loads((REFERENCE / "full_statistics.json").read_text())
    by_label = {row["label"]: row for row in new["comparisons"]}
    for a in ref["comparisons"]:
        b = by_label[a["label"]]
        for k in ("mean_diff", "sd_diff", "se_corr", "t", "p_raw", "p_holm"):
            if abs(a[k] - b[k]) > 1e-9 * max(abs(a[k]), 1e-300):
                errors.append(f"full_statistics {a['label']}.{k}: {b[k]} != archived {a[k]}")
    for c in new["comparisons"]:
        gain, lo, hi, ph = PAPER_TABLE_I[c["label"]]
        got = (round(c["mean_diff"], 4), round(c["ci95_gain"][0], 4), round(c["ci95_gain"][1], 4), _sig3(c["p_holm"]))
        if got != (gain, lo, hi, ph):
            errors.append(f"Table I {c['label']}: {got} != paper {(gain, lo, hi, ph)}")
    for c in new["pairwise_canonicalized_ml"]:
        diff, ph = PAPER_PAIRWISE[c["label"]]
        if (round(c["mean_diff"], 4), round(c["p_holm"], 4)) != (diff, ph):
            errors.append(f"pairwise {c['label']}: {c['mean_diff']:.4f}/{c['p_holm']:.4f} != paper {diff}/{ph}")
        if c["label"] == "SVM-MNB" and tuple(round(x, 4) for x in c["ci95_diff"]) != PAPER_SVM_MNB_CI:
            errors.append(f"SVM-MNB CI {c['ci95_diff']} != paper {PAPER_SVM_MNB_CI}")
    print(f"  statistics compared:           {len(new['comparisons'])} Table I rows (gain, CI, p_Holm), "
          f"{len(new['pairwise_canonicalized_ml'])} pairwise tests")
    return errors


def verify(run: Path) -> list[str]:
    errors = []

    ref = json.loads((REFERENCE / "fold_scores.json").read_text())["fold_scores"]
    new = json.loads((run / "fold_scores.json").read_text())["fold_scores"]
    n = 0
    for cfg, conds in ref.items():
        for cond, scores in conds.items():
            got = new.get(cfg, {}).get(cond, [])
            if len(got) != len(scores):
                errors.append(f"fold_scores {cfg}/{cond}: {len(got)} folds, expected {len(scores)}")
                continue
            for i, (a, b) in enumerate(zip(scores, got)):
                n += 1
                if abs(a - b) > TOL:
                    errors.append(f"fold_scores {cfg}/{cond}[{i}]: {b} != {a}")
    print(f"  fold-level F1 scores compared: {n}")

    ref = json.loads((REFERENCE / "single_split.json").read_text())["detectors"]
    new = json.loads((run / "single_split.json").read_text())["detectors"]
    n = 0
    for cfg, conds in ref.items():
        for cond in ("clean", "obf"):
            n += 1
            if new[cfg][cond]["confusion_matrix"] != conds[cond]["confusion_matrix"]:
                errors.append(f"confusion matrix {cfg}/{cond} differs")
    print(f"  confusion matrices compared:   {n}")

    ref, new = _per_technique(REFERENCE), _per_technique(run)
    for key, a in ref.items():
        if key not in new:
            errors.append(f"per_technique {key} missing")
        elif abs(new[key] - a) > TOL:
            errors.append(f"per_technique {key}: {new[key]} != {a}")
    print(f"  per-technique drops compared:  {len(ref)}")

    return errors + verify_statistics(run)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        run = Path(sys.argv[1])
    else:
        runs = sorted(p for p in RESULTS.glob("definitive_*") if p != REFERENCE)
        if not runs:
            sys.exit("no run found; run scripts/definitive_experiment.py first")
        run = runs[-1]
    print(f"[verify] {run.name} vs {REFERENCE.name}")
    errors = verify(run)
    if errors:
        print(f"\n[verify] FAIL: {len(errors)} mismatch(es)")
        for e in errors[:20]:
            print("  " + e)
        sys.exit(1)
    print("\n[verify] OK: reproduces the reference run exactly")
