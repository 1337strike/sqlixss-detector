"""
export_statistics.py
---------------------
Generates every inferential statistic reported in the paper from a run's
fold_scores.json, so none of them is computed by hand:

  * Table I  -- canonicalization effect per detector (canonicalized minus raw
                obfuscated macro-F1): mean gain, marginal and paired SDs,
                Nadeau-Bengio corrected SE and t, two-sided p (df = 14), Holm
                adjustment across the four detectors, and the unadjusted 95%
                CI of the gain, mean +/- t(0.975, 14) * SE_c (paper Eq. 1).
  * §IV-B   -- exploratory pairwise comparisons of the three canonicalized ML
                models on obfuscated fold scores (LR-MNB, LR-SVM, SVM-MNB),
                same corrected test, separate Holm family of three.

Correction factor: 1/n + n_test/n_train with the mean fold sizes recorded in
fold_scores.json (1/15 + 202.4/809.6 = 0.316667, paper §III-D).

Writes <run>/full_statistics.json. definitive_experiment.py calls this for
every new run; for the archived reference run use --out so its files are not
modified:

    python scripts/export_statistics.py results/definitive_<ts>_42
    python scripts/export_statistics.py results/definitive_20260923T094339Z_42 --out /tmp/ref_stats.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
from scipy import stats

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.statistics import holm_correct  # noqa: E402

DETECTORS = [  # (label, raw config, canonicalized config)
    ("logistic_regression", "logistic_regression_raw", "logistic_regression_normalized"),
    ("naive_bayes", "naive_bayes_raw", "naive_bayes_normalized"),
    ("svm", "svm_raw", "svm_normalized"),
    ("signature", "signature_raw", "signature_normalized"),
]
PAIRS = [  # (label, minuend, subtrahend): difference = minuend - subtrahend
    ("LR-MNB", "logistic_regression_normalized", "naive_bayes_normalized"),
    ("LR-SVM", "logistic_regression_normalized", "svm_normalized"),
    ("SVM-MNB", "svm_normalized", "naive_bayes_normalized"),
]


def corrected_test(minuend: np.ndarray, subtrahend: np.ndarray, correction: float) -> dict:
    d = minuend - subtrahend
    n = len(d)
    var_d = float(d.var(ddof=1))
    se = float(np.sqrt(correction * var_d))
    t = float(d.mean() / se) if se > 0 else float("inf")
    p = float(2 * stats.t.sf(abs(t), df=n - 1))
    half = float(stats.t.ppf(0.975, n - 1) * se)
    return {
        "mean_diff": float(d.mean()), "sd_diff": float(d.std(ddof=1)), "var_diff": var_d,
        "correction_factor": correction, "se_corr": se, "t": t, "df": n - 1, "p_raw": p,
        "ci95_diff": [float(d.mean()) - half, float(d.mean()) + half],
        "fold_diffs": [round(float(x), 6) for x in d],
    }


def export(run_dir: Path) -> dict:
    fs = json.loads((run_dir / "fold_scores.json").read_text())
    scores = fs["fold_scores"]
    n = len(next(iter(scores.values()))["f1_obf"])
    correction = 1.0 / n + fs["n_test_mean"] / fs["n_train_mean"]

    comparisons = []
    for label, raw_key, norm_key in DETECTORS:
        a = np.array(scores[raw_key]["f1_obf"])
        b = np.array(scores[norm_key]["f1_obf"])
        c = corrected_test(b, a, correction)
        sd_a, sd_b = float(a.std(ddof=1)), float(b.std(ddof=1))
        bounds = [abs(sd_a - sd_b), sd_a + sd_b]
        comparisons.append({
            "label": label, **{k: c[k] for k in ("mean_diff",)},
            "sd_raw": sd_a, "sd_norm": sd_b, "sd_diff": c["sd_diff"],
            "corr": float(np.corrcoef(a, b)[0, 1]), "var_diff": c["var_diff"],
            "correction_factor": correction, "se_corr": c["se_corr"], "t": c["t"], "df": c["df"],
            "p_raw": c["p_raw"], "ci95_gain": c["ci95_diff"],
            "triangle_ok": bool(bounds[0] <= c["sd_diff"] <= bounds[1]), "triangle_bounds": bounds,
            "fold_scores_raw": [round(float(x), 6) for x in a],
            "fold_scores_norm": [round(float(x), 6) for x in b],
            "fold_diffs": c["fold_diffs"],
        })
    for comp, ph in zip(comparisons, holm_correct([c["p_raw"] for c in comparisons])):
        comp["p_holm"] = ph

    pairwise = []
    for label, m_key, s_key in PAIRS:
        c = corrected_test(np.array(scores[m_key]["f1_obf"]), np.array(scores[s_key]["f1_obf"]), correction)
        pairwise.append({"label": label, "minuend": m_key, "subtrahend": s_key, **c})
    for comp, ph in zip(pairwise, holm_correct([c["p_raw"] for c in pairwise])):
        comp["p_holm"] = ph

    return {
        "run_id": fs.get("run_id", run_dir.name),
        "protocol": {
            "k": fs.get("n_folds"), "r": fs.get("n_reps"), "n_train_mean": fs["n_train_mean"],
            "n_test_mean": fs["n_test_mean"], "correction_factor": correction, "df": n - 1,
            "n_holm_comparisons": len(comparisons), "n_holm_pairwise": len(pairwise),
            "ci": "unadjusted 95%: mean_diff +/- t(0.975, df) * se_corr",
            "generated_by": "scripts/export_statistics.py",
        },
        "comparisons": comparisons,
        "pairwise_canonicalized_ml": pairwise,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir", type=Path)
    ap.add_argument("--out", type=Path, help="default: <run_dir>/full_statistics.json")
    args = ap.parse_args()
    out = args.out or args.run_dir / "full_statistics.json"
    stats_out = export(args.run_dir)
    out.write_text(json.dumps(stats_out, indent=2) + "\n")
    print(f"[stats] wrote {out}")
    for c in stats_out["comparisons"]:
        lo, hi = c["ci95_gain"]
        print(f"  {c['label']:20} gain={c['mean_diff']:+.4f} CI=[{lo:.4f}, {hi:.4f}] "
              f"t={c['t']:.3f} p_holm={c['p_holm']:.3g}")
    for c in stats_out["pairwise_canonicalized_ml"]:
        lo, hi = c["ci95_diff"]
        print(f"  {c['label']:20} diff={c['mean_diff']:+.4f} CI=[{lo:.4f}, {hi:.4f}] p_holm={c['p_holm']:.4f}")


if __name__ == "__main__":
    main()
