"""
src/statistics.py
------------------
Statistical utilities shared across experiment scripts.

Changes
-------
- Holm-Bonferroni correction for multiple comparisons (M3).
- Nadeau-Bengio corrected resampled t-test for repeated k-fold CV (M3):
  accounts for the positive correlation between fold scores that arises
  because test folds overlap across repetitions.
- CI computation handles zero-variance folds gracefully.
"""

from __future__ import annotations

import numpy as np
from scipy import stats


def paired_ci(arr: np.ndarray, confidence: float = 0.95) -> tuple[float, float]:
    """95 % CI via the t-distribution. Returns (low, high)."""
    n = len(arr)
    mean = arr.mean()
    sem = stats.sem(arr)
    if sem == 0 or np.isnan(sem):
        return (float(mean), float(mean))
    ci = stats.t.interval(confidence, df=n - 1, loc=mean, scale=sem)
    return (float(ci[0]), float(ci[1]))


def nadeau_bengio_ttest(
    scores_a: list[float],
    scores_b: list[float],
    n_train: int,
    n_test: int,
) -> tuple[float, float]:
    """Nadeau-Bengio corrected resampled paired t-test (2003).

    Standard paired t-test on repeated k-fold scores violates independence
    because test folds from different repetitions overlap.  The Nadeau-
    Bengio correction inflates the variance by a factor of
    (1/k + n_test/n_train), where k is the number of test samples per fold,
    effectively accounting for the positive correlation.

    Parameters
    ----------
    scores_a, scores_b : per-fold scores for the two configurations.
    n_train, n_test    : number of training and test samples per fold.

    Returns
    -------
    t_stat, p_value  (two-tailed)

    Reference
    ---------
    Nadeau, C. & Bengio, Y. (2003). Inference for the generalization error.
    Machine Learning, 52(3), 239–281.
    """
    diffs = np.array(scores_b) - np.array(scores_a)
    k = len(diffs)
    mean_diff = diffs.mean()
    # Unbiased variance of the per-fold differences
    var_diff = diffs.var(ddof=1)
    # Correction factor: accounts for fold correlation
    correction = 1.0 / k + n_test / n_train
    corrected_var = correction * var_diff
    if corrected_var <= 0:
        return (float("inf"), 0.0) if mean_diff != 0 else (0.0, 1.0)
    t_stat = mean_diff / np.sqrt(corrected_var)
    p_value = float(2 * stats.t.sf(abs(t_stat), df=k - 1))
    return (float(t_stat), p_value)


def holm_correct(p_values: list[float]) -> list[float]:
    """Holm-Bonferroni step-down correction."""
    n = len(p_values)
    if n == 0:
        return []
    order = np.argsort(p_values)
    corrected = np.array(p_values, dtype=float)
    running_max = 0.0
    for rank, idx in enumerate(order):
        adjusted = (n - rank) * p_values[idx]
        running_max = max(running_max, adjusted)
        corrected[idx] = min(1.0, running_max)
    return corrected.tolist()


def summarise_scores(scores: list[float]) -> dict:
    arr = np.array(scores)
    ci = paired_ci(arr)
    return {
        "mean":    round(float(arr.mean()),  4),
        "sd":      round(float(arr.std(ddof=1) if len(arr) > 1 else 0.0), 4),
        "ci_low":  round(ci[0], 4),
        "ci_high": round(ci[1], 4),
        "n_fits":  len(arr),
    }


def pairwise_tests(
    score_map: dict[str, list[float]],
    n_train: int = 749,
    n_test:  int = 263,
    alpha: float = 0.05,
) -> list[dict]:
    """Nadeau-Bengio corrected paired test for every pair, + Holm correction.

    Uses n_train and n_test from the grouped dataset to apply the
    Nadeau-Bengio variance correction before Holm.
    """
    from itertools import combinations

    names = list(score_map.keys())
    rows = []
    for a, b in combinations(names, 2):
        va = np.array(score_map[a])
        vb = np.array(score_map[b])
        diff = float(va.mean() - vb.mean())
        t, p = nadeau_bengio_ttest(
            list(va), list(vb), n_train=n_train, n_test=n_test
        )
        rows.append({"a": a, "b": b, "mean_diff": round(diff, 4),
                     "t_stat_corrected": round(t, 3), "p_raw": float(p)})

    rows.sort(key=lambda r: r["p_raw"])
    corrected = holm_correct([r["p_raw"] for r in rows])
    for row, pc in zip(rows, corrected):
        row["p_holm"] = round(pc, 6)
        row["significant"] = bool(pc < alpha)
    return rows

