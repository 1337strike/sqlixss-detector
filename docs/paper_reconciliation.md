# Paper Reconciliation Report
# PDF v17 vs Reference Run `definitive_20260923T094339Z_42`

Every number printed in PDF v17 is listed here next to its value in the
reference run and the check that guards it. All values match.

**Reproduce (pinned environment):**
```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.lock
python scripts/01c_build_grouped_dataset.py
python scripts/definitive_experiment.py --seed 42 --folds 5 --repeats 3
python scripts/verify_reference_run.py
```
With `requirements.lock` the new run matches the reference run bit-for-bit
(max absolute difference 0.0), and CI checks this on every push.

**Checks:**
- **V1**: `verify_reference_run.py`, fold scores (240 values, exact)
- **V2**: `verify_reference_run.py`, confusion matrices (16, identical)
- **V3**: `verify_reference_run.py`, per-technique drops (35, exact)
- **V4**: `verify_reference_run.py`, inferential statistics against the
  archived `full_statistics.json` (full precision) and the paper's printed values
- **M**: recomputed by hand from the listed artifact during the v17 audit

---

## 1. Tables

### Table I: canonicalization effects (grouped 5×3 CV)

| Detector | Raw clean F1 | Raw obf. F1 | Canon. obf. F1 | Gain | 95% CI of gain | Paired SD | p_H | Check |
|---|---|---|---|---|---|---|---|---|
| LR | 0.9909 | 0.7905 ± 0.0394 | 0.9934 ± 0.0068 | +0.2029 | [0.1597, 0.2461] | 0.0358 | 3.42 × 10⁻⁷ | V1, V4 ✅ |
| MNB | 0.9831 | 0.8121 ± 0.0380 | 0.9838 ± 0.0101 | +0.1717 | [0.1291, 0.2142] | 0.0353 | 1.65 × 10⁻⁶ | V1, V4 ✅ |
| SVM | 0.9931 | 0.8592 ± 0.0381 | 0.9919 ± 0.0077 | +0.1327 | [0.0892, 0.1762] | 0.0360 | 1.30 × 10⁻⁵ | V1, V4 ✅ |
| Signature | 0.8358 | 0.5893 ± 0.1059 | 0.8420 ± 0.0723 | +0.2527 | [0.1896, 0.3158] | 0.0523 | 1.65 × 10⁻⁶ | V1, V4 ✅ |

Source: `fold_scores.json`; statistics from `full_statistics.json`, which is
regenerated exactly by `scripts/export_statistics.py`. `cv_stats.json` in this
run computed its tests from rounded inputs (e.g. LR p_H 3.40 × 10⁻⁷); see the
run's `NOTE.md`.

### Table II: supplementary single split (n = 263)

| Configuration | Clean F1 | Obf. F1 | FN | Cross | Check |
|---|---|---|---|---|---|
| LR (raw / canon.) | 1.0000 / 1.0000 | 0.7895 / 0.9931 | 0 / 0 | 23 / 1 | V2 ✅ |
| MNB (raw / canon.) | 0.9937 / 0.9937 | 0.7950 / 0.9868 | 8 / 2 | 17 / 1 | V2 ✅ |
| SVM (raw / canon.) | 1.0000 / 1.0000 | 0.8369 / 0.9931 | 0 / 0 | 19 / 1 | V2 ✅ |
| Sig. (raw / canon.) | 0.7467 / 0.7563 | 0.4928 / 0.7516 | 90 / 59 | 0 / 0 | V2 ✅ |

Source: `single_split.json`. F1 values recomputed from the confusion matrices
match to all printed digits.

### Table III: macro-F1 drop by transformation attempt (5 seeds)

All 35 entries (7 techniques × LR, MNB, SVM, Sig.-R, Sig.-C) match
`per_technique.csv`, e.g. double URL encoding 0.3887 / 0.3829 / 0.3889 /
0.2806 / 0.0000 and whitespace 0.0000 / 0.0000 / 0.0000 / 0.0119 / 0.0079.
**V3 ✅.** (The archived file labels partial URL encoding
`partial_url_encoding_UNDISCLOSED`, a label from before §III-C disclosed it.)

### Table IV: canonicalized configurations (grouped 5×3 CV)

| Detector | Clean macro-F1 | Obf. macro-F1 | Drop | Check |
|---|---|---|---|---|
| LR | 0.9937 ± 0.0070 | 0.9934 ± 0.0068 | 0.0003 | V1 ✅ |
| MNB | 0.9843 ± 0.0097 | 0.9838 ± 0.0101 | 0.0006 | V1 ✅ |
| SVM | 0.9919 ± 0.0077 | 0.9919 ± 0.0077 | 0.0000 | V1 ✅ |
| Signature | 0.8460 ± 0.0712 | 0.8420 ± 0.0723 | 0.0040 | V1 ✅ |

### Table V: exploratory clean-input timing (ms, 263 calls)

| Configuration | Median | p95 | p99 | Check |
|---|---|---|---|---|
| LR (canon.) | 0.2731 | 0.3548 | 0.3750 | M ✅ |
| MNB (canon.) | 0.2579 | 0.3242 | 0.3783 | M ✅ |
| SVM (canon.) | 1.2457 | 1.3864 | 1.5812 | M ✅ |
| Signature (raw) | 0.0046 | 0.0091 | 0.0167 | M ✅ |
| Signature (canon.) | 0.0082 | 0.0190 | 0.0323 | M ✅ |

Source: `single_split.json: latency`. Timing is wall-clock and hardware
dependent, so it is not re-verified by CI; new runs record their own timings
alongside the archived values.

## 2. Numbers in the Text

| Claim | Location | Value | Check |
|---|---|---|---|
| Correction factor | §III-D | 0.316667 | V4 ✅ |
| LR t statistic | §IV-A | 10.071 | V4 ✅ |
| Largest adjusted p-value (SVM) | §IV-A | 1.30 × 10⁻⁵ | V4 ✅ |
| Raw clean→obfuscated loss range | §IV-A | 0.1340–0.2466 | M ✅ (`cv_stats.json: obf_drop`) |
| Canonicalized drop range | §IV-A | 0.0000–0.0040 | V1 ✅ |
| Pairwise LR–MNB, LR–SVM, SVM–MNB (diff, p_H) | §IV-B | 0.0096/0.2784, 0.0015/0.5154, 0.0081/0.4091 | V4 ✅ |
| SVM–MNB 95% CI | §IV-B | [−0.0050, 0.0213] | V4 ✅ |
| Normalizing signature drop | §IV-B | 0.0048 | V2 ✅ |
| Canonicalized SVM/LR obfuscated confusion matrix | §IV-B, Eq. (2) | [[145,0,0],[0,84,0],[0,1,33]] | V2 ✅ |
| SQLi P/R/F1 0.9882/1.0000/0.9941; XSS 1.0000/0.9706/0.9851 | §IV-B | as printed | M ✅ |
| MNB SQLi recall | §IV-B | 82/84 = 0.9762 | V2 ✅ |
| MNB p95 saving vs LR | §IV-D | 0.0306 ms | M ✅ (0.3548 − 0.3242) |
| Oracle: 66 / 16 / 2, before and after obfuscation | §IV-E | as printed | M ✅ (`results/semantic_validation_{clean,obf}.json`) |
| 1,012 IDs, 815 families; 749/263 split class counts | §III-A | as printed | M ✅, `tests/test_split_integrity.py` |

## 3. History: Earlier Drafts

Earlier drafts had discrepancies with the code. All are resolved in v17 (see
`AUDIT_REPORT.md` for the audit trail):

| Earlier discrepancy | Resolution in v17 |
|---|---|
| 6 techniques described, 7 in code | §III-C lists all 7; Table III covers all 7 |
| Signature single-split values copied from CV means | Table II uses the single-split values (0.7467 / 0.7563) |
| Table I raw values and SDs from a different run | Table I from the reference run only |
| Double canonicalization of the normalizing signature (B1) | Fixed; §III-B describes the single pass |
| Latency hardware described inconsistently | §III-E states what the environment record contains |

## 4. Open Items (stated as limitations in the paper)

| Item | Paper location |
|---|---|
| Benign data template-generated; independent benchmark (CSIC 2010 [11]) not evaluated | §V |
| Obfuscated-input per-sample predictions not exported | §III-E, §V |
| SQLi oracle inconclusive (failed positive controls); no browser execution for XSS | §IV-E |
| No end-to-end proxy throughput or sustained-load memory benchmark | §III-E, §V |
| Physical CPU model and memory not recorded for the reference run | §III-E |
