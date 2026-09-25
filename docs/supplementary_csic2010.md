# Supplementary: False Positives on Realistic Benign Traffic (CSIC 2010)

Source run: `results/supplementary_20260925T122826Z/` (produced by
`scripts/supplementary_csic.py`; data fetched by `scripts/00b_download_csic2010.py`).

## Table (from `csic2010_fpr.md`)

| Config | FP (n = 36,000) | FP rate | FP with params (n = 16,000) | FP rate with params | Empty input → |
|---|---:|---:|---:|---:|---|
| LR (raw)     | 20,000 | 55.56% |   0 | 0.00% | sqli |
| LR (canon.)  | 20,000 | 55.56% |   0 | 0.00% | sqli |
| MNB (raw)    |    112 |  0.31% | 112 | 0.70% | benign |
| MNB (canon.) |    116 |  0.32% | 116 | 0.73% | benign |
| SVM (raw)    | 20,000 | 55.56% |   0 | 0.00% | sqli |
| SVM (canon.) | 20,000 | 55.56% |   0 | 0.00% | sqli |
| Sig (raw)    |      0 |  0.00% |   0 | 0.00% | benign |
| Sig (canon.) |      0 |  0.00% |   0 | 0.00% | benign |

## Notes

- Data provenance: CSIC 2010 is fetched from the GitHub mirror
  `msudol/Web-Application-Attack-Datasets` at commit `424c6e1c`, SHA-256
  `f05dfc31…8385089`. The original host was not reliably reachable. The file
  has the documented 36,000 requests (28,000 GET, 8,000 POST).
- The 55.56% figure is a classifier-level artifact of empty input, not of
  benign parameter content. The run was not tuned in any way.
- Each flagged MNB input appears twice in CSIC (once as GET, once as POST),
  hence 56/58 distinct inputs behind 112/116 FPs. The full list is in
  `csic2010_fp_inputs.csv`.
