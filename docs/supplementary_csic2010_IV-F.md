# §IV-F — False Positives on Realistic Benign Traffic (CSIC 2010)

Source run: `results/supplementary_20260925T122826Z/` (produced by
`scripts/supplementary_csic.py`; data fetched by `scripts/00b_download_csic2010.py`).

## Paragraph for the paper

**F. False Positives on Realistic Benign Traffic.** To test the benign class
beyond our templates, we ran the eight configurations, retrained with the
paper's single-split code (749 training samples, seed 42), on the 36,000
requests in the CSIC 2010 normal test set (`normalTrafficTest.txt`). Before
the evaluation we confirmed that all 16 single-split confusion matrices were
identical to the reference run. We tested each classifier on its own, with no
WAF layers. The input was the query string for GET requests and the body for
POST requests, exactly as sent (percent-encoded). 20,000 of the 36,000
requests (all GET) had no parameters, so their input was the empty string.
LR and SVM, raw and canonicalized, labelled every empty input as SQLi: an
all-zero TF-IDF vector leaves only the learned intercepts, and these favour
SQLi. This gives an FP rate of 55.56% over all 36,000 requests. On the 16,000
requests with parameters, the same four configurations produced no false
positives (0/16,000; 95% Wilson upper bound 0.024%). MNB labelled empty input
as benign. It produced 112 false positives raw and 116 canonicalized, all
labelled SQLi: 0.31% and 0.32% of all requests, or 0.70% and 0.73% of the
requests with parameters. Most of these were login forms (`modo=entrar`) whose
passwords are random strings of letters and digits. Both signature baselines
produced no false positives (0/36,000; upper bound 0.011%). Canonicalization
therefore added essentially no false positives on this traffic (MNB +4, all
others +0). The dominant false-positive source for LR and SVM is empty input,
which a deployment must route around the classifier, as our WAF does by
abstaining when an input shares no token with the vocabulary.

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

## Notes for the revision

- Data provenance: CSIC 2010 is fetched from the GitHub mirror
  `msudol/Web-Application-Attack-Datasets` at commit `424c6e1c`, SHA-256
  `f05dfc31…8385089`. The original host was not reliably reachable. The file
  has the documented 36,000 requests (28,000 GET, 8,000 POST).
- The 55.56% figure is a classifier-level artifact of empty input, not of
  benign parameter content. Both views are reported above so the paper can
  state either. The run was not tuned in any way.
- Each flagged MNB input appears twice in CSIC (once as GET, once as POST),
  hence 56/58 distinct inputs behind 112/116 FPs. The full list is in
  `csic2010_fp_inputs.csv`.
