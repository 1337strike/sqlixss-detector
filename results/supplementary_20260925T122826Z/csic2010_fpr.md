# Supplementary: false positives on CSIC 2010 normal traffic

run_id: `supplementary_20260925T122826Z`

- Data: CSIC 2010 `normalTrafficTest.txt`, 36,000 benign requests (28,000 GET, 8,000 POST), sha256 `f05dfc312d5d14fd…`
- Input: GET query string / POST body, as on the wire (percent-encoded)
- Requests without parameters (empty input): 20,000 (GET 20,000); with parameters: 16,000; distinct inputs: 4,802
- Models: retrained with `definitive_experiment.run_single_split` (n_train = 749, seed 42); all 16 single-split confusion matrices identical to `definitive_20260923T094339Z_42`
- Classifier level only (no WAF layers); FP = prediction other than `benign`
- Environment: Python 3.12.3, scikit-learn 1.8.0, NumPy 2.4.4, SciPy 1.17.1

| Config | Input | FP (n = 36,000) | FP rate | 95% CI (Wilson) | → SQLi | → XSS | FP, with params (n = 16,000) | FP rate, with params | Empty input → |
|---|---|---:|---:|---|---:|---:|---:|---:|---|
| LR (raw) | raw | 20,000 | 55.56% | [55.04%, 56.07%] | 20,000 | 0 | 0 | 0.00% | sqli |
| LR (canon.) | canonicalize(input) | 20,000 | 55.56% | [55.04%, 56.07%] | 20,000 | 0 | 0 | 0.00% | sqli |
| MNB (raw) | raw | 112 | 0.31% | [0.26%, 0.37%] | 112 | 0 | 112 | 0.70% | benign |
| MNB (canon.) | canonicalize(input) | 116 | 0.32% | [0.27%, 0.39%] | 116 | 0 | 116 | 0.73% | benign |
| SVM (raw) | raw | 20,000 | 55.56% | [55.04%, 56.07%] | 20,000 | 0 | 0 | 0.00% | sqli |
| SVM (canon.) | canonicalize(input) | 20,000 | 55.56% | [55.04%, 56.07%] | 20,000 | 0 | 0 | 0.00% | sqli |
| Sig (raw) | raw | 0 | 0.00% | [0.00%, 0.01%] | 0 | 0 | 0 | 0.00% | benign |
| Sig (canon.) | raw; canonicalizes internally | 0 | 0.00% | [0.00%, 0.01%] | 0 | 0 | 0 | 0.00% | benign |
