# Supplementary: detection on an independent SQLi/XSS benchmark (HttpParamsDataset)

run_id: `supplementary_20260925T144247Z`

- Data: `Morzeux/HttpParamsDataset` @ `926670a7`, `payload_full.csv`, sha256 `a4e62ba13435ad3d…` (MIT). In scope: attack_type `sqli` (10,852, sqlmap) and `xss` (532, XSSYA + FuzzDB); upstream payloads are lowercase
- Paper corpus for overlap removal: 1,285 distinct strings (InfoSecWarrior SQLi + XSS files, train / test_clean / test_obfuscated payloads)
- Overlap removed (primary): SQLi 3 (exact 3), XSS 3 (exact 2), matched after case folding and whitespace collapsing
- Sensitivity: also remove `family_key` matches; SQLi 4, XSS 21 removed in total
- Models: retrained with `definitive_experiment.run_single_split` (n_train = 749, seed 42); all 16 single-split confusion matrices identical to `definitive_20260923T094339Z_42`
- Classifier level only (no WAF layers). Detection = predicted `sqli` or `xss`; correct class = predicted the item's own class. Nothing tuned
- Environment: Python 3.12.3, scikit-learn 1.8.0, NumPy 2.4.4, SciPy 1.17.1

## Primary: paper-corpus strings removed (SQLi n = 10,849, 8,427 families; XSS n = 529, 410 families)

| Config | Input | SQLi detection (n = 10,849) | 95% CI | SQLi correct class | 95% CI | XSS detection (n = 529) | 95% CI | XSS correct class | 95% CI |
|---|---|---:|---|---:|---|---:|---|---:|---|
| LR (raw) | raw | 99.68% | [99.55%, 99.77%] | 99.62% | [99.49%, 99.72%] | 99.62% | [98.63%, 99.90%] | 97.92% | [96.32%, 98.84%] |
| LR (canon.) | canonicalize(input) | 99.68% | [99.55%, 99.77%] | 99.62% | [99.49%, 99.72%] | 99.43% | [98.35%, 99.81%] | 97.54% | [95.84%, 98.56%] |
| MNB (raw) | raw | 99.98% | [99.93%, 99.99%] | 99.98% | [99.93%, 99.99%] | 100.00% | [99.28%, 100.00%] | 97.73% | [96.08%, 98.70%] |
| MNB (canon.) | canonicalize(input) | 99.98% | [99.93%, 99.99%] | 99.97% | [99.92%, 99.99%] | 100.00% | [99.28%, 100.00%] | 97.54% | [95.84%, 98.56%] |
| SVM (raw) | raw | 99.72% | [99.61%, 99.81%] | 99.63% | [99.50%, 99.73%] | 99.81% | [98.94%, 99.97%] | 98.30% | [96.80%, 99.10%] |
| SVM (canon.) | canonicalize(input) | 99.72% | [99.61%, 99.81%] | 99.67% | [99.54%, 99.76%] | 99.81% | [98.94%, 99.97%] | 98.30% | [96.80%, 99.10%] |
| Sig (raw) | raw | 75.78% | [74.96%, 76.57%] | 75.78% | [74.96%, 76.57%] | 77.32% | [73.56%, 80.68%] | 77.32% | [73.56%, 80.68%] |
| Sig (canon.) | raw; canonicalizes internally | 75.78% | [74.96%, 76.57%] | 75.78% | [74.96%, 76.57%] | 77.32% | [73.56%, 80.68%] | 77.32% | [73.56%, 80.68%] |

| Config | SQLi → benign / sqli / xss | XSS → benign / sqli / xss | SQLi det. / correct, family-weighted | XSS det. / correct, family-weighted |
|---|---|---|---|---|
| LR (raw) | 35 / 10,808 / 6 | 2 / 9 / 518 | 99.84% / 99.82% | 99.51% / 97.32% |
| LR (canon.) | 35 / 10,808 / 6 | 3 / 10 / 516 | 99.84% / 99.82% | 99.27% / 96.83% |
| MNB (raw) | 2 / 10,847 / 0 | 0 / 12 / 517 | 99.98% / 99.98% | 100.00% / 97.07% |
| MNB (canon.) | 2 / 10,846 / 1 | 0 / 13 / 516 | 99.98% / 99.96% | 100.00% / 96.83% |
| SVM (raw) | 30 / 10,809 / 10 | 1 / 8 / 520 | 99.90% / 99.87% | 99.76% / 97.80% |
| SVM (canon.) | 30 / 10,813 / 6 | 1 / 8 / 520 | 99.90% / 99.88% | 99.76% / 97.80% |
| Sig (raw) | 2,628 / 8,221 / 0 | 120 / 0 / 409 | 77.78% / 77.78% | 79.37% / 79.37% |
| Sig (canon.) | 2,628 / 8,221 / 0 | 120 / 0 / 409 | 77.78% / 77.78% | 79.37% / 79.37% |

## Benign control: HttpParamsDataset `norm` values (n = 19,304)

Same bare-value shape as the attack items (the paper's benign training samples are `k=v&k=v` strings). A configuration that flags most of these also flags most attacks regardless of content, so read its detection rate together with this row.

| Config | Flagged as attack | 95% CI | → SQLi | → XSS |
|---|---:|---|---:|---:|
| LR (raw) | 97.03% | [96.78%, 97.26%] | 18,730 | 1 |
| LR (canon.) | 97.53% | [97.30%, 97.74%] | 18,826 | 1 |
| MNB (raw) | 6.18% | [5.85%, 6.53%] | 1,190 | 3 |
| MNB (canon.) | 6.28% | [5.94%, 6.63%] | 1,209 | 3 |
| SVM (raw) | 96.91% | [96.66%, 97.15%] | 18,703 | 5 |
| SVM (canon.) | 97.16% | [96.91%, 97.38%] | 18,753 | 2 |
| Sig (raw) | 0.00% | [0.00%, 0.02%] | 0 | 0 |
| Sig (canon.) | 0.00% | [0.00%, 0.02%] | 0 | 0 |

## Sensitivity: family_key matches also removed (SQLi n = 10,848, XSS n = 511)

| Config | Input | SQLi detection (n = 10,848) | 95% CI | SQLi correct class | 95% CI | XSS detection (n = 511) | 95% CI | XSS correct class | 95% CI |
|---|---|---:|---|---:|---|---:|---|---:|---|
| LR (raw) | raw | 99.68% | [99.55%, 99.77%] | 99.62% | [99.49%, 99.72%] | 99.61% | [98.58%, 99.89%] | 97.85% | [96.19%, 98.79%] |
| LR (canon.) | canonicalize(input) | 99.68% | [99.55%, 99.77%] | 99.62% | [99.49%, 99.72%] | 99.41% | [98.29%, 99.80%] | 97.46% | [95.70%, 98.51%] |
| MNB (raw) | raw | 99.99% | [99.95%, 100.00%] | 99.99% | [99.95%, 100.00%] | 100.00% | [99.25%, 100.00%] | 97.65% | [95.94%, 98.65%] |
| MNB (canon.) | canonicalize(input) | 99.99% | [99.95%, 100.00%] | 99.98% | [99.93%, 99.99%] | 100.00% | [99.25%, 100.00%] | 97.46% | [95.70%, 98.51%] |
| SVM (raw) | raw | 99.72% | [99.61%, 99.81%] | 99.63% | [99.50%, 99.73%] | 99.80% | [98.90%, 99.97%] | 98.24% | [96.69%, 99.07%] |
| SVM (canon.) | canonicalize(input) | 99.72% | [99.61%, 99.81%] | 99.67% | [99.54%, 99.76%] | 99.80% | [98.90%, 99.97%] | 98.24% | [96.69%, 99.07%] |
| Sig (raw) | raw | 75.78% | [74.97%, 76.58%] | 75.78% | [74.97%, 76.58%] | 77.69% | [73.88%, 81.09%] | 77.69% | [73.88%, 81.09%] |
| Sig (canon.) | raw; canonicalizes internally | 75.78% | [74.97%, 76.58%] | 75.78% | [74.97%, 76.58%] | 77.69% | [73.88%, 81.09%] | 77.69% | [73.88%, 81.09%] |
