# Experiment Tables
run_id: `definitive_20260923T145813Z_42`

## Table I — Canonicalization Effects on Obfuscated F1

| Detector | Raw F1±SD | Canon F1±SD | Gain | p_holm | sig_005 | triangle_ok | sd_diff |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Logistic Regression | 0.7905±0.0394 | 0.9934±0.0068 | +0.203 | 3.40e-07 | ✓ | ✓ | 0.0358 |
| Naive Bayes | 0.8121±0.038 | 0.9838±0.0101 | +0.172 | 1.64e-06 | ✓ | ✓ | 0.0353 |
| Svm | 0.8592±0.0381 | 0.9919±0.0077 | +0.133 | 1.30e-05 | ✓ | ✓ | 0.036 |
| Signature | 0.5893±0.1059 | 0.842±0.0723 | +0.253 | 1.64e-06 | ✓ | ✓ | 0.0523 |

## Table II — Single-Split Performance

| Detector | Clean_Acc | Clean_F1 | Obf_Acc | Obf_F1 | Drop | Lat_p95_ms |
| --- | --- | --- | --- | --- | --- | --- |
| logistic_regression_raw | 1.0 | 1.0 | 0.912548 | 0.78949 | 0.21051 | 0.4386 |
| logistic_regression_normalized | 1.0 | 1.0 | 0.996198 | 0.993052 | 0.006948 | 0.4752 |
| naive_bayes_raw | 0.992395 | 0.993701 | 0.904943 | 0.795001 | 0.1987 | 0.4085 |
| naive_bayes_normalized | 0.992395 | 0.993701 | 0.988593 | 0.986754 | 0.006947 | 0.4612 |
| svm_raw | 1.0 | 1.0 | 0.927757 | 0.83688 | 0.16312 | 1.6979 |
| svm_normalized | 1.0 | 1.0 | 0.996198 | 0.993052 | 0.006948 | 1.6263 |
| signature_raw | 0.771863 | 0.746711 | 0.657795 | 0.492751 | 0.25396 | 0.0105 |
| signature_normalized | 0.779468 | 0.756342 | 0.775665 | 0.751558 | 0.004784 | 0.0193 |

## Table III — CV Canonicalized

| Detector | F1_clean | F1_obf | 95CI_obf | Drop |
| --- | --- | --- | --- | --- |
| Logistic Regression | 0.9937±0.007 | 0.9934±0.0068 | [0.9897,0.9972] | 0.0003 |
| Naive Bayes | 0.9843±0.0097 | 0.9838±0.0101 | [0.9782,0.9894] | 0.0006 |
| Svm | 0.9919±0.0077 | 0.9919±0.0077 | [0.9877,0.9962] | 0.0 |
| Signature | 0.846±0.0712 | 0.842±0.0723 | [0.802,0.882] | 0.004 |