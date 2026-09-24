# Experiment Tables
run_id: `definitive_20260923T233531Z_42`

## Table I — Canonicalization Effects on Obfuscated F1

| Detector | Raw F1±SD | Canon F1±SD | Gain | p_holm | sig_005 | triangle_ok | sd_diff |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Logistic Regression | 0.790514±0.039389 | 0.993404±0.006777 | +0.203 | 3.40e-07 | ✓ | ✓ | 0.0358 |
| Naive Bayes | 0.812117±0.037975 | 0.983776±0.010128 | +0.172 | 1.64e-06 | ✓ | ✓ | 0.035283 |
| Svm | 0.859188±0.038081 | 0.991925±0.007704 | +0.133 | 1.30e-05 | ✓ | ✓ | 0.036041 |
| Signature | 0.589255±0.105917 | 0.84198±0.07227 | +0.253 | 1.64e-06 | ✓ | ✓ | 0.052281 |

## Table II — Single-Split Performance

| Detector | Clean_Acc | Clean_F1 | Obf_Acc | Obf_F1 | Drop | Lat_p95_ms |
| --- | --- | --- | --- | --- | --- | --- |
| logistic_regression_raw | 1.0 | 1.0 | 0.912548 | 0.78949 | 0.21051 |  |
| logistic_regression_normalized | 1.0 | 1.0 | 0.996198 | 0.993052 | 0.006948 |  |
| naive_bayes_raw | 0.992395 | 0.993701 | 0.904943 | 0.795001 | 0.1987 |  |
| naive_bayes_normalized | 0.992395 | 0.993701 | 0.988593 | 0.986754 | 0.006947 |  |
| svm_raw | 1.0 | 1.0 | 0.927757 | 0.83688 | 0.16312 |  |
| svm_normalized | 1.0 | 1.0 | 0.996198 | 0.993052 | 0.006948 |  |
| signature_raw | 0.771863 | 0.746711 | 0.657795 | 0.492751 | 0.25396 |  |
| signature_normalized | 0.779468 | 0.756342 | 0.775665 | 0.751558 | 0.004784 |  |

## Table III — CV Canonicalized

| Detector | F1_clean | F1_obf | 95CI_obf | Drop |
| --- | --- | --- | --- | --- |
| Logistic Regression | 0.993684±0.006967 | 0.993404±0.006777 | [0.989651,0.997156] | 0.000281 |
| Naive Bayes | 0.984344±0.009685 | 0.983776±0.010128 | [0.978168,0.989385] | 0.000568 |
| Svm | 0.991925±0.007704 | 0.991925±0.007704 | [0.987659,0.996192] | 0.0 |
| Signature | 0.845959±0.071199 | 0.84198±0.07227 | [0.801958,0.882002] | 0.003979 |