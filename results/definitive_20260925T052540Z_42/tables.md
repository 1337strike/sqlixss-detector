# Experiment Tables — PDF 17 Numbering
run_id: `definitive_20260925T052540Z_42`

> Table V latency from archived run `definitive_20260923T094339Z_42`


## Table I — Canonicalization Effects on Obfuscated F1 (CV)

| Detector | Raw F1±SD | Canon F1±SD | Gain | SD_diff | p_holm | triangle_ok |
| --- | --- | --- | --- | --- | --- | --- |
| Logistic Regression | 0.790514±0.039389 | 0.993404±0.006777 | +0.2029 | 0.0358 | 3.42e-07 | ✓ |
| Naive Bayes | 0.812117±0.037975 | 0.983776±0.010128 | +0.1717 | 0.035283 | 1.65e-06 | ✓ |
| Svm | 0.859188±0.038081 | 0.991925±0.007704 | +0.1327 | 0.036041 | 1.30e-05 | ✓ |
| Signature | 0.589255±0.105917 | 0.84198±0.07227 | +0.2527 | 0.052281 | 1.65e-06 | ✓ |

## Table II — Single-Split Results (n=263): FN and Cross errors

| Configuration | Clean_F1 | Obf_F1 | FN | Cross | Drop |
| --- | --- | --- | --- | --- | --- |
| logistic_regression_raw | 1.0 | 0.7895 | 0 | 23 | 0.21051 |
| logistic_regression_normalized | 1.0 | 0.9931 | 0 | 1 | 0.006948 |
| naive_bayes_raw | 0.9937 | 0.795 | 8 | 17 | 0.1987 |
| naive_bayes_normalized | 0.9937 | 0.9868 | 2 | 1 | 0.006947 |
| svm_raw | 1.0 | 0.8369 | 0 | 19 | 0.16312 |
| svm_normalized | 1.0 | 0.9931 | 0 | 1 | 0.006948 |
| signature_raw | 0.7467 | 0.4928 | 90 | 0 | 0.25396 |
| signature_normalized | 0.7563 | 0.7516 | 59 | 0 | 0.004784 |

## Table III — Per-Technique F1 Drop (Raw Input, 5 Seeds)

| Technique | Detector | F1_clean | F1_obf | F1_drop | in_paper |
| --- | --- | --- | --- | --- | --- |
| url_encoding | logistic_regression_raw | 1.0 | 0.7034 | 0.2966 | True |
| url_encoding | naive_bayes_raw | 0.9937 | 0.7729 | 0.2208 | True |
| url_encoding | svm_raw | 1.0 | 0.9322 | 0.0678 | True |
| url_encoding | signature_naive | 0.7467 | 0.4661 | 0.2806 | True |
| url_encoding | signature_normalized | 0.7563 | 0.7563 | 0.0 | True |
| double_url_encoding | logistic_regression_raw | 1.0 | 0.6113 | 0.3887 | True |
| double_url_encoding | naive_bayes_raw | 0.9937 | 0.6108 | 0.3829 | True |
| double_url_encoding | svm_raw | 1.0 | 0.6111 | 0.3889 | True |
| double_url_encoding | signature_naive | 0.7467 | 0.4661 | 0.2806 | True |
| double_url_encoding | signature_normalized | 0.7563 | 0.7563 | 0.0 | True |
| whitespace_manipulation | logistic_regression_raw | 1.0 | 1.0 | 0.0 | True |
| whitespace_manipulation | naive_bayes_raw | 0.9937 | 0.9937 | 0.0 | True |
| whitespace_manipulation | svm_raw | 1.0 | 1.0 | 0.0 | True |
| whitespace_manipulation | signature_naive | 0.7467 | 0.7349 | 0.0119 | True |
| whitespace_manipulation | signature_normalized | 0.7563 | 0.7484 | 0.0079 | True |
| case_toggling | logistic_regression_raw | 1.0 | 1.0 | 0.0 | True |
| case_toggling | naive_bayes_raw | 0.9937 | 0.9937 | 0.0 | True |
| case_toggling | svm_raw | 1.0 | 1.0 | 0.0 | True |
| case_toggling | signature_naive | 0.7467 | 0.7467 | 0.0 | True |
| case_toggling | signature_normalized | 0.7563 | 0.7563 | 0.0 | True |
| comment_insertion | logistic_regression_raw | 1.0 | 1.0 | 0.0 | True |
| comment_insertion | naive_bayes_raw | 0.9937 | 0.9937 | 0.0 | True |
| comment_insertion | svm_raw | 1.0 | 1.0 | 0.0 | True |
| comment_insertion | signature_naive | 0.7467 | 0.7418 | 0.0049 | True |
| comment_insertion | signature_normalized | 0.7563 | 0.7563 | 0.0 | True |
| unicode_substitution | logistic_regression_raw | 1.0 | 0.9436 | 0.0564 | True |
| unicode_substitution | naive_bayes_raw | 0.9937 | 0.9606 | 0.0331 | True |
| unicode_substitution | svm_raw | 1.0 | 0.9655 | 0.0345 | True |
| unicode_substitution | signature_naive | 0.7467 | 0.6239 | 0.1228 | True |
| unicode_substitution | signature_normalized | 0.7563 | 0.7563 | 0.0 | True |
| partial_url_encoding | logistic_regression_raw | 1.0 | 0.9749 | 0.0251 | True |
| partial_url_encoding | naive_bayes_raw | 0.9937 | 0.9641 | 0.0296 | True |
| partial_url_encoding | svm_raw | 1.0 | 0.9891 | 0.0109 | True |
| partial_url_encoding | signature_naive | 0.7467 | 0.6116 | 0.1351 | True |
| partial_url_encoding | signature_normalized | 0.7563 | 0.7563 | 0.0 | True |

## Table IV — Canonicalized Configurations (CV mean±SD)

| Detector | F1_clean | F1_obf | 95CI_obf | Drop |
| --- | --- | --- | --- | --- |
| Logistic Regression | 0.993684±0.006967 | 0.993404±0.006777 | [0.989651,0.997156] | 0.000281 |
| Naive Bayes | 0.984344±0.009685 | 0.983776±0.010128 | [0.978168,0.989385] | 0.000568 |
| Svm | 0.991925±0.007704 | 0.991925±0.007704 | [0.987659,0.996192] | 0.0 |
| Signature | 0.845959±0.071199 | 0.84198±0.07227 | [0.801958,0.882002] | 0.003979 |

## Table V — Latency (Archived Run 094339, Clean-Input, 263 Calls)

| Configuration | Calls | Median_ms_paper | p95_ms_paper | p99_ms_paper | p95_ms_this_run | source |
| --- | --- | --- | --- | --- | --- | --- |
| logistic_regression_normalized | 263 | 0.2731 | 0.3548 | 0.375 | 0.3224 | archived run definitive_20260923T094339Z_42 |
| naive_bayes_normalized | 263 | 0.2579 | 0.3242 | 0.3783 | 0.3183 | archived run definitive_20260923T094339Z_42 |
| svm_normalized | 263 | 1.2457 | 1.3864 | 1.5812 | 1.3881 | archived run definitive_20260923T094339Z_42 |
| signature_raw | 263 | 0.0046 | 0.0091 | 0.0167 | 0.009 | archived run definitive_20260923T094339Z_42 |
| signature_normalized | 263 | 0.0082 | 0.019 | 0.0323 | 0.017 | archived run definitive_20260923T094339Z_42 |