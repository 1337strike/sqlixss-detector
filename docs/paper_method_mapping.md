# Paper Method Mapping
# PDF v17 → Code → Evidence

**Paper:** "Evaluating Input Canonicalization for SQLi and XSS Detection Using
Lightweight Machine Learning" (ICITDA 2026), revision PDF v17.
**Reference run:** `results/definitive_20260923T094339Z_42/` (paper §III-E).
**Automated check:** `scripts/verify_reference_run.py` (run by CI on every push)
compares a fresh run against the reference run and against the values printed
in the paper.

Section numbers follow PDF v17. For the numbers themselves, see
`docs/paper_reconciliation.md`.

---

## §III-A Experimental Design and Data

| Paper claim | Implementation | Evidence | Status |
|---|---|---|---|
| 8 configurations: LR, MNB, SVM, signature × raw / canonicalized | `run_single_split()`, `run_cv()` | `scripts/definitive_experiment.py` | ✅ |
| 307 SQLi + 135 XSS from InfoSecWarrior/Offensive-Payloads [8] | download pinned to upstream commit `9e67029a`, SHA-256 checked | `scripts/00_download_payloads.py`, `data/raw/provenance.json` | ✅ |
| 570 benign strings from parameterized query templates | `_BENIGN_TEMPLATES` | `src/dataset.py` | ✅ |
| Duplicates removed, shuffle with seed 42 | de-duplication in downloader; `df.sample(random_state=seed)` | `00_download_payloads.py`, `definitive_experiment.py` | ✅ |
| 1,012 sample IDs, 815 heuristic families | `family_key()`: digits→N, quoted literals→placeholder, whitespace collapsed, lowercased | `predictions.csv` (1,012 IDs / 815 families) | ✅ |
| Stratified group-aware 5-fold CV × 3, split seeds 42/43/44 | `StratifiedGroupKFold(shuffle=True, random_state=seed+rep)` | `fold_scores.json: fold_meta` | ✅ |
| Mean train/test sizes 809.6 / 202.4 | from fold sizes | `fold_scores.json` | ✅ |
| Script asserts disjoint train/test families | `assert not overlap` per fold | `definitive_experiment.py` | ✅ |
| No family shared between test folds within a repetition | exported IDs | `predictions.csv` (checked: 0 families span >1 test fold) | ✅ |
| Supplementary 749/263 split: test 145/84/34, train 425/223/101 | group-aware builder | `scripts/01c_build_grouped_dataset.py`, `single_split.json` | ✅ |
| No payload string or family shared between 749 and 263 | leakage tests | `tests/test_split_integrity.py` (CI) | ✅ |

## §III-B Canonicalization and Detector Configuration

| Paper claim | Implementation | Evidence | Status |
|---|---|---|---|
| (1) percent-decoding to a fixed point, ≤3 rounds | `for _ in range(max_decode_rounds=3)` | `src/baseline_normalized.py: canonicalize()` | ✅ |
| (2) HTML entity and Unicode-escape decoding | `html.unescape()`, `_UNICODE_ESC_RE` | same | ✅ |
| (3) SQL comment removal | `_COMMENT_RE.sub("")` | same | ✅ |
| (4) whitespace compression, (5) lowercasing | `re.sub(r"\s+", " ")`, `.lower()` | same | ✅ |
| Learned canonicalized configs: train and test transformed before vectorization | `Xtr_n`, `Xc_n`, `Xo_n` | `definitive_experiment.py` | ✅ |
| Normalizing signature receives raw strings, canonicalizes once | `NormalizedSignatureBaseline._classify_one()` | `src/baseline_normalized.py` | ✅ (double-canonicalization bug of `08_final_experiment.py` fixed; see `AUDIT_REPORT.md` B1) |
| 11 SQLi + 8 XSS regular expressions, same for both signature baselines | `_SQLI_PATTERNS`, `_XSS_PATTERNS` | `src/baseline_signature.py` | ✅ (WAF-only rules live in separate `WAF_EXTRA_*` lists and are never used by the experiment) |
| Custom tokenizer retaining security-relevant punctuation | `_TOKEN_PATTERN` | `src/tokenizer.py` | ✅ |
| TF-IDF uni+bigrams, 4,000 features, sublinear TF | `build_vectorizer()` | `src/features.py` | ✅ |
| LR L2, C = 10; MNB Laplace smoothing; SVM linear, C = 1, 3-fold calibration | `get_model_definitions()` | `src/models.py` | ✅ |
| Models fitted inside each outer training fold | pipelines fitted per fold | `run_cv()` | ✅ |

## §III-C Obfuscation Protocol

| Paper claim | Implementation | Evidence | Status |
|---|---|---|---|
| Seven transformations (incl. partial URL encoding) | `_TECHNIQUES` (7 entries) | `src/obfuscation.py` | ✅ |
| Only malicious test strings transformed | obfuscation applied to attack rows of the test fold | `run_cv()`, `run_single_split()` | ✅ |
| Aggregate: 1–3 operations; fold seed 42 + 1000·j, per-sample seed drawn from it | `random.Random(seed + fold_id * 1000)` | `run_cv()` | ✅ |
| Per-technique: supplementary split, seeds 42 + 1000·s, s = 0..4 | `seed_offset=s*1000` | `run_per_technique()` | ✅ |
| Transformation exception → original string retained; no exception counter | as described | `src/obfuscation.py` | ✅ (limitation stated in paper) |
| Zero unchanged malicious strings out of 118 (supplementary) | `unchanged_malicious` | `single_split.json` | ✅ |

## §III-D Metrics and Statistical Comparisons

| Paper claim | Implementation | Evidence | Status |
|---|---|---|---|
| Macro-F1 over benign/SQLi/XSS; per-class analysis from confusion matrices | `full_metrics()` | `single_split.json` | ✅ |
| Malicious-to-benign vs. cross-attack errors reported separately | `errors` dict | `single_split.json`, Table II | ✅ |
| Eq. (1) corrected SE, n = 15, correction factor ≈ 0.316667 | `1/n + n_test_mean/n_train_mean` | `scripts/export_statistics.py` → `full_statistics.json` | ✅ |
| Sample variance, two-sided tests, df = 14, Holm across 4 comparisons | `corrected_test()`, `holm_correct()` | `export_statistics.py`, `src/statistics.py` | ✅ |
| Unadjusted 95% CI of gain, d̄ ± t(0.975,14)·SE_c (Table I) | `ci95_gain` | `full_statistics.json` | ✅ generated automatically |
| Exploratory pairwise tests of canonicalized ML models, separate Holm family of 3 (§IV-B) | `pairwise_canonicalized_ml` | `full_statistics.json` | ✅ generated automatically |

## §III-E Timing and Evidence Traceability

| Paper claim | Implementation | Evidence | Status |
|---|---|---|---|
| All classification results from `definitive_20260923T094339Z_42` | archived run folder | `results/definitive_20260923T094339Z_42/` | ✅ |
| Environment: Python 3.12.3, scikit-learn 1.8.0, NumPy 2.4.4, SciPy 1.17.1, 1 logical CPU; CPU model/RAM not recorded | `env_info()` | `environment.json` | ✅ (pinned in `requirements.lock`) |
| 5 warm-up calls, then one predict per sample for 263 clean inputs | `measure_latency()` | `single_split.json: latency` | ✅ |
| Canonicalization outside timing for canonicalized ML, inside for normalizing signature | as described | `run_single_split()` | ✅ |
| 240 fold-level F1 scores reproduce from `fold_scores.json` | 8 configs × 15 folds × 2 conditions | `verify_reference_run.py` (CI) | ✅ bit-exact |
| 16 single-split confusion matrices reproduce reported metrics | confusion matrices | `verify_reference_run.py` (CI) | ✅ identical |
| Per-sample predictions exported for clean ML configurations only | `predictions.csv` | reference run | ✅ (limitation stated in paper) |
| Repository identified in [10] | citable snapshot: release tag `v1.1.0` (commit `4b45d4a`) | `README.md` | ✅ once the release is published |

## §IV-E Semantic Validity and WAF Prototype

| Paper claim | Implementation | Evidence | Status |
|---|---|---|---|
| SQLi oracle, 84 test strings, single SQLite login-query context: 66 baseline / 16 syntax errors / 2 other errors, before and after obfuscation | `oracle_sqli()` | `results/semantic_validation_clean.json`, `results/semantic_validation_obf.json` | ✅ |
| Failed positive-control checks; outcomes treated as inconclusive | audit oracle controls | `results/audit/audit_20260923T050848Z_42_semantic_validation.json` | ✅ |
| XSS pattern matching is not a browser-execution test | static oracle | `scripts/validate_semantics.py` | ✅ (limitation stated) |
| Prototype: payload inspection, scanner fingerprinting, path checks, header handling, shared rate limiting | proxy | `src/waf_proxy.py`, `src/recon_detection.py`, `src/rate_limiter.py` | ✅ (the deployment layers added after the reference run, listed in README "Real-World Deployment", are not part of the paper's evaluation) |

---

## Resolved Issues From Earlier Drafts

All issues raised against earlier drafts are resolved in PDF v17 or the
repository. Details are in `AUDIT_REPORT.md` and `docs/paper_reconciliation.md` §3.

| Earlier issue | Resolution |
|---|---|
| 7th technique (`partial_url_encode`) undisclosed | Disclosed in §III-C; included in Table III |
| Double canonicalization in `08_final_experiment.py` | Fixed in `definitive_experiment.py`; paper cites only the fixed run |
| Table I SD values from a different run (triangle violation) | Table I now from the reference run; triangle check passes for all rows |
| Single-split protocol ambiguity (263 vs 253 samples) | §III-A names the group-aware 749/263 builder explicitly |
| Latency from undocumented hardware | §III-E states what the run's environment record does and does not contain |
| Independent benchmark (CSIC 2010) | Stated as future work (§V, ref. [11]); not part of the paper's evaluation |
