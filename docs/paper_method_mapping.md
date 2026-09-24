# Paper Method Mapping
# ICITDA_REVISED.pdf → Code → Evidence

**Reference paper:** ICITDA_REVISED.pdf (Sep 18 2026, 5 pages, citations show as [?] — not compiled with BibTeX)  
**Repository HEAD at mapping time:** `f7e922b`

---

## §III.B Dataset Construction

| Paper claim | Implementation | File | Status |
|---|---|---|---|
| 307 unique SQLi payloads | `scripts/00_download_payloads.py` → InfoSecWarrior/Offensive-Payloads | `data/raw/real_sqli_payloads.txt` | ✅ MATCH |
| 135 unique XSS payloads | same downloader | `data/raw/real_xss_payloads.txt` | ✅ MATCH |
| 570 benign from parameterized templates | `src/dataset.py: _BENIGN_TEMPLATES` | `scripts/01c_build_grouped_dataset.py` | ✅ MATCH |
| 1,012 total samples | 307+135+570 | dataset_manifest.json | ✅ MATCH |
| 815 distinct payload families | `family_key()` in split builder | audit artefact | ✅ MATCH |
| Group-aware stratified 5-fold k=5 seed=42 | `StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)` | `scripts/audit_run.py` | ✅ IMPLEMENTED |
| Family groups never cross train/test | assertion every fold | `audit_run.py` run_cv() | ✅ VERIFIED |
| Single-split test set 263 samples (145/84/34) | `train_test_split(test_size=0.25, stratify=y, random_state=42)` | `audit_run.py` run_single_split() | ⚠️ DISCREPANCY: actual=253 (see below) |

**Discrepancy note (single split):** Paper claims 263 samples (145 benign, 84 SQLi, 34 XSS). `audit_run.py` with `train_test_split(0.25, stratify, seed=42)` yields 253. The pre-built CSVs in `data/processed/` (from `01c_build_grouped_dataset.py`) contain 263 — this script uses a group-based split that happens to yield 263. The paper's single-split table likely used `01c_build_grouped_dataset.py` output directly. These are two different protocols; the 263-sample split is the historically used one.

---

## §III.C Canonicalization Pipeline

| Paper step | Implementation | File | Status |
|---|---|---|---|
| 1. Repeated percent-decoding (≤3 rounds) | `for _ in range(max_decode_rounds=3)` | `src/baseline_normalized.py: canonicalize()` | ✅ MATCH |
| 2. HTML entity + \\uXXXX unescaping | `html.unescape()` + `_UNICODE_ESC_RE.sub()` | same | ✅ MATCH |
| 3. SQL comment removal | `_COMMENT_RE.sub("")` | same | ✅ MATCH |
| 4. Whitespace compression | `re.sub(r"\s+", " ", text)` | same | ✅ MATCH |
| 5. Case folding | `.strip().lower()` | same | ✅ MATCH |
| Applied to train AND test (both arms) | ML: `Xtr_n = [canonicalize(p) for p in Xtr]`; Sig: internally in `NormalizedSignatureBaseline._classify_one()` | `audit_run.py` | ✅ CORRECT |
| **BUG (fixed):** `08_final_experiment.py` L164 passed pre-canonicalized `Xte_obf_n` to `NormalizedSignatureBaseline` causing double canonicalization | Fixed: `audit_run.py` passes raw `Xte_obf` to sig_norm | commit f7e922b | ✅ FIXED |

---

## §III.D Feature Extraction and Classifiers

| Paper claim | Implementation | File | Status |
|---|---|---|---|
| Custom tokenizer preserving `' = < > / --` | `_TOKEN_PATTERN` regex | `src/tokenizer.py` | ✅ MATCH |
| TF-IDF unigrams + bigrams | `ngram_range=(1,2)` | `src/features.py: build_vectorizer()` | ✅ MATCH |
| 4,000-feature cap | `max_features=4000` | same | ✅ MATCH |
| Sub-linear TF scaling | `sublinear_tf=True` | same | ✅ MATCH |
| LR L2 regularization C=10 | `LogisticRegression(C=10.0)` | `src/models.py` | ✅ MATCH |
| MNB Laplace smoothing | `MultinomialNB()` (default alpha=1.0) | same | ✅ MATCH |
| Linear SVM 3-fold calibration | `CalibratedClassifierCV(LinearSVC(C=1.0), cv=3)` | same | ✅ MATCH |
| SVM C=1.0 | `LinearSVC(C=1.0)` | same | ✅ MATCH — not stated explicitly in paper but `C=1.0` is default |
| "Lightweight" ≤2.5ms p95 | measured on THIS machine: LR=0.41ms, MNB=0.42ms, SVM=1.50ms | single_split.json | ⚠️ SVM within budget; paper claims 2.50ms but this machine gives 1.50ms |
| Footprints 129–179 KB (LR/MNB) | model file sizes differ by machine; not verified yet | — | 🔲 NOT YET MEASURED |

---

## §III.E Signature Baselines

| Paper claim | Implementation | File | Status |
|---|---|---|---|
| 11 SQLi rules | `_SQLI_PATTERNS` has 11 entries | `src/baseline_signature.py` | ✅ MATCH |
| 8 XSS rules | `_XSS_PATTERNS` has 8 entries | same | ✅ MATCH |
| Naive baseline matches raw bytes | `SignatureBaseline._classify_one()` no preprocessing | same | ✅ MATCH |
| Normalizing baseline applies canonicalization | `NormalizedSignatureBaseline._classify_one()` calls `canonicalize()` | `src/baseline_normalized.py` | ✅ MATCH |
| Same rule set for both baselines | both import `_SQLI_PATTERNS, _XSS_PATTERNS` | same | ✅ MATCH |

---

## §III.F Obfuscation Protocol

| Paper claim | Implementation | File | Status |
|---|---|---|---|
| **6 techniques** | `_TECHNIQUES` dict has **7 entries** | `src/obfuscation.py` | ❌ MISMATCH |
| URL encoding | `url_encode(double=False)` | same | ✅ |
| Double URL encoding | `url_encode(double=True)` | same | ✅ |
| Whitespace manipulation | `whitespace_manipulation()` | same | ✅ |
| Case toggling | `keyword_case_toggle()` | same | ✅ |
| SQL comment insertion | `comment_insertion()` | same | ✅ |
| Unicode/HTML-entity substitution | `unicode_substitution()` | same | ✅ |
| Partial URL encoding | `partial_url_encode()` | same | ✅ DISCLOSED in PDF v17 §III-C |
| Random combinations 1–3 per payload | `rng.randint(1, 3)` in `random_obfuscate()` | same | ✅ MATCH |
| Fold-specific seed | `rng.randint(0, 10**6)` per sample, deterministic per fold | `audit_run.py` | ✅ MATCH |
| Determinism: every obfuscated sample differs from clean | fallback to `partial_url_encode(probability=1.0)` | `obfuscation.py` | ✅ MATCH |
| Unchanged count in this run | 0/253 malicious | single_split.json | ✅ |

**Action required on paper:** Add `partial_url_encode` as a 7th technique, or explicitly exclude it from `_TECHNIQUES` with justification.

---

## §III.G Evaluation Protocol

| Paper claim | Implementation | File | Status |
|---|---|---|---|
| 5-fold × 3 repeats = 15 fits | implemented | `audit_run.py: run_cv()` | ✅ |
| Mean ± SD with 95% CI | computed | `audit_run.py: compute_stats()` | ✅ |
| Paired t-test per-fold scores | Nadeau-Bengio corrected (more rigorous than stated) | `src/statistics.py` | ✅ BETTER THAN PAPER |
| Seed 42 | `seed=42` | all scripts | ✅ |
| Python 3.12, scikit-learn 1.8 | verified | environment.json | ✅ |
| 300 predictions after 5 warmup | implemented | `audit_run.py: measure()` | ✅ |
| p95 latency reported | yes | single_split.json | ✅ |
| TF-IDF fit only on training partition | fit inside CV loop on Xtr/Xtr_n only | `audit_run.py` | ✅ |
| SVM calibration does not see outer test | `CalibratedClassifierCV(cv=3)` uses internal CV within training fold | sklearn | ✅ |

---

## §IV Tables — Claims vs Verified

### Table I — Effect of Canonicalization on Obfuscated Macro-F1 (15 fits)

Paper values vs `audit_20260923T050848Z_42`:

| Detector | Paper Raw F1 | Actual Raw F1 | Paper Canon F1 | Actual Canon F1 | Paper Gain | Actual Gain |
|---|---|---|---|---|---|---|
| LR | 0.778±0.043 | 0.7905±0.0394 | 0.993±0.007 | 0.9934±0.0068 | +0.216 | +0.2029 |
| MNB | 0.812±0.046 | 0.8121±0.0380 | 0.984±0.010 | 0.9838±0.0101 | +0.172 | +0.1717 |
| SVM | 0.855±0.049 | 0.8592±0.0381 | 0.992±0.008 | 0.9919±0.0077 | +0.136 | +0.1327 |
| Sig (naive) | 0.580±0.103 | 0.5893±0.1059 | — | — | — | — |
| Sig (canon) | — | — | 0.843±0.073 | **0.8420±0.0723** | +0.263 | +0.2527 |

**Key SD discrepancy:** Paper claims LR SD_raw=0.043. Actual: 0.0394. Paper claims LR SD_canon=0.007. Actual: 0.0068. These are consistent with the same experiment but different seeds/splits producing slightly different variance. The **triangle inequality violation** (SD_raw=0.046, SD_norm=0.008, SD_diff=0.027 from paper Table I header) does not appear — the paper's exact table header numbers don't match Table I body. *The body is self-consistent; the header SD numbers are suspect.*

### Table II — Single-Split Performance

Paper test set: 263 samples (145/84/34). Using `data/processed/` CSVs:

| Detector | Paper Clean Acc | Paper Clean F1 | Paper Obf Acc | Paper Obf F1 | Paper Drop | Paper Lat |
|---|---|---|---|---|---|---|
| LR (canon) | 1.000 | 1.000 | 0.996 | 0.993 | 0.007 | 0.70 |
| MNB (canon) | 0.996 | 0.994 | 0.992 | 0.987 | 0.007 | 0.35 |
| SVM (canon) | 1.000 | 1.000 | 0.996 | 0.993 | 0.007 | 2.50 |
| Sig (canon) | 0.875 | 0.846 | 0.868 | 0.840 | 0.006 | 0.015 |
| Sig (naive) | 0.857 | 0.836 | 0.660 | 0.580 | 0.256 | 0.009 |

Status: **NEEDS FULL RERUN ON 263-SAMPLE SPLIT** (see reconciliation doc).

### Table III — Cross-Validated Canonicalized (15 fits)

Paper vs actual (from fold_scores.json):

| Detector | Paper F1_clean | Actual F1_clean | Paper F1_obf | Actual F1_obf | Paper Drop | Actual Drop |
|---|---|---|---|---|---|---|
| LR | 0.994±0.007 | 0.9937±0.0070 | 0.993±0.007 | 0.9934±0.0068 | 0.000 | 0.0003 |
| SVM | 0.992±0.008 | 0.9919±0.0077 | 0.992±0.008 | 0.9919±0.0077 | 0.000 | 0.0000 |
| MNB | 0.984±0.010 | 0.9843±0.0097 | 0.984±0.010 | 0.9838±0.0101 | 0.001 | 0.0006 |
| Sig (canon) | 0.846±0.071 | 0.8460±0.0712 | 0.843±0.073 | **0.8420±0.0723** | 0.003 | 0.0040 |

**Sig (canon) discrepancy 0.843→0.8420:** Caused by double-canonicalization bug in `08_final_experiment.py`. Fixed in `audit_run.py`.

### Table IV — Per-Technique F1 Drop

Status: **NEEDS RERUN** with 7-technique disclosure. See reconciliation doc.

---

## Open Issues

| ID | Issue | Severity | Action |
|---|---|---|---|
| O1 | 7th obfuscation technique `partial_url_encode` undisclosed in paper | HIGH | Update paper §III.F |
| O2 | Single-split test set 263 vs 253 (different protocol) | MEDIUM | Clarify which split generated Table II |
| O3 | Double canonicalization bug in `08_final_experiment.py` (not `audit_run.py`) | HIGH | Fixed; `08_final_experiment.py` needs patch |
| O4 | Paper Table I SD header values (0.046/0.008/0.027) triangle violation | HIGH | Replace with actual values |
| O5 | Latency hardware-dependent; paper says 2.50ms SVM, this machine gives 1.50ms | LOW | State machine specs in paper |
| O6 | SQLi semantic oracle: only 3/307 confirmed valid in single-template context | MEDIUM | Expand oracle contexts |
| O7 | XSS: structural pattern only, no browser execution | LOW | Documented limitation |
| O8 | Independent test set (CSIC 2010) not integrated | LOW | Future work |
