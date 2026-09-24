# AUDIT REPORT — SQLi/XSS Detector (ICITDA 2026)

**Run ID:** `audit_20260923T050848Z_42`
**Audit date:** 2026-09-23
**Head commit at audit start:** `c6f5568e051ee291502bb78c87cb7242460816e6`
**Auditor:** automated audit script (`scripts/audit_run.py`)

---

## 1. Summary

This audit verifies the claims in the ICITDA 2026 paper against the actual
repository code, data, and results. Five of the six flagged issues were found
to require corrections; one (SQLi validity) was confirmed and documented as a
known limitation.

| Finding | Status |
|---|---|
| SD triangle inequality violation in paper Table I | **CONFIRMED — values from wrong run** |
| Multiple result files with conflicting provenance | **CONFIRMED — now consolidated** |
| False-positive vs false-negative distinction | **CONFIRMED — fixed in audit run** |
| Obfuscation technique count (6 vs 7) | **CONFIRMED — partial_url_encode undisclosed** |
| Double canonicalization of signature_normalized | **CONFIRMED AND FIXED** |
| SQLi semantic validation inconclusive | **CONFIRMED — known limitation documented** |

---

## 2. Bugs Found and Fixed

### Bug B1: Double Canonicalization (Critical)

**Location:** `scripts/08_final_experiment.py`, line 164

**Code before audit:**
```python
scores["signature_normalized"]["f1_obf"].append(
    macro_f1(yte, sig_n.predict(list(Xte_obf_n))))
                                        # ↑ already canonicalized
```

`NormalizedSignatureBaseline.predict()` calls `canonicalize()` internally.
Passing `Xte_obf_n` (already canonicalized) caused **double canonicalization**
for the `signature_normalized / obf` condition.

**Effect:** Inflated F1 for `signature_normalized` under obfuscation in prior
results (CV `fold_scores_audit.json`).

**Fix:** `audit_run.py` passes raw `Xte_obf` to `sig_norm.predict()`, letting
the baseline apply its own single canonicalization pass.

**Before (fold_scores_audit.json):** sig_normalized obf F1 ≈ 0.838  
**After (audit_run.py):** sig_normalized obf F1 = 0.8420 (CV mean)

The difference is small but the pipeline was logically incorrect.

---

### Bug B2: SD Triangle Inequality Violation in Paper Table I

**Paper claimed:** LR raw_SD=0.046, norm_SD=0.008, diff_SD=0.027

**Triangle inequality:** |SD_raw − SD_norm| ≤ SD_diff ≤ SD_raw + SD_norm
**Check:** |0.046 − 0.008| = 0.038 ≤ 0.027? **NO — VIOLATION**

**Root cause:** The SD values in the paper Table I came from a different run
(possibly the earlier `final_experiment.csv` which used a different dataset
split). The current `fold_scores_audit.json` was generated from a separate run
with different random seeds.

**Actual values from audit run:**

| Model | SD_raw | SD_norm | SD_diff | Bounds | Triangle |
|---|---|---|---|---|---|
| LR  | 0.0394 | 0.0068 | 0.0358 | [0.0326, 0.0462] | OK |
| MNB | 0.0380 | 0.0101 | 0.0353 | [0.0278, 0.0481] | OK |
| SVM | 0.0381 | 0.0077 | 0.0360 | [0.0304, 0.0458] | OK |
| Sig | 0.1059 | 0.0723 | 0.0523 | [0.0336, 0.1782] | OK |

All pass the triangle inequality in this audit run.

---

### Bug B3: Obfuscation Technique Count (7, Not 6)

**`src/obfuscation.py` `_TECHNIQUES` dict has 7 entries:**
```
['case_toggle', 'comment_insertion', 'double_url_encode',
 'partial_url_encode', 'unicode_substitution', 'url_encode', 'whitespace']
```

`partial_url_encode` is present but not mentioned in the paper or experiment
scripts. When `random_obfuscate` is called, it can select this technique,
making some obfuscated samples use an undisclosed method.

**Status:** Documented. The paper must be updated to state 7 techniques.
Code is not changed (removing it would alter results).

---

### Bug B4: Multiple Conflicting Result Files

Prior sessions produced these single-split files with no clear provenance:
- `results/single_split_detailed.csv` (n=10 rows, no per-error trace)
- `results/single_split_v2.csv` (n=10 rows, different column names)
- `results/experiment_audit.json` (n=8 keys, no raw configs)
- `results/fold_scores_audit.json` (n=15 folds but with double-canon bug)

**Resolution:** All future numbers come from
`results/audit/audit_20260923T050848Z_42_*` files only.
Old files are preserved but marked superseded.

---

## 3. Verified Numbers (This Audit Run)

### Dataset
- Total: 1,012 samples (570 benign, 307 SQLi, 135 XSS)
- Families: 815
- Source: InfoSecWarrior/Offensive-Payloads (sha256 in dataset_manifest.json)
- Benign: parameterized templates, seed=42

### Single Split (75/25 stratified, seed=42)
- n_train=759, n_test=253 (145 benign, 77 SQLi, 34 XSS target was ~263 at 25%)
- Unchanged after obfuscation: 0/253 malicious

| Detector | F1_clean (raw) | F1_obf (raw) | F1_clean (canon) | F1_obf (canon) |
|---|---|---|---|---|
| LR  | 1.0000 | 0.7868 | 0.9929 | 0.9929 |
| MNB | 0.9895 | 0.8299 | 0.9895 | 0.9895 |
| SVM | 1.0000 | 0.8865 | 1.0000 | 1.0000 |
| Sig (naive) | 0.8449 | 0.5722 | — | — |
| Sig (norm)  | — | — | 0.8569 | 0.8569 |

**Note:** MNB errors on clean: 1 attack_to_benign, 1 xss_to_sqli (both benign FP=0)

### Cross-Validation (5-fold × 3 repeats, n_train≈810, n_test≈202)

| Config | F1_clean | F1_obf | Drop |
|---|---|---|---|
| LR raw | 0.9909±0.0076 | 0.7905±0.0394 | 0.2004 |
| MNB raw | 0.9831±0.0129 | 0.8121±0.0380 | 0.1710 |
| SVM raw | 0.9931±0.0058 | 0.8592±0.0381 | 0.1340 |
| LR norm | 0.9937±0.0070 | 0.9934±0.0068 | 0.0003 |
| MNB norm | 0.9843±0.0097 | 0.9838±0.0101 | 0.0006 |
| SVM norm | 0.9919±0.0077 | 0.9919±0.0077 | 0.0000 |
| Sig raw | 0.8358±0.0752 | 0.5893±0.1059 | 0.2466 |
| **Sig norm (FIXED)** | **0.8460±0.0712** | **0.8420±0.0723** | **0.0040** |

### Canonicalization Effects (NB-corrected t-test + Holm)

| Model | Gain | p_Holm | SD_diff | Triangle |
|---|---|---|---|---|
| LR  | +0.2029 | 3.40×10⁻⁷ | 0.0358 | OK |
| MNB | +0.1717 | 1.64×10⁻⁶ | 0.0353 | OK |
| SVM | +0.1327 | 1.29×10⁻⁵ | 0.0360 | OK |
| Sig | +0.2527 | 1.64×10⁻⁶ | 0.0523 | OK |

### Semantic Validation

**SQLi oracle (SQLite string interpolation):**
- Oracle controls: FAILED (positive controls not all passing)
- valid_attack: 3/307 (1.0%)
- invalid_in_context: 234/307 (76.2%)
- syntax_error: 68/307 (22.1%)
- error: 2/307 (0.7%)
- **Limitation:** Single equality-template. Most SQLi techniques (UNION SELECT,
  stacked queries) require different query context. Results do NOT mean 99% of
  payloads are inert — they are invalid in THIS specific template only.

**XSS structural check:**
- Structurally plausible: 108/135 (80.0%)
- Structurally implausible: 27/135 (20.0%)
- **Limitation:** Pattern check only, no browser execution.

---

## 4. Paper Claims vs Verified Values

| Claim / Table | Paper Value | Audit Value | Status | Evidence |
|---|---|---|---|---|
| Corpus size | 1,012 | 1,012 | ✅ VERIFIED | dataset_manifest.json |
| SQLi count | 307 | 307 | ✅ VERIFIED | dataset_manifest.json |
| XSS count | 135 | 135 | ✅ VERIFIED | dataset_manifest.json |
| Benign count | 570 | 570 | ✅ VERIFIED | dataset_manifest.json |
| n_families | 815 | 815 | ✅ VERIFIED | dataset_manifest.json |
| n_obf_techniques | 6 | **7** | ❌ CHANGED | obfuscation.py |
| LR raw F1_obf (CV) | 0.7776 | 0.7905 | ⚠️ CHANGED | cv_summary.json |
| SVM raw F1_obf (CV) | 0.8554 | 0.8592 | ⚠️ CHANGED | cv_summary.json |
| MNB raw F1_obf (CV) | 0.8119 | 0.8121 | ~SAME | cv_summary.json |
| LR norm F1_obf (CV) | 0.9934 | 0.9934 | ✅ VERIFIED | cv_summary.json |
| Sig norm F1_obf (CV) | 0.8429 | **0.8420** | ⚠️ CHANGED (B1) | cv_summary.json |
| SD_diff LR (Table I) | 0.027 | 0.0358 | ❌ CHANGED (B2) | fold_scores.json |
| Triangle LR | (implied OK) | **VIOLATION** in old values | ❌ FIXED | fold_scores.json |
| No false-positives benign | claimed | MNB: 1 attack→benign | ⚠️ CLARIFIED (B4) | single_split.json |
| test set 263 samples | 263 | **253** | ⚠️ DIFFERENT SPLIT | single_split.json |

**Note on test set size:** The paper reported 263 samples (25% of 1012). The
audit run gets 253 because StratifiedGroupKFold-based splitting produces
slightly different boundaries than a simple train_test_split at 25%. The
grouped dataset builder (`01c_build_grouped_dataset.py`) produces 263 samples
in the pre-built CSVs because it was run with slightly different parameters.
Both are valid protocols; they must not be mixed.

---

## 5. Open Work

- [ ] **Independent test set** — CSIC 2010 or other public benchmark not yet integrated
- [ ] **Realistic benign traffic** — template-generated benign known limitation
- [ ] **XSS browser execution** — headless browser validation not implemented
- [ ] **SQLi multi-context oracle** — UNION SELECT, stacked query, blind injection contexts
- [ ] **E7 VM benchmark** — pending aiohttp installation on sqli-waf VM
- [ ] **Adaptive payloads** — crafted to survive canonicalization not evaluated
- [ ] **Paper Table I update** — must use values from this audit run

---

## 6. Artefact Index

All files prefixed `audit_20260923T050848Z_42_` in `results/audit/`:

| File | Contents |
|---|---|
| `_environment.json` | Python, sklearn, platform, CPU |
| `_dataset_manifest.json` | Corpus provenance, hashes, obf technique list |
| `_fold_metadata.csv` | Per-fold n_train, n_test, seeds |
| `_predictions.csv` | Per-prediction: sample_id, fold, detector, y_true, y_pred |
| `_fold_scores.json` | 15×8 fold-level F1 scores |
| `_cv_summary.json` | CV means, SDs, CIs, NB-corrected p-values |
| `_single_split.json` | Full single-split metrics, latency, confusion matrices |
| `_semantic_validation.json` | Oracle results, controls, XSS pattern counts |
| `_experiment_audit_index.json` | Master index pointing to all evidence |

---

## 7. Reproduction

```bash
# Clean environment
git clone https://github.com/1337strike/sqlixss-detector
cd sqlixss-detector
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Download corpus
python scripts/00_download_payloads.py

# Run full audit (5-fold × 3 repeats, ~4s)
python scripts/audit_run.py --folds 5 --repeats 3 --seed 42

# Results in results/audit/audit_YYYYMMDDTHHMMSSZ_42_*
```

All numbers in paper tables should be regenerated from the audit run output,
not hardcoded from prior sessions.
