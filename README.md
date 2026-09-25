# SQLi/XSS Detector — sqlixss-detector

**"Evaluating Input Canonicalization for SQLi and XSS Detection Using Lightweight Machine Learning"**

> Ahsani Taufiq Khawarizmi · 

---

## Quick Start

```bash
# 1. Install the pinned paper environment (Python 3.12)
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.lock

# 2. Corpus (307 SQLi + 135 XSS from InfoSecWarrior/Offensive-Payloads) is
#    committed in data/raw/. Optional re-download, pinned to the paper's
#    upstream commit and SHA-256-verified:
python scripts/00_download_payloads.py

# 3. Build group-aware 749/263 split (seed 42)
python scripts/01c_build_grouped_dataset.py

# 4. Train models
python scripts/02_train_models.py

# 5. Run the definitive experiment — reproduces all paper tables
python scripts/definitive_experiment.py --seed 42 --folds 5 --repeats 3
```

Results land in `results/definitive_<timestamp>_42/`.
Reference run: `results/definitive_20260923T094339Z_42/` (see its `NOTE.md`)

---

## Repository Structure

```
data/
  raw/          ← downloaded corpus (00_download_payloads.py)
  processed/    ← split CSVs (01c_build_grouped_dataset.py)
models/         ← trained joblib files (02_train_models.py)
results/
  definitive_20260923T094339Z_42/   ← authoritative run (paper §III-E)
    NOTE.md                 how to read this run's files; bit-exact reproduction
    manifest.json           experiment metadata + technique list
    single_split.json       Tables II & V (263-sample split, confusion matrices, timing)
    fold_scores.json        240 fold-level F1 scores: 8 configs × 15 folds × 2 (Tables I & IV)
    full_statistics.json    Table I statistics at full precision (authoritative)
    cv_stats.json           CV means/SDs; tests from rounded inputs (see NOTE.md)
    per_technique.csv       Table III (7 techniques, 5 seeds)
    predictions.csv         per-sample clean ML predictions
    tables.md               paper tables in Markdown
  semantic_validation_clean.json    §IV-E SQLi oracle, before obfuscation
  semantic_validation_obf.json      §IV-E SQLi oracle, after obfuscation
docs/
  paper_method_mapping.md   every §III claim → code location → status
  paper_reconciliation.md   every table value → actual vs paper → diff
  latex_tables.tex          copy-paste LaTeX for paper/thesis
src/
  baseline_normalized.py    canonicalization pipeline + normalizing signature
  baseline_signature.py     11 SQLi + 8 XSS regex rules
  dataset.py                benign template generator
  features.py               TF-IDF build_vectorizer()
  models.py                 LR / MNB / SVM pipelines
  obfuscation.py            7 transformation techniques
  statistics.py             Nadeau-Bengio t-test + Holm correction
  tokenizer.py              security-aware tokenizer
scripts/
  definitive_experiment.py  ← MAIN: reproduces all paper tables
  00_download_payloads.py
  01c_build_grouped_dataset.py
  02_train_models.py
  03_evaluate_offline.py
  05_run_waf.py             reverse-proxy WAF
tests/
  test_pipeline_regression.py   G1/M2 canonicalization + vocabulary isolation
  test_split_integrity.py       G4 family leakage checks
  integration/
    test_end_to_end.py          pipeline + WAF extraction path; FP edge cases are xfail
AUDIT_REPORT.md             full audit findings
```

---

## Paper Numbers

All numbers below come from `results/definitive_20260923T094339Z_42/`.

### Table I — Canonicalization Effect (CV, 15 fits)

| Detector | Raw obf. F1 | Canon. obf. F1 | Gain | p_Holm |
|---|---|---|---|---|
| LR  | 0.7905 ± 0.0394 | 0.9934 ± 0.0068 | +0.2029 | 3.42×10⁻⁷ |
| MNB | 0.8121 ± 0.0380 | 0.9838 ± 0.0101 | +0.1717 | 1.65×10⁻⁶ |
| SVM | 0.8592 ± 0.0381 | 0.9919 ± 0.0077 | +0.1327 | 1.30×10⁻⁵ |
| Sig | 0.5893 ± 0.1059 | 0.8420 ± 0.0723 | +0.2527 | 1.65×10⁻⁶ |

### Table II — Single Split (n=263)

| Config | Clean F1 | Obf F1 | FN | Cross |
|---|---|---|---|---|
| LR (raw) | 1.0000 | 0.7895 | 0 | 23 |
| LR (canon.) | 1.0000 | 0.9931 | 0 | 1 |
| MNB (raw) | 0.9937 | 0.7950 | 8 | 17 |
| MNB (canon.) | 0.9937 | 0.9868 | 2 | 1 |
| SVM (raw) | 1.0000 | 0.8369 | 0 | 19 |
| SVM (canon.) | 1.0000 | 0.9931 | 0 | 1 |
| Sig (raw) | 0.7467 | 0.4928 | 90 | 0 |
| Sig (canon.) | 0.7563 | 0.7516 | 59 | 0 |

---

## Known Limitations

- Benign corpus from narrow templates; 5 edge-case inputs (apostrophe, SQL tutorial text, HTML) produce false positives outside the test set (documented as `xfailed` tests)
- 7 obfuscation techniques in code; paper covers all 7 including `partial_url_encode`
- SQLi oracle limited to single equality-template context
- No end-to-end proxy benchmark (throughput, sustained-load memory) yet
- CSIC 2010 is evaluated for false positives only (36,000 normal requests, classifier level):
  `scripts/00b_fetch_csic2010.py` + `scripts/supplementary_csic.py`, results in
  `results/supplementary_20260925T122826Z/`, write-up in `docs/supplementary_csic2010_IV-F.md`.
  LR/SVM label empty input (20,000 parameterless GETs) as SQLi; no CSIC attack-traffic evaluation yet

---

## Reproduce from Scratch

```bash
git clone --branch v1.1.0 https://github.com/1337strike/sqlixss-detector
cd sqlixss-detector
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.lock
python scripts/01c_build_grouped_dataset.py
python scripts/definitive_experiment.py --seed 42 --folds 5 --repeats 3
python -m pytest tests/ -q   # all pass; documented FP edge cases report as xfailed
```

With `requirements.lock` (Python 3.12.3, scikit-learn 1.8.0, NumPy 2.4.4,
SciPy 1.17.1), the run reproduces the reference run **bit-for-bit**: all 240
fold-level F1 scores, 16 single-split confusion matrices and 35 per-technique
drops are identical. Latency (Table V) is wall-clock and varies by machine.

- Experiment ID: `definitive_20260923T094339Z_42`
- Citable snapshot: release tag **`v1.1.0`**. The commit that originally
  produced the run (`ff88291`) was never pushed; `v1.1.0` reproduces it exactly.
- Corpus: InfoSecWarrior/Offensive-Payloads @ `9e67029a`, SHA-256 in
  `data/raw/provenance.json`
