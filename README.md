# SQLi/XSS Detector — sqlixss-detector

Replication package for the ICITDA 2026 paper
**"Evaluating Input Canonicalization for SQLi and XSS Detection Using Lightweight Machine Learning"**

> Ahsani Taufiq Khawarizmi · Yudi Prayudi  
> Universitas Islam Indonesia, Yogyakarta

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Download corpus (307 SQLi + 135 XSS from InfoSecWarrior/Offensive-Payloads)
python scripts/00_download_payloads.py

# 3. Build group-aware 749/263 split (seed 42)
python scripts/01c_build_grouped_dataset.py

# 4. Train models
python scripts/02_train_models.py

# 5. Run the definitive experiment — reproduces all paper tables
python scripts/definitive_experiment.py --seed 42 --folds 5 --repeats 3
```

Results land in `results/definitive_<timestamp>_42/`.
Reference run: `results/definitive_20260923T145813Z_42/`

---

## Repository Structure

```
data/
  raw/          ← downloaded corpus (00_download_payloads.py)
  processed/    ← split CSVs (01c_build_grouped_dataset.py)
models/         ← trained joblib files (02_train_models.py)
results/
  definitive_20260923T145813Z_42/   ← authoritative run
    manifest.json           experiment metadata + technique list
    single_split.json       Tables II & V (263-sample split)
    fold_scores.json        15×8 fold-level F1 (Tables I & III)
    cv_stats.json           CV means, SDs, CIs, NB-corrected p-values
    full_statistics.json    complete stats: mean_diff, SD, SE, t, df, p_raw, p_holm
    per_technique.csv       Table IV (7 techniques, 5 seeds)
    predictions.csv         per-prediction audit trail
    tables.md               all 5 paper tables in Markdown
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
    test_end_to_end.py          37 passed, 5 xfailed (documented FP edge cases)
AUDIT_REPORT.md             full audit findings
```

---

## Paper Numbers

All numbers below come from `results/definitive_20260923T145813Z_42/`.

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
- Live WAF benchmark (E7) not completed (aiohttp not installed on WAF VM)
- No independent benchmark (CSIC 2010) yet integrated

---

## Reproduce from Scratch

```bash
git clone https://github.com/1337strike/sqlixss-detector
cd sqlixss-detector
pip install -r requirements.txt
python scripts/00_download_payloads.py
python scripts/01c_build_grouped_dataset.py
python scripts/definitive_experiment.py --seed 42 --folds 5 --repeats 3
python -m pytest tests/ -q   # 70 passed, 5 xfailed
```

Experiment ID: `definitive_20260923T145813Z_42`  
Head commit at reference run: `ff88291`
