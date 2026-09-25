# Supplementary: Detection on an Independent SQLi/XSS Benchmark (HttpParamsDataset)

Source run: `results/supplementary_20260925T144247Z/` (produced by
`scripts/supplementary_httpparams.py`; data fetched by `scripts/00c_download_httpparams.py`).

```bash
python3.12 -m venv .venv && .venv/bin/pip install -r requirements.lock
.venv/bin/python scripts/00c_download_httpparams.py      # pinned commit, SHA-256-verified
.venv/bin/python scripts/supplementary_httpparams.py
```

## Setup

| Item | Value |
|---|---|
| Benchmark | HttpParamsDataset, `Morzeux/HttpParamsDataset` @ `926670a710283f87c05b554680facf3f9530548c`, `payload_full.csv` (MIT) |
| SHA-256 | `a4e62ba13435ad3dd583c5790db2175629020fc41c56e1b26baa02a9ae45f03d` |
| In scope | `sqli` 10,852 (generated with sqlmap), `xss` 532 (XSSYA, FuzzDB). `cmdi` and `path-traversal` not used |
| Independence | None of its sources is InfoSecWarrior/Offensive-Payloads |
| Overlap removal (primary) | Drop items equal to any of the 1,285 distinct paper-corpus strings (InfoSecWarrior files + train/test_clean/test_obfuscated payloads) after case folding and whitespace collapsing: SQLi 3, XSS 3 (exact: 3 and 2) |
| Overlap removal (sensitivity) | Also drop items whose `family_key` matches a paper-corpus string: SQLi 4, XSS 21 in total |
| Models | Retrained with `definitive_experiment.run_single_split` (749 training samples, seed 42); all 16 confusion matrices asserted identical to `definitive_20260923T094339Z_42` before evaluation |
| Level | Classifier only, no WAF layers, nothing tuned |
| Environment | Python 3.12.3, `requirements.lock` (scikit-learn 1.8.0, NumPy 2.4.4, SciPy 1.17.1) |

Detection rate = share of class-c items predicted `sqli` or `xss`. Correct-class rate = share
predicted exactly c. Intervals are Wilson 95%.

## Results (primary: SQLi n = 10,849, XSS n = 529)

| Config | SQLi detection | SQLi correct class | XSS detection | XSS correct class | Benign control flagged (n = 19,304) |
|---|---:|---:|---:|---:|---:|
| LR (raw)     | 99.68% | 99.62% |  99.62% | 97.92% | 97.03% |
| LR (canon.)  | 99.68% | 99.62% |  99.43% | 97.54% | 97.53% |
| MNB (raw)    | 99.98% | 99.98% | 100.00% | 97.73% |  6.18% |
| MNB (canon.) | 99.98% | 99.97% | 100.00% | 97.54% |  6.28% |
| SVM (raw)    | 99.72% | 99.63% |  99.81% | 98.30% | 96.91% |
| SVM (canon.) | 99.72% | 99.67% |  99.81% | 98.30% | 97.16% |
| Sig (raw)    | 75.78% | 75.78% |  77.32% | 77.32% |  0.00% |
| Sig (canon.) | 75.78% | 75.78% |  77.32% | 77.32% |  0.00% |

Confidence intervals, prediction counts, family-weighted rates and the sensitivity table
are in `httpparams_detection.md` / `.json` of the run folder.
Per-item predictions for all 8 configurations are in `httpparams_predictions.csv`.

## Notes

- **Read the detection rates together with the benign control.** The `norm` rows of the same
  benchmark are CSIC 2010 parameter values (names, addresses, numbers). They have the same
  bare-value shape as the attack items. LR and SVM flag about 97% of them, almost all as SQLi.
  For these four configurations, the detection rate therefore does not show that attacks are
  separated from benign input. The paper's benign training samples are all `k=v&k=v` strings
  (`src/dataset.py`), and every attack sample is a bare payload. This matches the CSIC 2010
  finding (`docs/supplementary_csic2010.md`) that LR/SVM label empty input as SQLi.
  MNB flags 6.2–6.3% of benign values. The signature baselines flag none.
- Raw and canonicalized results are nearly identical, and identical for the signatures. The
  benchmark's payloads are plain (not percent- or entity-encoded, all lowercase). The paper's
  canonicalization targets encoding and obfuscation, so this benchmark does not exercise it.
  The tokenizer, `canonicalize()` and the signature regexes are all case-insensitive, so the
  upstream lowercasing does not affect predictions.
- sqlmap emits many variants of each template: 10,849 SQLi items form 8,427 `family_key`
  groups. Family-weighted rates differ from item rates by less than 2.1 percentage points
  (see the run's `.md`).
- 15 XSS rows have an upstream `length` column one or two characters shorter than the payload
  (backslash escaping in the CSV). Payloads are used as parsed; `length` is ignored.
