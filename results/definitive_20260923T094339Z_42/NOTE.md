# Note on this run (reference run cited in the paper)

`definitive_20260923T094339Z_42` is the archived run behind every
classification number in the paper (§III-E, Tables I–V). Its files are kept
exactly as produced. This note explains a few labels in them that predate the
final manuscript.

## Labels written before the final manuscript

| Where | Label | Meaning |
|---|---|---|
| `per_technique.csv` | `partial_url_encoding_UNDISCLOSED` | The partial-URL-encoding technique. An earlier draft described 6 techniques. The paper (§III-C) discloses all 7, and later runs write `partial_url_encoding`. |
| `manifest.json` | `paper_claims_6_techniques_code_has_7` | The same audit flag. It was resolved when §III-C was revised. |
| `manifest.json` | `output_files` paths under `/home/claude/sqli/` | Absolute paths from the machine that ran the experiment. They are not needed to use the files, and later runs write repo-relative paths. |

## Which statistics file is authoritative

`full_statistics.json` computes every test at full floating-point precision.
`scripts/export_statistics.py` regenerates it exactly from `fold_scores.json`
(new runs also get the Table I 95% CIs and the §IV-B pairwise tests).
The paper's Table I (t, p_raw, p_Holm, CIs) matches it exactly.

`cv_stats.json` computes the same tests from means and SDs that were rounded
to 4 decimals first, so its test statistics differ in the third significant
digit. For example, LR p_Holm is 3.40e-07 in `cv_stats.json` and 3.42e-07 in
`full_statistics.json` and the paper. The means and SDs in `cv_stats.json` are
exact to their printed precision; use `full_statistics.json` for test
statistics.

## Semantic oracle records (§IV-E)

`results/semantic_validation_clean.json` holds the SQLi oracle before
obfuscation, and `results/semantic_validation_obf.json` holds it after. Both
report 84 SQLi strings: 66 `invalid` (baseline outcome), 16 `error` (SQLite
syntax errors) and 2 `uncertain` (other execution exceptions). To regenerate
them:

    python scripts/validate_semantics.py --label sqli --seed 42
    python scripts/validate_semantics.py --label sqli --seed 42 --obfuscated

## Reproducing this run bit-for-bit

    python3.12 -m venv .venv && .venv/bin/pip install -r requirements.lock
    .venv/bin/python scripts/definitive_experiment.py --seed 42 --folds 5 --repeats 3

This was verified at commit `4b45d4a` (release `v1.1.0`) in a clean Python 3.12.3 environment
with scikit-learn 1.8.0, NumPy 2.4.4 and SciPy 1.17.1. The new run's 240
fold-level F1 scores, 16 single-split confusion matrices and 35 per-technique
drops are identical to this folder (max absolute difference 0.0). The latency
columns (Table V) are wall-clock measurements, so they vary between machines
and sessions.

The commit that originally produced this run (`ff88291`) was never pushed to
this repository. Commit `4b45d4a` (release `v1.1.0`) is the citable snapshot that reproduces it.
