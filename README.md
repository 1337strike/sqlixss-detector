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
    full_statistics.json    Table I gains/CIs/p_Holm + §IV-B pairwise tests (scripts/export_statistics.py)
    cv_stats.json           CV means/SDs; tests from rounded inputs (see NOTE.md)
    per_technique.csv       Table III (7 techniques, 5 seeds)
    predictions.csv         per-sample clean ML predictions
    tables.md               paper tables in Markdown
  semantic_validation_clean.json    §IV-E SQLi oracle, before obfuscation
  semantic_validation_obf.json      §IV-E SQLi oracle, after obfuscation
docs/
  paper_method_mapping.md   every PDF v17 method claim → code → evidence
  paper_reconciliation.md   every PDF v17 number → reference-run value → check
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
  rate_limiter.py           WAF behavioral rate limiting (memory / Redis)
  agent_defense.py          WAF AI-agent defense: probation, payload families, honeypots, error scrubbing
  csic2010.py, waf_replay.py  CSIC 2010 parser + live WAF replay harness
scripts/
  definitive_experiment.py  ← MAIN: reproduces all paper tables
  export_statistics.py      Table I CIs/p_Holm + §IV-B pairwise tests → full_statistics.json
  verify_reference_run.py   fresh run vs reference run and paper values (CI)
  00_download_payloads.py
  01c_build_grouped_dataset.py
  02_train_models.py
  03_evaluate_offline.py
  05_run_waf.py             reverse-proxy WAF
  00b_download_csic2010.py  CSIC 2010 (rate-limit validation only)
  09_csic_rate_limit_validation.py  0-false-ban check on CSIC 2010 normal traffic
tests/
  test_pipeline_regression.py   G1/M2 canonicalization + vocabulary isolation
  test_split_integrity.py       G4 family leakage checks
  test_rate_limiter.py          behavioral rate limiter, both backends
  test_agent_defense.py         AI-agent defense layer, both backends
  integration/
    test_end_to_end.py          pipeline + WAF extraction path; FP edge cases are xfail
    test_waf_deployment.py      evasion views, WAF rules, block/monitor, uniform refusals (in-process HTTP)
    test_proxy_live.py          real processes: single-process WAF and gunicorn + Redis shared bans
    test_rate_limiter_live.py   live WAF bans/escalation; CSIC 2010 normal traffic → 0 bans
    test_waf_agent_defense.py   AI-agent scenarios: mutation, IP rotation, honeypot, error oracle, fuzzing
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

## Real-World Deployment

The WAF (`src/waf_proxy.py`) adds deployment-only layers on top of the paper's
pipeline. They do not change any paper number; CI re-verifies the reference
run on every push.

- **Evasion-aware canonicalization** (`src/waf_canonical.py`): decodes IIS
  `%uXXXX`, unwraps MySQL versioned comments `/*!…*/` (nested too), and also
  inspects a comments-as-spaces view.
- **WAF-only signature rules** (`WAF_EXTRA_*_PATTERNS`): tautologies,
  `xp_cmdshell`, `@@version`, quote+comment, `IIF(`/`(CASE WHEN`, numeric
  boolean probes, generic `<tag on*=>`, `` alert` ``, UTF-7.
- **Input-shape routing**: URL paths and headers → signature rules; query,
  form and JSON (`key=value` leaves) → ML ensemble; ML abstains on inputs
  with no known features.
- **Monitor mode**: `mode: "monitor"` logs `would_block` and forwards the
  request. Use it first on real traffic.

### Measured on data the models never saw (`scripts/evaluate_waf_realworld.py`)

Default: detectors LR + SVM + signature, `model_set: deploy` (models trained by
`scripts/train_deploy_models.py`; the paper's models are available as
`model_set: paper`).

| Test | Deploy models (default) | Paper models |
|---|---|---|
| False positives, CSIC 2010 normal traffic (36,000 real HTTP requests) | **0** | 0 |
| False positives, ordinary values with unseen parameter names | **0%** | 6.9% |
| False positives, values with apostrophes (`it's`, `O'Neil`) | **0.1%** | 99.4% |
| SQLi holdout, PayloadsAllTheThings (879 complete payloads, not in training) | 99.1–99.4% | 99.2–99.8% |
| XSS holdout, PayloadsAllTheThings (1,572 complete payloads) | 98.5–99.4% | 99.2–99.7% |
| Paper test split, attacks detected at the WAF | 96.6% | 95.8% |
| sqlmap 1.10.9 replay, 6 tamper configurations (10,252 attack requests) | 99.05% | 99.91% |
| Latency (content inspection, in-process) | ~2.5 ms / request | ~2.4 ms / request |

The deployment models trade 0.9 points of sqlmap detection for far fewer
false positives on real-world inputs; signature rules and repeat-offender bans
remain behind them. Most sqlmap requests that pass are arithmetic probes
(`5602-5601`) and single encoded digits, which are not injections.
`naive_bayes` is off by default: on CSIC it caused all 112 false positives
(it flags short-password login forms as SQLi).

Every detection-based refusal (payload, scanner, ban, deny list) returns the
same `403 {"error": "Forbidden", "request_id": ...}`; the reason is recorded
in `logs/waf.log` under that `request_id`.

### Repeat-offender bans (behavioral rate limiting)

`src/rate_limiter.py` bans source IPs on behavior, not on single detections:

- **Refusal ratio over a sliding window.** Every request is recorded per IP
  as allowed or refused. An IP is banned when, within `offense_window_seconds`,
  it has at least `offense_threshold` refused requests **and** they make up at
  least `refusal_ratio_threshold` of its traffic. A scanner is refused on most
  of what it sends; a busy legitimate client that trips an occasional false
  positive is not banned.
- **Anti-dilution cap.** `hard_offense_threshold` refusals in the window ban
  regardless of ratio, so padding payloads with benign requests doesn't work.
- **Escalating bans.** The n-th ban issued within `offender_memory_seconds`
  of the previous one ending lasts
  `ban_duration_seconds × ban_escalation_factor^(n-1)`, capped at
  `max_ban_duration_seconds` (defaults: 5 min → 20 min → 80 min → … → 24 h).
  A banned IP gets the same uniform 403 as any other refusal.
- **Redis backend.** With `backend: redis`, each request is one atomic Lua
  call, so state is shared correctly across gunicorn workers and replicas.

Validated on all 72,000 CSIC 2010 normal requests (training + test files):

```bash
redis-server --daemonize yes                      # optional; else in-memory backend
python scripts/00b_download_csic2010.py            # pinned mirror, SHA-256-verified
python scripts/09_csic_rate_limit_validation.py --with-anomalous
```

| CSIC 2010, live through the WAF (Redis), clients of 100 requests | Refused | Bans |
|---|---|---|
| Normal traffic, shipped detectors (LR + SVM + signature, deploy) | 0 / 72,000 | **0** |
| Normal traffic, stress detectors (LR + NB + signature, paper models) | 230 / 72,000 (0.32%) | **0** |
| Same recorded refusals, one IP at 1 / 10 / 100 req/s, and clients of 10 / 50 / 500 / 5,000 requests in one window (both backends) | — | **0** |
| Anomalous traffic, shipped detectors, 251 clients | 2,309 / 25,065 | 159 of 251 clients banned; 11,183 later requests turned away |

The stress configuration runs the ban layer against detectors that do
misfire. They refuse at most 2 of any 30 consecutive normal requests. One IP
sending that traffic would reach the anti-dilution cap only above ~228 req/s.
Full output: `results/waf_csic2010_rate_limit.json`. Tests:
`tests/test_rate_limiter.py` (unit, both backends) and
`tests/integration/test_rate_limiter_live.py` (live WAF over HTTP, includes the
CSIC run).

### AI-agent defense (`src/agent_defense.py`)

LLM-driven attack agents (HexStrike AI, PentestGPT, custom MCP/tool loops)
swap out tool User-Agents after the first 403 and then run
*payload → response → mutate → retry*, rotating IPs when banned and reading
backend errors as an oracle. The recon filter's tool signatures cannot stop
that; this layer targets the loop itself (config section `agent_defense`):

- **Probation.** After 3 *distinct* refused payloads, a client's inputs with
  any injection syntax (quote, comment, `;`, tag, SQL/JS keyword, `or true`,
  …), or similar to its refused payloads, are refused for an hour — past the
  first bans. The model bypass a mutation search finds (e.g. `1 AnD 2>1`,
  `admin'`, `<b onclick`, all passed by the ensemble) is refused.
- **Cross-client payload families.** Refused payloads are indexed with
  MinHash-LSH; a near-duplicate with injection syntax is refused from *any*
  IP for an hour (`-1 UNION SELECT 1 INTO @,@,@` blocked → the bypass
  `-1 UNION SELxECT 1 INTO @,@,@` is refused from a fresh IP).
- **Suspicion score.** Decoy `honeypot_paths` (list them under `Disallow:` in
  robots.txt), forced browsing (30 distinct 401/403/404/405 in 10 min),
  provoked backend errors, and client fingerprint (pasted browser UA without
  `Accept-Language`, HTTP-library/headless UAs, self-declared AI agents).
  The fingerprint signals alone add up to 95 points, under the threshold of 100, so they never block anyone by themselves.
- **Error-oracle removal.** Backend responses leaking DB errors or stack
  traces become a generic 500 when the status is ≥ 500 or the request
  carried injection syntax (a page quoting a MySQL error is untouched).

All refusals are the uniform 403; state is shared through Redis whenever the
rate limiter uses it. Measured with the shipped config:

| CSIC 2010, live through the WAF, clients of 100 requests | Layer off | Layer on |
|---|---|---|
| Normal traffic (72,000): refused / bans | 0 / 0 | **0 / 0** |
| Anomalous traffic (25,065): forwarded to backend | 11,573 | **8,495** |
| Anomalous traffic: clients banned | 159 / 251 | **239 / 251** |
| Added latency per request (in-process) | — | 0.04–0.10 ms |

Tests: `tests/test_agent_defense.py` (unit, both backends) and
`tests/integration/test_waf_agent_defense.py` (agent scenarios over HTTP).
This raises the cost of automated adaptive attacks; it cannot stop a patient
human who never trips a detector.

### Recommended rollout
1. Deploy behind Caddy (`deploy/Caddyfile`) with `deploy/waf.service`; set
   `rate_limit.backend: redis` (the service runs 4 workers).
2. Run with `mode: "monitor"` on real traffic; review `would_block` entries in
   `logs/waf.log` for false positives.
3. Switch to `mode: "block"`. Keep a mature ruleset (e.g. ModSecurity + OWASP
   CRS) in front for defense in depth: this WAF is not adversarially hardened
   against attackers who adapt to it specifically.

---

## Known Limitations

- Benign corpus from narrow templates; 5 edge-case inputs (apostrophe, SQL tutorial text, HTML) produce false positives outside the test set (documented as `xfailed` tests)
- 7 obfuscation techniques in code; paper covers all 7 including `partial_url_encode`
- SQLi oracle limited to single equality-template context
- No end-to-end proxy benchmark (throughput, sustained-load memory) yet
- CSIC 2010 is evaluated for false positives only (36,000 normal requests, classifier level):
  `scripts/00b_download_csic2010.py` + `scripts/supplementary_csic.py`, results in
  `results/supplementary_20260925T122826Z/`, write-up in `docs/supplementary_csic2010.md`.
  LR/SVM label empty input (20,000 parameterless GETs) as SQLi; no CSIC attack-traffic evaluation yet

---

## Reproduce from Scratch

```bash
git clone https://github.com/1337strike/sqlixss-detector
cd sqlixss-detector
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.lock
python scripts/01c_build_grouped_dataset.py
python scripts/definitive_experiment.py --seed 42 --folds 5 --repeats 3
python scripts/verify_reference_run.py   # exits 1 on any mismatch
python -m pytest tests/ -q   # all pass; documented FP edge cases report as xfailed
```

With `requirements.lock` (Python 3.12.3, scikit-learn 1.8.0, NumPy 2.4.4,
SciPy 1.17.1), the run reproduces the reference run **bit-for-bit**: all 240
fold-level F1 scores, 16 single-split confusion matrices and 35 per-technique
drops are identical. `full_statistics.json` (generated by
`scripts/export_statistics.py`) reproduces every inferential statistic in the
paper: Table I gains, 95% CIs and p_Holm, and the §IV-B pairwise tests.
Latency (Table V) is wall-clock and varies by machine.

- Experiment ID: `definitive_20260923T094339Z_42`
- Citable snapshot: commit **`4b45d4a`** (release `v1.1.0`); check it out with
  `git checkout 4b45d4a`. The commit that originally produced the run
  (`ff88291`) was never pushed; `4b45d4a` reproduces it exactly.
- Corpus: InfoSecWarrior/Offensive-Payloads @ `9e67029a`, SHA-256 in
  `data/raw/provenance.json`
