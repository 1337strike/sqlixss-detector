# SQLi/XSS Detector

A Python project for studying SQL injection and cross-site scripting detection with lightweight machine learning. It compares Logistic Regression, Multinomial Naive Bayes, a calibrated linear SVM, and a local signature baseline, with and without input canonicalization.

The repository includes the paper experiments, supplementary benchmarks, and a reverse-proxy WAF prototype. The experiments measure how preprocessing changes classification results. The prototype explores how those detectors behave alongside request inspection and rate limiting.

**Accompanying paper:** *Evaluating Input Canonicalization for SQLi and XSS Detection Using Lightweight Machine Learning*

## Run the paper experiments

Use Python 3.12 and the pinned dependencies in `requirements.lock`. The reference experiment used Python 3.12.3, scikit-learn 1.8.0, NumPy 2.4.4, and SciPy 1.17.1.

```bash
git clone https://github.com/1337strike/sqlixss-detector.git
cd sqlixss-detector
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.lock

python scripts/00_download_payloads.py
python scripts/01c_build_grouped_dataset.py
python scripts/02_train_models.py
python scripts/definitive_experiment.py --seed 42 --folds 5 --repeats 3
python scripts/verify_reference_run.py
```

The raw corpus is already included in `data/raw/`. The download step retrieves it from the pinned upstream revision and checks its SHA-256 hashes.

Each experiment writes to `results/definitive_<timestamp>_42/`. The verifier compares the new classification results with the [reference run](results/definitive_20260923T094339Z_42/) and checks the statistics against the paper. Timing varies with the machine and is not part of that equality check.

This workflow reproduces the main experiments in Tables I–V. The external benchmarks and repeated timing measurements use the separate commands below.

## What the experiments show

The main corpus contains **1,012 strings**: 307 SQLi, 135 XSS, and 570 template-generated benign inputs. Evaluation uses five-fold cross-validation repeated three times, with heuristic payload families kept apart between training and test folds. A separate split contains 749 training and 263 test samples.

Canonicalization improves obfuscated macro-F1 for all four detector families on this corpus:

| Detector | Raw obfuscated F1 | Canonicalized obfuscated F1 | Gain | Holm-adjusted p |
|---|---:|---:|---:|---:|
| Logistic Regression | 0.7905 ± 0.0394 | 0.9934 ± 0.0068 | +0.2029 | 3.42 × 10⁻⁷ |
| Multinomial Naive Bayes | 0.8121 ± 0.0380 | 0.9838 ± 0.0101 | +0.1717 | 1.65 × 10⁻⁶ |
| Calibrated linear SVM | 0.8592 ± 0.0381 | 0.9919 ± 0.0077 | +0.1327 | 1.30 × 10⁻⁵ |
| Local signatures | 0.5893 ± 0.1059 | 0.8420 ± 0.0723 | +0.2527 | 1.65 × 10⁻⁶ |

These are means and marginal standard deviations across 15 folds. The paper also reports corrected confidence intervals for the paired gains.

The separate test split helps explain what those gains mean. Confusing SQLi with XSS is different from allowing an attack-labeled string through as benign:

| Configuration | Clean F1 | Obfuscated F1 | Attacks predicted benign | SQLi/XSS confusions |
|---|---:|---:|---:|---:|
| LR, raw | 1.0000 | 0.7895 | 0 | 23 |
| LR, canonicalized | 1.0000 | 0.9931 | 0 | 1 |
| MNB, raw | 0.9937 | 0.7950 | 8 | 17 |
| MNB, canonicalized | 0.9937 | 0.9868 | 2 | 1 |
| SVM, raw | 1.0000 | 0.8369 | 0 | 19 |
| SVM, canonicalized | 1.0000 | 0.9931 | 0 | 1 |
| Signatures, raw | 0.7467 | 0.4928 | 90 | 0 |
| Signatures, canonicalized | 0.7563 | 0.7516 | 59 | 0 |

Error counts refer to the obfuscated condition and its 118 attack-labeled strings. For LR and SVM, the F1 improvement here comes from better attack-type recognition; neither configuration predicts an attack as benign on this split. These results describe string classification, not successful exploitation or blocking in a live application.

## Results beyond the main corpus

The supplementary experiments test the paper classifiers on external data without adding WAF layers or retuning the models.

| Experiment | Finding | Details |
|---|---|---|
| CSIC 2010 normal traffic | On 16,000 requests with parameters, LR, SVM, and signatures have no false positives. MNB flags 0.70–0.73%. LR and SVM classify the other 20,000 empty inputs as SQLi. | [CSIC evaluation](docs/supplementary_csic2010.md) |
| HttpParamsDataset | After overlap removal, evaluation covers 10,849 SQLi and 529 XSS strings, plus 19,304 benign values. ML detection is 99.4–100%, but LR/SVM also flag 96.9–97.5% of the benign values. | [External detection benchmark](docs/supplementary_httpparams.md) |
| SVM calibration and timing | Removing the calibration wrapper preserves the reported clean/obfuscated macro-F1 while reducing median prediction time from 1.604 to 0.381 ms on the supplementary host. Five timing sessions are recorded. | [Timing and calibration](docs/supplementary_measurements.md) |

The benign control is central to interpreting the external detection rates. The paper's benign training examples are query strings such as `key=value`, while HttpParamsDataset supplies bare values. LR and SVM respond poorly to that change in input shape, so their high attack detection rate alone does not demonstrate useful separation from benign input.

To reproduce these measurements in the environment above:

```bash
python scripts/00b_download_csic2010.py
python scripts/supplementary_csic.py
python scripts/00c_download_httpparams.py
python scripts/supplementary_httpparams.py
python scripts/supplementary_measurements.py --sessions 5
```

The scripts write separate `results/supplementary_<timestamp>/` folders. Their timings come from different runs and do not replace the archived values in Table V.

## Try the WAF prototype

The WAF sits between a client and a backend application. Set `backend_url`, the listening address, and the inspection options in [config/waf_config.yaml](config/waf_config.yaml), start your backend, then run:

```bash
python scripts/05_run_waf.py --config config/waf_config.yaml
```

The default configuration listens on `http://127.0.0.1:8443` and forwards allowed requests to `http://127.0.0.1:8080`. TLS is disabled in this local configuration.

The prototype adds several layers around the classifiers:

- Additional decoding and signature checks for paths, headers, query parameters, forms, and JSON.
- Input routing that sends `key=value` inputs to the ML ensemble and uses signatures for paths and headers. ML abstains when an input has no known features.
- Behavioral rate limiting with temporary bans and escalation for repeat offenders.
- Optional Redis state shared across workers.
- A uniform `403` response for detection-based refusals, with a request ID that can be traced in `logs/waf.log`.

The default detectors are LR, SVM, and signatures, using `model_set: deploy`. Deployment models are trained with [scripts/train_deploy_models.py](scripts/train_deploy_models.py). Set `model_set: paper` to use the paper models instead. This choice changes the prototype's behavior; it does not change the archived paper experiments.

### Inspect traffic before enabling blocking

Set `mode: "monitor"` to log detection decisions as `would_block` while forwarding those requests. Protocol-safety checks and static deny rules still apply. Review the logs for false positives before choosing `mode: "block"`.

The repository also includes a [Caddy configuration](deploy/Caddyfile) and a [service definition](deploy/waf.service). The service uses multiple workers, so configure the Redis backend when using it. The prototype has not been validated as a replacement for a production WAF.

### Deployment measurements

The following results were reported for the deployment configuration using [scripts/evaluate_waf_realworld.py](scripts/evaluate_waf_realworld.py). They include WAF content inspection and should be read separately from the classifier-only tables above.

| Evaluation | Deployment models | Paper models |
|---|---:|---:|
| False positives on 36,000 CSIC normal requests | 0 | 0 |
| False positives with unseen parameter names | 0% | 6.9% |
| False positives on values with apostrophes | 0.1% | 99.4% |
| Detection on 879 SQLi payloads from PayloadsAllTheThings | 99.1–99.4% | 99.2–99.8% |
| Detection on 1,572 XSS payloads from PayloadsAllTheThings | 98.5–99.4% | 99.2–99.7% |
| Attack detection on the paper test split | 96.6% | 95.8% |
| Detection on 10,252 sqlmap replay requests, six tamper configurations | 99.05% | 99.91% |
| Content-inspection latency, in process | ~2.5 ms/request | ~2.4 ms/request |

The zero CSIC false-positive count here is a result of the WAF's routing and selected detectors. It is a different measurement from feeding all 36,000 inputs directly to each paper classifier. Replay detection also does not establish whether each request would successfully exploit a backend.

### Behavioral rate limiting

The limiter counts allowed and refused requests for each source IP over a sliding window. A ban requires both a minimum number of refusals and a minimum refusal ratio. An absolute refusal cap also applies, and repeated bans become longer. The defaults start at five minutes and cap at 24 hours.

This policy is intended to tolerate occasional false positives, but its behavior still depends on traffic volume, thresholds, and whether legitimate users share an IP address.

[The CSIC replay results](results/waf_csic2010_rate_limit.json) record zero bans on 72,000 normal requests for both the default detectors and a stress configuration that includes MNB. The stress configuration refuses 230 requests without banning a client under the evaluated traffic patterns.

```bash
python scripts/00b_download_csic2010.py
python scripts/09_csic_rate_limit_validation.py --with-anomalous
```

### Adaptive probing controls

The `agent_defense` configuration enables additional checks for repeated probing. After several distinct blocked payloads, a client can enter a stricter probation period. The module also remembers similar blocked payloads across clients, scores signals such as decoy-path access and repeated error responses, and can replace leaked backend errors with a generic response.

These controls target behaviors that automated tools and LLM-driven agents can share. They do not reliably identify every AI agent or guarantee resistance to adaptive attacks. The default fingerprint signals alone stay below the blocking threshold. With Redis enabled, the defense state is shared across workers.

The HTTP scenarios are in [tests/integration/test_waf_agent_defense.py](tests/integration/test_waf_agent_defense.py); store and decision tests are in [tests/test_agent_defense.py](tests/test_agent_defense.py).

## Checks and current limitations

Run the test suite from the project root:

```bash
python -m pytest tests/ -q
```

Some tests require a running Redis server or the downloaded CSIC dataset and may be skipped locally. Known benign false-positive cases are marked `xfail`. The [CI workflow](.github/workflows/ci.yml) provisions Redis, downloads the datasets it needs, reproduces the main experiment, and exercises the proxy over HTTP. It also checks that incomplete or malformed statistics cannot pass the reference verifier.

The main limitations are:

- The training corpus is small and its benign examples come from narrow templates. External tests show why its results cannot be generalized to arbitrary legitimate input.
- Family grouping is heuristic. It separates recorded families in the outer folds but does not establish semantic independence or grouped internal SVM calibration.
- The seven transformations are not an adaptive attack benchmark. The SQLite oracle and XSS pattern checks do not establish preserved attack execution.
- Prediction timing and in-process inspection timing do not measure sustained throughput, memory under load, or end-to-end service latency.

## Find the code and evidence

| Path | Contents |
|---|---|
| `data/raw/` and `data/processed/` | Source corpus, provenance, and train/test CSVs |
| `src/` | Canonicalization, features, classifiers, obfuscation, and WAF components |
| `scripts/definitive_experiment.py` | Main paper experiment |
| `scripts/export_statistics.py` | Full-precision statistics for a run, including gain intervals and pairwise tests |
| `scripts/verify_reference_run.py` | Classification and statistics verification |
| `results/definitive_20260923T094339Z_42/` | Archived main experiment; read its `NOTE.md` for file history |
| `results/supplementary_*/` | External evaluations, calibration ablation, and repeated timings |
| [Method mapping](docs/paper_method_mapping.md) and [number reconciliation](docs/paper_reconciliation.md) | Detailed audit of the main Tables I–V, originally prepared for manuscript version 17 |
| [AUDIT_REPORT.md](AUDIT_REPORT.md) | Historical findings from earlier development; not a list of current failures |

Fresh runs export `full_statistics.json` automatically. The archived folder contains historical files with older schemas, so use its notes and the generated exports when following the statistical calculations.

## Paper and data references

The main experiment is identified by `definitive_20260923T094339Z_42`.

The final manuscript cites [project commit 969efcd](https://github.com/1337strike/sqlixss-detector/tree/969efcdba2581243c398adcf26bc2a3e39ab56b3), which includes the supplementary experiments and verifier fixes. The earlier `v1.1.0` release points to `4b45d4a` and predates those additions.

The malicious corpus comes from [InfoSecWarrior/Offensive-Payloads](https://github.com/InfoSecWarrior/Offensive-Payloads) at commit `9e67029a`. File hashes are recorded in [data/raw/provenance.json](data/raw/provenance.json). The supplementary documentation records the pinned CSIC mirror and HttpParamsDataset revisions used for those evaluations.
