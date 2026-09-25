# Supplementary Measurements for the Paper Revision

> **Supplementary, not part of the archived results.** Nothing here changes Table V.
> Table V still reports the archived reference run `definitive_20260923T094339Z_42`.
> These numbers come from a separate run on a different host.

- Script: `scripts/supplementary_measurements.py`
- Run folder: `results/supplementary_20260925T122914Z/` (raw per-call timings, per-session
  statistics, environment record, calibration confusion matrices)
- Environment: `requirements.lock` on Python 3.12.3 (every package matches the lock)

Reproduce:

```bash
python3.12 -m venv .venv && .venv/bin/pip install -r requirements.lock
.venv/bin/python scripts/supplementary_measurements.py --sessions 5
```

Macro-F1 values are deterministic, and the calibrated SVM's confusion matrices match the reference run exactly.
Latencies are wall-clock and change from run to run.

## Environment

| Item | Value |
|---|---:|
| CPU model | Intel(R) Xeon(R) Processor @ 2.80GHz |
| Logical CPUs / physical cores / usable by process | 4 / 4 / 4 |
| RAM | 15.72 GiB |
| OS / kernel | Ubuntu 24.04.4 LTS / 6.18.44-fc-v37 |
| Python | 3.12.3 (CPython) |
| scikit-learn / NumPy / SciPy | 1.8.0 / 2.4.4 / 1.17.1 |
| pandas / joblib / threadpoolctl | 3.0.6 / 1.6.0 / 3.7.0 |
| All packages match requirements.lock | True |
| Timer | time.perf_counter (resolution 1e-09 s) |

## S1. Calibration ablation (canonicalized linear SVM, 749 train / 263 test)

| SVM variant | Clean macro-F1 | Obf. macro-F1 | Drop | Median ms, median of 5 sessions (range) | p95 ms, median of 5 sessions (range) | Matches reference run |
|---|---:|---:|---:|---:|---:|---:|
| LinearSVC + CalibratedClassifierCV (cv=3) | 1.0000 | 0.9931 | 0.0069 | 1.6036 (1.5834–1.6314) | 1.9917 (1.8631–2.5530) | True |
| LinearSVC (no calibration) | 1.0000 | 0.9931 | 0.0069 | 0.3813 (0.3659–0.3934) | 0.5372 (0.4615–0.6356) | n/a |

## S2. Latency, Table V protocol, 5 repeated sessions

Per session: fresh process, models retrained, 5 warm-up calls, then one `predict([x])` per clean test input (263 calls). Range = min–max of the per-session statistic. With 263 calls, p99 is set by the 3rd-slowest call, so it is sensitive to single scheduler or GC stalls. The archived Table V values come from a different host (`definitive_20260923T094339Z_42/environment.json`: 1 CPU visible to the process) and are listed for reference only.

| Configuration | Median ms (range) | p95 ms (range) | p99 ms (range) | Archived Table V median / p95 / p99 |
|---|---:|---:|---:|---:|
| logistic_regression_normalized | 0.4054–0.7293 | 0.5340–0.8495 | 0.6127–0.9659 | 0.2731 / 0.3548 / 0.375 |
| naive_bayes_normalized | 0.3925–0.4051 | 0.4901–0.5485 | 0.5693–0.7152 | 0.2579 / 0.3242 / 0.3783 |
| svm_normalized | 1.5834–1.6314 | 1.8631–2.5530 | 2.1936–2.8047 | 1.2457 / 1.3864 / 1.5812 |
| signature_raw | 0.0057–0.0059 | 0.0109–0.0113 | 0.0195–0.0383 | 0.0046 / 0.0091 / 0.0167 |
| signature_normalized | 0.0088–0.0105 | 0.0179–0.0254 | 0.0293–0.0424 | 0.0082 / 0.019 / 0.0323 |
| svm_normalized_uncalibrated | 0.3659–0.3934 | 0.4615–0.6356 | 0.5624–0.9584 | — |

### Per-session values (ms)

| Configuration | Session | Median | p95 | p99 |
|---|---:|---:|---:|---:|
| logistic_regression_normalized | 1 | 0.4218 | 0.5489 | 0.6776 |
| naive_bayes_normalized | 1 | 0.4028 | 0.5485 | 0.7152 |
| svm_normalized | 1 | 1.6036 | 2.3576 | 2.5577 |
| signature_raw | 1 | 0.0059 | 0.0110 | 0.0203 |
| signature_normalized | 1 | 0.0099 | 0.0222 | 0.0317 |
| svm_normalized_uncalibrated | 1 | 0.3659 | 0.4615 | 0.5624 |
| logistic_regression_normalized | 2 | 0.4170 | 0.6171 | 0.6653 |
| naive_bayes_normalized | 2 | 0.3925 | 0.5049 | 0.5989 |
| svm_normalized | 2 | 1.5857 | 1.8798 | 2.2629 |
| signature_raw | 2 | 0.0058 | 0.0113 | 0.0383 |
| signature_normalized | 2 | 0.0088 | 0.0193 | 0.0334 |
| svm_normalized_uncalibrated | 2 | 0.3868 | 0.5372 | 0.6501 |
| logistic_regression_normalized | 3 | 0.4054 | 0.5340 | 0.6682 |
| naive_bayes_normalized | 3 | 0.3931 | 0.4901 | 0.5693 |
| svm_normalized | 3 | 1.6158 | 1.8631 | 2.1936 |
| signature_raw | 3 | 0.0058 | 0.0111 | 0.0277 |
| signature_normalized | 3 | 0.0090 | 0.0179 | 0.0293 |
| svm_normalized_uncalibrated | 3 | 0.3813 | 0.6356 | 0.9584 |
| logistic_regression_normalized | 4 | 0.4057 | 0.5455 | 0.6127 |
| naive_bayes_normalized | 4 | 0.4051 | 0.5233 | 0.5926 |
| svm_normalized | 4 | 1.6314 | 2.5530 | 2.8047 |
| signature_raw | 4 | 0.0057 | 0.0111 | 0.0268 |
| signature_normalized | 4 | 0.0105 | 0.0254 | 0.0424 |
| svm_normalized_uncalibrated | 4 | 0.3934 | 0.5306 | 0.6383 |
| logistic_regression_normalized | 5 | 0.7293 | 0.8495 | 0.9659 |
| naive_bayes_normalized | 5 | 0.3981 | 0.5325 | 0.6885 |
| svm_normalized | 5 | 1.5834 | 1.9917 | 2.3955 |
| signature_raw | 5 | 0.0057 | 0.0109 | 0.0195 |
| signature_normalized | 5 | 0.0093 | 0.0197 | 0.0377 |
| svm_normalized_uncalibrated | 5 | 0.3684 | 0.5523 | 0.8169 |

### Note on session 5

In session 5, logistic regression was slow for the whole session: median 0.73 ms against
0.41–0.42 ms in sessions 1–4, and roughly 0.7 ms on almost every call rather than a few outliers. The other five configurations
in the same session had normal medians (NB 0.398, calibrated SVM 1.583, uncalibrated SVM
0.368 ms). LR is timed first in every session, so this fits contention on the shared cloud VM
during the first ~0.2 s of session 5. The session is kept as
measured, not re-run or dropped; the across-session range is meant to show exactly this kind of variation.

## Paper paragraph (draft)

**Supplementary measurements.** To separate the cost of probability calibration from the linear decision function, we retrained the canonicalized linear SVM on the same 749-sample training split without `CalibratedClassifierCV`. Macro-F1 was 1.0000 (clean) and 0.9931 (obfuscated) with calibration, and 1.0000 and 0.9931 without it (identical). Median single-request latency fell from 1.604 ms to 0.381 ms (4.2× faster); the calibrated model evaluates three LinearSVC fits and their sigmoid calibrators per call. We also repeated the Table V timing protocol in 5 independent sessions (CPU: Intel(R) Xeon(R) Processor @ 2.80GHz, 4 usable CPUs; 15.72 GiB RAM; Ubuntu 24.04.4 LTS; Python 3.12.3; scikit-learn 1.8.0). Across sessions, median latency ranged from 0.0057–0.0059 ms (signature_raw) to 1.5834–1.6314 ms (svm_normalized), and the canonicalized SVM's p99 ranged from 2.1936–2.8047 ms. The ordering of the five configurations by median latency was the same in every session. These values are supplementary. Table V still reports the archived reference run, which was recorded on a different host (1 CPU visible to the process); absolute latencies depend on hardware, so only the relative ordering and the calibration overhead should be compared.
