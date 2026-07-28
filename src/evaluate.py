"""
evaluate.py
-----------
Implements Section 3.6 (Evaluation Method):
  - Classification performance: confusion matrix, accuracy, precision,
    recall, F1-score (macro-averaged across benign/sqli/xss).
  - Computational performance: inference latency (ms/packet) and
    process-level CPU/memory utilization.

Works identically for the three ML pipelines AND the signature baseline,
since both expose the same `.predict(list[str]) -> list[str]` interface.
"""

from __future__ import annotations

import time
import tracemalloc
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    precision_recall_fscore_support,
)

try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False

LABELS = ["benign", "sqli", "xss"]


def compute_classification_metrics(y_true: list[str], y_pred: list[str]) -> dict[str, Any]:
    acc = accuracy_score(y_true, y_pred)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, y_pred, labels=LABELS, average="macro", zero_division=0
    )
    cm = confusion_matrix(y_true, y_pred, labels=LABELS)
    return {
        "accuracy": acc,
        "precision_macro": precision,
        "recall_macro": recall,
        "f1_macro": f1,
        "confusion_matrix": cm,
    }


def benchmark_latency(model: Any, payloads: list[str], n_repeats: int = 1) -> dict[str, float]:
    """
    Measures per-sample inference latency by calling .predict() ONE payload
    at a time (this matches the real-time sniffer's usage pattern: one
    HTTP request classified as it arrives, not a big batch).

    Returns latency statistics in MILLISECONDS.
    """
    latencies_ms = []
    for _ in range(n_repeats):
        for payload in payloads:
            start = time.perf_counter()
            model.predict([payload])
            end = time.perf_counter()
            latencies_ms.append((end - start) * 1000.0)

    arr = np.array(latencies_ms)
    return {
        "mean_ms": float(arr.mean()),
        "median_ms": float(np.median(arr)),
        "p95_ms": float(np.percentile(arr, 95)),
        "max_ms": float(arr.max()),
        "n_samples": len(arr),
    }


def benchmark_resource_usage(model: Any, payloads: list[str]) -> dict[str, float]:
    """
    Measures CPU time consumed and peak Python-level memory allocation
    while classifying `payloads` one at a time. Uses tracemalloc for
    memory (portable, no root needed) and psutil for process CPU percent
    if available (falls back gracefully if psutil isn't installed).
    """
    process = psutil.Process() if _HAS_PSUTIL else None
    if process:
        process.cpu_percent(interval=None)  # prime the internal counter

    tracemalloc.start()
    cpu_time_start = time.process_time()

    for payload in payloads:
        model.predict([payload])

    cpu_time_end = time.process_time()
    _, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    result = {
        "cpu_time_seconds": cpu_time_end - cpu_time_start,
        "peak_memory_mb": peak_mem / (1024 * 1024),
    }
    if process:
        result["process_cpu_percent"] = process.cpu_percent(interval=None)
    return result


def evaluate_detector(
    name: str,
    model: Any,
    test_clean: pd.DataFrame,
    test_obfuscated: pd.DataFrame,
) -> dict[str, Any]:
    """Runs the full Section 3.6 evaluation for one detector on both test
    partitions and returns a single flat result dict (one row of the final
    comparison table)."""

    y_true_clean = test_clean["label"].tolist()
    y_pred_clean = model.predict(test_clean["payload"].tolist())
    metrics_clean = compute_classification_metrics(y_true_clean, y_pred_clean)

    y_true_obf = test_obfuscated["label"].tolist()
    y_pred_obf = model.predict(test_obfuscated["payload"].tolist())
    metrics_obf = compute_classification_metrics(y_true_obf, y_pred_obf)

    latency = benchmark_latency(model, test_clean["payload"].tolist()[:200])
    resources = benchmark_resource_usage(model, test_clean["payload"].tolist()[:200])

    f1_drop = metrics_clean["f1_macro"] - metrics_obf["f1_macro"]

    return {
        "detector": name,
        "accuracy_clean": metrics_clean["accuracy"],
        "f1_clean": metrics_clean["f1_macro"],
        "accuracy_obfuscated": metrics_obf["accuracy"],
        "f1_obfuscated": metrics_obf["f1_macro"],
        "f1_drop_evasion": f1_drop,
        "latency_mean_ms": latency["mean_ms"],
        "latency_p95_ms": latency["p95_ms"],
        "cpu_time_seconds_per_200": resources["cpu_time_seconds"],
        "peak_memory_mb": resources["peak_memory_mb"],
        "_confusion_matrix_clean": metrics_clean["confusion_matrix"],
        "_confusion_matrix_obfuscated": metrics_obf["confusion_matrix"],
    }


def format_confusion_matrix(cm: np.ndarray, labels: list[str] = LABELS) -> str:
    header = "        " + "  ".join(f"{l:>8}" for l in labels)
    lines = [header]
    for i, row_label in enumerate(labels):
        row = "  ".join(f"{v:8d}" for v in cm[i])
        lines.append(f"{row_label:8}{row}")
    return "\n".join(lines)
