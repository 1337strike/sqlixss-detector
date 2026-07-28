"""
Usage:
    python scripts/03_evaluate_offline.py

Evaluates Logistic Regression, Naive Bayes, SVM, and the signature-based
baseline on BOTH test_clean.csv and test_obfuscated.csv, producing:
  - results/metrics.csv          (one row per detector, matches Table-4.x)
  - results/confusion_matrices.txt
Prints a human-readable summary table to stdout as well.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd

from src.models import load_all_models
from src.baseline_signature import SignatureBaseline
from src.evaluate import evaluate_detector, format_confusion_matrix

PROCESSED_DIR = Path(__file__).resolve().parent.parent / "data" / "processed"
RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"


if __name__ == "__main__":
    test_clean = pd.read_csv(PROCESSED_DIR / "test_clean.csv").dropna(subset=["payload", "label"])
    test_obfuscated = pd.read_csv(PROCESSED_DIR / "test_obfuscated.csv").dropna(subset=["payload", "label"])

    detectors = load_all_models()
    detectors["signature_baseline"] = SignatureBaseline()

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    rows = []
    cm_report_lines = []

    for name, model in detectors.items():
        print(f"[03] Evaluating {name} ...")
        result = evaluate_detector(name, model, test_clean, test_obfuscated)

        cm_report_lines.append(f"=== {name} :: CLEAN test set ===")
        cm_report_lines.append(format_confusion_matrix(result["_confusion_matrix_clean"]))
        cm_report_lines.append(f"\n=== {name} :: OBFUSCATED test set ===")
        cm_report_lines.append(format_confusion_matrix(result["_confusion_matrix_obfuscated"]))
        cm_report_lines.append("\n" + "=" * 60 + "\n")

        row = {k: v for k, v in result.items() if not k.startswith("_")}
        rows.append(row)

    results_df = pd.DataFrame(rows).sort_values("f1_obfuscated", ascending=False)
    results_df.to_csv(RESULTS_DIR / "metrics.csv", index=False)
    (RESULTS_DIR / "confusion_matrices.txt").write_text("\n".join(cm_report_lines))

    pd.set_option("display.width", 140)
    pd.set_option("display.max_columns", 20)
    print("\n" + "=" * 100)
    print("SUMMARY (sorted by F1-score on OBFUSCATED test set)")
    print("=" * 100)
    print(results_df.to_string(index=False, float_format=lambda x: f"{x:.4f}"))
    print(f"\n[03] Full results: {RESULTS_DIR/'metrics.csv'}")
    print(f"[03] Confusion matrices: {RESULTS_DIR/'confusion_matrices.txt'}")
