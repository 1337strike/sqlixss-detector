"""
Usage:
    python scripts/02_train_models.py

Loads data/processed/train.csv, trains Logistic Regression, Multinomial
Naive Bayes, and Linear SVM (each with its own TF-IDF vectorizer inside a
Pipeline), and saves them to models/*.joblib.
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd

from src.models import train_all, save_models

PROCESSED_DIR = Path(__file__).resolve().parent.parent / "data" / "processed"

if __name__ == "__main__":
    train_path = PROCESSED_DIR / "train.csv"
    if not train_path.exists():
        raise SystemExit(f"{train_path} not found. Run scripts/01_build_dataset.py first.")

    train_df = pd.read_csv(train_path).dropna(subset=["payload", "label"])
    X_train = train_df["payload"].astype(str).tolist()
    y_train = train_df["label"].tolist()

    print(f"[02] Training on {len(X_train)} samples: "
          f"{train_df['label'].value_counts().to_dict()}")

    t0 = time.perf_counter()
    models = train_all(X_train, y_train)
    t1 = time.perf_counter()
    print(f"[02] Total training time: {t1 - t0:.2f}s")

    save_models(models)
    print("[02] Done. See models/*.joblib")
