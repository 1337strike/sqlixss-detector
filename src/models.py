"""
models.py
---------
The three lightweight classifiers from Chapter 3, Section 3.5:
  - Logistic Regression (LR)
  - Multinomial Naive Bayes (MNB)
  - Linear-kernel Support Vector Machine (SVM)

Each is wrapped in a scikit-learn Pipeline(vectorizer -> classifier) so a
single object handles raw payload strings in, label out -- this is exactly
what the real-time sniffer needs at inference time (Module 3 + Module 4
collapsed into one `.predict()` call).
"""

from __future__ import annotations

from pathlib import Path

import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV

from src.features import build_vectorizer

MODELS_DIR = Path(__file__).resolve().parent.parent / "models"


def get_model_definitions() -> dict[str, Pipeline]:
    """Returns {name: untrained sklearn Pipeline} for all three classifiers.

    Each pipeline gets its OWN vectorizer instance (fit independently per
    model) so that comparisons stay clean and each model's pipeline is
    fully self-contained and independently deployable/picklable.
    """
    return {
        "logistic_regression": Pipeline([
            ("tfidf", build_vectorizer()),
            ("clf", LogisticRegression(max_iter=1000, C=10.0)),
        ]),
        "naive_bayes": Pipeline([
            ("tfidf", build_vectorizer()),
            ("clf", MultinomialNB()),
        ]),
        # LinearSVC has no predict_proba by default; CalibratedClassifierCV
        # adds probability estimates (useful later for ROC curves / thresholds)
        # while keeping LinearSVC's fast, margin-based decision boundary.
        "svm": Pipeline([
            ("tfidf", build_vectorizer()),
            ("clf", CalibratedClassifierCV(LinearSVC(C=1.0, dual="auto"), cv=3)),
        ]),
    }


def train_all(X_train: list[str], y_train: list[str]) -> dict[str, Pipeline]:
    models = get_model_definitions()
    for name, pipeline in models.items():
        print(f"[models] training {name} ...")
        pipeline.fit(X_train, y_train)
    return models


def save_models(models: dict[str, Pipeline], out_dir: Path = MODELS_DIR) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, pipeline in models.items():
        path = out_dir / f"{name}.joblib"
        joblib.dump(pipeline, path)
        print(f"[models] saved {path}")


def load_model(name: str, models_dir: Path = MODELS_DIR) -> Pipeline:
    path = models_dir / f"{name}.joblib"
    if not path.exists():
        raise FileNotFoundError(
            f"{path} not found. Run scripts/02_train_models.py first."
        )
    return joblib.load(path)


def load_all_models(models_dir: Path = MODELS_DIR) -> dict[str, Pipeline]:
    return {
        name: load_model(name, models_dir)
        for name in ("logistic_regression", "naive_bayes", "svm")
    }


if __name__ == "__main__":
    # tiny smoke test (needs >=3 samples/class since SVM calibration uses cv=3)
    X = [
        "id=5", "page=2", "sort=asc", "q=laptop",
        "' OR 1=1 --", "UNION SELECT * FROM users", "admin' --",
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>",
    ]
    y = ["benign", "benign", "benign", "benign",
         "sqli", "sqli", "sqli",
         "xss", "xss", "xss"]
    models = train_all(X, y)
    for name, pipe in models.items():
        pred = pipe.predict(["' OR 1=1 --"])
        print(f"{name}: predicted {pred[0]} for a known SQLi sample")
