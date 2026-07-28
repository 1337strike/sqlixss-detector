"""
Quick end-to-end smoke test. Not a full unit-test suite -- just enough to
catch "I broke the pipeline" before you spend time re-running the full
scripts/01-03 sequence.

Run:
    python -m tests.test_pipeline
(from the project root)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.tokenizer import tokenize
from src.obfuscation import random_obfuscate
from src.dataset import build_dataset
from src.models import train_all
from src.baseline_signature import SignatureBaseline
from src.evaluate import compute_classification_metrics


def test_tokenizer_preserves_special_chars():
    tokens = tokenize("' OR 1=1 --")
    assert "'" in tokens and "=" in tokens and "1" in tokens
    print("[ok] tokenizer preserves special characters")


def test_obfuscation_changes_payload():
    original = "' OR 1=1 --"
    obfuscated, techniques = random_obfuscate(original, seed=1)
    assert obfuscated != original
    assert len(techniques) >= 1
    print(f"[ok] obfuscation applied {techniques}")


def test_dataset_has_three_classes():
    parts = build_dataset(seed=1)
    labels = set(parts["train"]["label"].unique())
    assert labels == {"benign", "sqli", "xss"}
    print("[ok] dataset has benign/sqli/xss classes:", parts["train"]["label"].value_counts().to_dict())


def test_models_train_and_predict():
    parts = build_dataset(seed=1)
    models = train_all(
        parts["train"]["payload"].tolist()[:300],
        parts["train"]["label"].tolist()[:300],
    )
    for name, model in models.items():
        pred = model.predict(["' OR 1=1 --"])
        assert pred[0] in ("benign", "sqli", "xss")
    print("[ok] all 3 models train and predict")


def test_baseline_predicts():
    baseline = SignatureBaseline()
    pred = baseline.predict(["<script>alert(1)</script>", "id=5"])
    assert pred == ["xss", "benign"]
    print("[ok] signature baseline predicts correctly on clean samples")


def test_metrics_computation():
    y_true = ["benign", "sqli", "xss", "benign"]
    y_pred = ["benign", "sqli", "benign", "benign"]
    metrics = compute_classification_metrics(y_true, y_pred)
    assert 0.0 <= metrics["accuracy"] <= 1.0
    assert metrics["confusion_matrix"].shape == (3, 3)
    print(f"[ok] metrics computed: accuracy={metrics['accuracy']:.2f}")


if __name__ == "__main__":
    test_tokenizer_preserves_special_chars()
    test_obfuscation_changes_payload()
    test_dataset_has_three_classes()
    test_models_train_and_predict()
    test_baseline_predicts()
    test_metrics_computation()
    print("\nALL SMOKE TESTS PASSED")
