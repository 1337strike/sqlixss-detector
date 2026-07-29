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


def test_obfuscation_is_deterministic():
    """Regression test: obfuscation functions must use the seeded rng
    (not the global `random` module), or results won't be reproducible
    across runs -- this exact bug was caught and fixed once already."""
    payload = "' OR 1=1 --"
    for seed in range(10):
        a, _ = random_obfuscate(payload, seed=seed)
        b, _ = random_obfuscate(payload, seed=seed)
        assert a == b, f"seed={seed} produced non-deterministic output: {a!r} vs {b!r}"
    print("[ok] obfuscation is deterministic across repeated calls with the same seed")


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


def test_ensemble_any_policy_blocks_on_single_vote():
    from src.ensemble import EnsembleDetector

    class _Fake:
        def __init__(self, label): self.label = label
        def predict(self, payloads): return [self.label] * len(payloads)

    ensemble = EnsembleDetector(
        {"a": _Fake("benign"), "b": _Fake("sqli")}, policy="any"
    )
    verdict = ensemble.classify("' OR 1=1 --")
    assert verdict.blocked is True
    assert verdict.final_label == "sqli"
    assert "b" in verdict.triggered_by
    print("[ok] ensemble 'any' policy blocks when at least one detector flags malicious")


def test_rate_limiter_bans_after_threshold():
    from src.rate_limiter import RateLimiter, RateLimiterConfig

    rl = RateLimiter(RateLimiterConfig(offense_window_seconds=30, offense_threshold=3, ban_duration_seconds=10))
    ip = "198.51.100.23"
    assert rl.is_blocked(ip) is False
    for _ in range(2):
        assert rl.record_offense(ip) is False   # not banned yet
    assert rl.record_offense(ip) is True        # 3rd offense triggers the ban
    assert rl.is_blocked(ip) is True
    print("[ok] rate limiter auto-bans an IP after crossing the offense threshold")


def test_inmemory_stats_counts_correctly():
    from src.waf_stats import InMemoryStats

    s = InMemoryStats()
    s.increment("allowed")
    s.increment("allowed")
    s.increment("blocked")
    result = s.get_all()
    assert result["allowed"] == 2
    assert result["blocked"] == 1
    print("[ok] in-memory stats counter accumulates correctly")


def test_trusted_proxy_ip_resolution():
    from unittest.mock import MagicMock
    from src.waf_proxy import resolve_client_ip

    # Case 1: no trusted proxies configured -> always use the direct IP,
    # NEVER trust a client-supplied X-Forwarded-For (anti-spoofing default)
    req = MagicMock(remote="203.0.113.9", headers={"X-Forwarded-For": "9.9.9.9"})
    assert resolve_client_ip(req, trusted_proxies=[]) == "203.0.113.9"

    # Case 2: request comes from a configured trusted proxy -> trust
    # X-Forwarded-For's left-most (original client) address
    req2 = MagicMock(remote="127.0.0.1", headers={"X-Forwarded-For": "198.51.100.5, 127.0.0.1"})
    assert resolve_client_ip(req2, trusted_proxies=["127.0.0.1"]) == "198.51.100.5"

    # Case 3: direct connection is NOT in trusted_proxies -> ignore
    # X-Forwarded-For even if present (don't let a random client spoof it)
    req3 = MagicMock(remote="203.0.113.9", headers={"X-Forwarded-For": "9.9.9.9"})
    assert resolve_client_ip(req3, trusted_proxies=["127.0.0.1"]) == "203.0.113.9"

    print("[ok] trusted-proxy IP resolution only trusts X-Forwarded-For from configured proxies")


def test_recon_detection_flags_known_scanner_tools():
    from src.recon_detection import classify_recon

    # Normal browser must NEVER be flagged
    v = classify_recon("/search?q=laptop", {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}, "203.0.113.5", [])
    assert v.flagged is False

    # Known pentest-tool signatures (sqlmap, and HexStrike's own hardcoded UA)
    v = classify_recon("/search?q=1", {"User-Agent": "sqlmap/1.7.2#stable (http://sqlmap.org)"}, "203.0.113.5", [])
    assert v.flagged is True
    v = classify_recon("/", {"User-Agent": "HexStrike-HTTP-Framework/1.0 (Advanced Security Testing)"}, "203.0.113.5", [])
    assert v.flagged is True

    # Sensitive-path probing (what gobuster/dirb/ffuf/dirsearch wordlists always hit)
    v = classify_recon("/.git/config", {"User-Agent": "Mozilla/5.0"}, "203.0.113.5", [])
    assert v.flagged is True

    # Spoofed X-Forwarded-For from an UNtrusted source -> flagged (this is
    # the exact IP-spoofing technique HexStrike's own code uses)
    v = classify_recon("/admin", {"User-Agent": "Mozilla/5.0", "X-Forwarded-For": "127.0.0.1"}, "203.0.113.5", [])
    assert v.flagged is True

    # Same header, but the source IS a configured trusted proxy -> NOT flagged
    v = classify_recon("/admin", {"User-Agent": "Mozilla/5.0", "X-Forwarded-For": "198.51.100.9"}, "127.0.0.1", ["127.0.0.1"])
    assert v.flagged is False

    print("[ok] recon detection flags known scanner UAs, sensitive paths, and untrusted IP-spoofing attempts")


def test_header_content_uses_signature_only_not_ml_ensemble():
    """
    Regression test for a real bug found during development: the ML
    ensemble, trained on query/body-shaped text, misclassified an ordinary
    browser User-Agent as SQLi (false positive from domain shift). Header
    content must be checked with the signature baseline only.
    """
    from src.baseline_signature import SignatureBaseline

    sig = SignatureBaseline()
    normal_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    assert sig.predict([normal_ua])[0] == "benign"

    # A genuine SQLi payload placed in a header (sqlmap --level 3+ style)
    # must still be caught
    assert sig.predict(["' OR SLEEP(5)-- -"])[0] == "sqli"

    print("[ok] header inspection (signature-only) has no false positive on a normal User-Agent, "
          "and still catches SQLi injected into a header")


if __name__ == "__main__":
    test_tokenizer_preserves_special_chars()
    test_obfuscation_changes_payload()
    test_obfuscation_is_deterministic()
    test_dataset_has_three_classes()
    test_models_train_and_predict()
    test_baseline_predicts()
    test_metrics_computation()
    test_ensemble_any_policy_blocks_on_single_vote()
    test_rate_limiter_bans_after_threshold()
    test_inmemory_stats_counts_correctly()
    test_trusted_proxy_ip_resolution()
    test_recon_detection_flags_known_scanner_tools()
    test_header_content_uses_signature_only_not_ml_ensemble()
    print("\nALL SMOKE TESTS PASSED")
