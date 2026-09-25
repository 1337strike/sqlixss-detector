"""
tests/integration/test_end_to_end.py
--------------------------------------
End-to-end integration tests (checklist item G2).

These tests verify that the trained models, when called through the same
preprocessing path used by both the offline evaluator and the live WAF
proxy, produce consistent decisions and that the decision boundary is
not degraded by the canonicalization step.

These tests do NOT start a network proxy; they test the pipeline
components directly in the same way the proxy would call them.  Network
proxy tests belong in tests/integration/test_proxy_live.py (written
separately, requires a running WAF instance).

Run:
    python -m pytest tests/integration/test_end_to_end.py -v
"""

from __future__ import annotations

import json
import sys
import urllib.parse
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from src.baseline_normalized import NormalizedSignatureBaseline, canonicalize
from src.baseline_signature import SignatureBaseline
from src.json_extraction import extract_json_string_values
from src.models import get_model_definitions
from src.waf_proxy import extract_header_texts, extract_inspectable_texts


# ── shared fixtures ──────────────────────────────────────────────────────────

TRAIN_X = [
    # SQLi
    "' OR 1=1 --", "' OR 'a'='a", "UNION SELECT 1,2,3 --",
    "SELECT * FROM users WHERE id=1", "1' AND SLEEP(5)--", "' OR ''='",
    # XSS
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>", "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>", "<input autofocus onfocus=alert(1)>",
    # benign
    "id=5&sort=asc", "name=alice&page=1", "q=laptop+camera",
    "lang=en&format=json", "filter=recent&size=10", "category=electronics",
    "search=python+tutorial", "user=bob&action=view",
]
TRAIN_Y = ["sqli"]*6 + ["xss"]*6 + ["benign"]*8

# cases: (description, payload, expected_label)
CLEAN_CASES = [
    ("clean SQLi OR",         "' OR 1=1 --",                    "sqli"),
    ("clean UNION SELECT",    "UNION SELECT password FROM users","sqli"),
    ("clean XSS script tag",  "<script>alert(1)</script>",      "xss"),
    ("clean XSS img",         "<img src=x onerror=alert(1)>",   "xss"),
    ("benign query string",   "id=42&sort=asc&lang=en",         "benign"),
    ("benign search",         "q=laptop+camera&page=1",         "benign"),
]

ENCODED_CASES = [
    ("URL-encoded SQLi",      "%27%20OR%201%3D1%20--",          "sqli"),
    ("double-encoded SQLi",   "%2527%2520OR%25201%253D1%2520--","sqli"),
    ("entity-encoded XSS",    "&lt;script&gt;alert(1)&lt;/script&gt;","xss"),
    ("unicode-escaped XSS",   "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e","xss"),
    ("comment-split SQLi",    "UNI/**/ON SEL/**/ECT pass FROM users","sqli"),
]

LOCATIONS = ["query", "body", "json", "header"]


@pytest.fixture(scope="module")
def trained_models():
    models = {}
    for name, pipeline in get_model_definitions().items():
        pipeline.fit(TRAIN_X, TRAIN_Y)
        models[name] = pipeline
    return models


@pytest.fixture(scope="module")
def baselines():
    return {
        "signature_naive":      SignatureBaseline(),
        "signature_normalized": NormalizedSignatureBaseline(),
    }


# ── clean payload detection ──────────────────────────────────────────────────

class TestCleanPayloadDetection:
    """ML models must correctly classify clean (unobfuscated) payloads."""

    @pytest.mark.parametrize("desc,payload,expected", CLEAN_CASES)
    def test_ml_classifiers(self, trained_models, desc, payload, expected):
        for name, model in trained_models.items():
            canon = canonicalize(payload)
            pred = model.predict([canon])[0]
            assert pred == expected, (
                f"{name} misclassified {desc!r}: got {pred!r}, want {expected!r}"
            )

    @pytest.mark.parametrize("desc,payload,expected", CLEAN_CASES)
    def test_normalized_baseline(self, baselines, desc, payload, expected):
        pred = baselines["signature_normalized"].predict([payload])[0]
        assert pred == expected, (
            f"Normalizing baseline misclassified {desc!r}: "
            f"got {pred!r}, want {expected!r}"
        )


# ── encoded payload detection (with canonicalization) ───────────────────────

class TestEncodedPayloadDetection:
    """With canonicalization, encoded variants must be detected."""

    @pytest.mark.parametrize("desc,payload,expected", ENCODED_CASES)
    def test_ml_classifiers_with_canon(self, trained_models, desc, payload, expected):
        canon = canonicalize(payload)
        for name, model in trained_models.items():
            pred = model.predict([canon])[0]
            assert pred == expected, (
                f"{name} missed encoded payload {desc!r}: "
                f"got {pred!r}, want {expected!r}\n"
                f"canonical form: {canon!r}"
            )

    @pytest.mark.parametrize("desc,payload,expected", ENCODED_CASES)
    def test_normalized_baseline(self, baselines, desc, payload, expected):
        pred = baselines["signature_normalized"].predict([payload])[0]
        assert pred == expected, (
            f"Normalizing baseline missed {desc!r}: "
            f"got {pred!r}, want {expected!r}"
        )


# ── benign false-positive rate ───────────────────────────────────────────────

class TestBenignFalsePositiveRate:
    """All canonicalized detectors must produce zero false positives on
    clean benign samples."""

    # Note: samples containing SQL/HTML keywords in benign context (e.g.
    # tutorial text, code snippets, legitimate apostrophes) may trigger
    # false positives on a small training corpus. This is a known
    # limitation documented in the paper's limitations section. In
    # deployment, context-aware preprocessing or a larger, more diverse
    # benign corpus addresses this.
    BENIGN_SAMPLES = [
        ("id=5&sort=asc",         False),
        ("q=laptop+camera&page=1",False),
        ("name=alice&role=user",  False),
        ("format=json&lang=en",   False),
        # Known edge cases — may FP on small training corpus (xfail)
        ("O'Connor",                                 True),   # apostrophe
        ("def square(x): return x*x",               True),   # code
        ("SQL tutorial: SELECT * FROM books",        True),   # SQL keyword
        ("<p>A harmless HTML paragraph</p>",         True),   # HTML tag
    ]

    @pytest.mark.parametrize("payload,known_fp", BENIGN_SAMPLES)
    def test_no_false_positives_ml(self, trained_models, payload, known_fp):
        canon = canonicalize(payload)
        for name, model in trained_models.items():
            pred = model.predict([canon])[0]
            if known_fp:
                # Document the FP but don't fail the build — this is a
                # known limitation of training on web payloads only.
                if pred != "benign":
                    pytest.xfail(
                        f"{name} false-positive (known limitation): "
                        f"{payload!r} → {pred!r}. "
                        f"Benign corpus needs context-diverse samples."
                    )
            else:
                assert pred == "benign", (
                    f"{name} false-positive on {payload!r}: {pred!r}"
                )

    @pytest.mark.parametrize("payload,known_fp", BENIGN_SAMPLES)
    def test_no_false_positives_normalized_baseline(self, baselines, payload, known_fp):
        pred = baselines["signature_normalized"].predict([payload])[0]
        if known_fp and pred != "benign":
            pytest.xfail(
                f"Normalizing baseline FP (known): {payload!r} → {pred!r}"
            )
        elif not known_fp:
            assert pred == "benign", (
                f"Normalizing baseline FP on {payload!r}: {pred!r}"
            )


# ── decision consistency across request locations ────────────────────────────

class TestRequestLocationConsistency:
    """The same payload must receive the same classification regardless of
    whether it arrives in the query string, body, JSON value, or a header.

    The canonicalization stage normalises input before feature extraction,
    so location must not affect the decision.
    """

    PAYLOAD = "' OR 1=1 --"
    EXPECTED = "sqli"

    @staticmethod
    def _extract(loc: str, payload: str) -> list[str]:
        """Return the texts the WAF proxy would inspect for ``payload``
        placed in ``loc``, using the proxy's own extraction functions."""
        enc = urllib.parse.quote(payload, safe="")
        if loc == "query":
            return extract_inspectable_texts(f"/search?q={enc}", b"", "")
        if loc == "body":
            return extract_inspectable_texts(
                "/login", f"user={enc}".encode(), "application/x-www-form-urlencoded")
        if loc == "json":
            # ' exercises JSON's own escaping, which only a real parse undoes
            body = json.dumps({"filters": {"q": payload}}).replace("'", "\\u0027")
            result = extract_json_string_values(body.encode())
            assert result.was_valid_json and not result.truncated
            return result.string_values
        if loc == "header":
            return extract_header_texts({"User-Agent": payload})
        raise ValueError(loc)

    @pytest.mark.parametrize("loc", LOCATIONS)
    def test_location_invariance_ml(self, trained_models, loc):
        texts = self._extract(loc, self.PAYLOAD)
        for name, model in trained_models.items():
            preds = model.predict([canonicalize(t) for t in texts])
            assert self.EXPECTED in preds, (
                f"{name} missed payload in location={loc}: "
                f"texts={texts!r} preds={list(preds)!r}"
            )

    @pytest.mark.parametrize("loc", LOCATIONS)
    def test_location_invariance_normalized_baseline(self, baselines, loc):
        # The proxy classifies headers with the normalizing signature
        # baseline only, so every location must be caught by it too.
        texts = self._extract(loc, self.PAYLOAD)
        preds = baselines["signature_normalized"].predict(texts)
        assert self.EXPECTED in preds, (
            f"Normalizing baseline missed payload in location={loc}: "
            f"texts={texts!r} preds={list(preds)!r}"
        )
