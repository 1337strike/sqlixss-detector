"""
anomaly_detection.py
---------------------
A statistical ML classifier (this project's LR/MNB/SVM included) can only
ever recognize patterns shaped like what it was trained on. An adversarial
payload built specifically to sit outside that training distribution --
extreme percent-encoding density, absurd length, unusual character-class
ratios -- is a well-documented way to evade ANY trained classifier,
including this one. This is not a flaw specific to this project; it's an
inherent property of statistical/learned detectors in general.

This module doesn't (and can't) "solve" that -- no single technique does.
What it adds is a second, DIFFERENT kind of signal that doesn't depend on
the trained model at all: simple, explainable statistical anomaly checks
on the raw request text. An attacker who successfully crafts a payload
that evades the TF-IDF/ML models specifically often does so by pushing one
of these statistics to an extreme (heavy percent-encoding to break
tokenization, padding a benign-looking prefix to dilute the malicious
n-grams, etc.) -- so this acts as an independent check that doesn't share
the ML models' blind spots, precisely because it isn't a learned model at
all.

This is a mitigation, not a solution: a sufufficiently patient attacker
who stays within "normal-looking" statistics can still evade both this
AND the ML models. Treat this the same way as everything else in
`config.models` -- one more voting member in the ensemble, not a
guarantee.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class AnomalyConfig:
    max_length: int = 2048              # single parameter/header value longer than this is unusual
    max_percent_encoded_ratio: float = 0.35   # fraction of chars that are part of a %XX sequence
    max_special_char_ratio: float = 0.5       # fraction of non-alphanumeric characters
    min_length_for_ratio_checks: int = 20     # don't apply ratio checks to very short strings (too noisy)


_PERCENT_ENCODED_RE = re.compile(r"%[0-9A-Fa-f]{2}")


class AnomalyDetector:
    """Exposes the same .predict(list[str]) -> list[str] interface as
    every other detector in this project, so it drops straight into
    EnsembleDetector alongside the ML models and the signature baseline."""

    def __init__(self, config: AnomalyConfig | None = None):
        self.config = config or AnomalyConfig()

    def _score_one(self, text: str) -> tuple[bool, list[str]]:
        reasons = []
        length = len(text)

        if length > self.config.max_length:
            reasons.append(f"length={length}>{self.config.max_length}")

        if length >= self.config.min_length_for_ratio_checks:
            percent_matches = _PERCENT_ENCODED_RE.findall(text)
            percent_encoded_chars = len(percent_matches) * 3  # each match is 3 chars: %XX
            percent_ratio = percent_encoded_chars / length
            if percent_ratio > self.config.max_percent_encoded_ratio:
                reasons.append(f"percent_encoded_ratio={percent_ratio:.2f}")

            special_chars = sum(1 for c in text if not c.isalnum() and not c.isspace())
            special_ratio = special_chars / length
            if special_ratio > self.config.max_special_char_ratio:
                reasons.append(f"special_char_ratio={special_ratio:.2f}")

        return (len(reasons) > 0, reasons)

    def predict(self, payloads: list[str]) -> list[str]:
        """Returns "anomalous" or "benign" per payload -- deliberately NOT
        "sqli"/"xss", since this check has no idea which attack class it
        might be; it only knows the input LOOKS statistically unusual."""
        results = []
        for text in payloads:
            flagged, _ = self._score_one(text)
            results.append("anomalous" if flagged else "benign")
        return results

    def explain(self, text: str) -> list[str]:
        """Same check as predict(), but returns the specific reason(s) --
        used by the WAF's logger so a blocked request's log line says
        *why* it was flagged as anomalous, not just that it was."""
        _, reasons = self._score_one(text)
        return reasons


if __name__ == "__main__":
    detector = AnomalyDetector()
    cases = [
        ("normal search query", "q=laptop&sort=asc"),
        ("normal-length SQLi (should be caught by ML/signature anyway)", "' OR 1=1 --"),
        ("heavily percent-encoded evasion attempt", "%27%20%4F%52%20%31%3D%31%20%2D%2D%20%20%20%20%20%20%20%20"),
        ("absurdly long single value (padding/DoS-ish)", "a" * 3000),
        ("special-character-dense obfuscation", "!@#$%^&*()_+-=[]{}|;:,.<>?/~`" * 3),
        ("normal sentence-like text", "the quick brown fox jumps over the lazy dog"),
    ]
    for name, text in cases:
        flagged, reasons = detector._score_one(text)
        print(f"{name:60} flagged={flagged!s:5} reasons={reasons}")
