"""
ensemble.py
-----------
Production WAFs almost never rely on a single model -- they layer several
detection mechanisms and combine their verdicts, precisely because each
mechanism has different blind spots (a signature rule catches obvious
attacks near-instantly; a statistical classifier catches obfuscated
variants the signature misses; a second/third classifier catches whatever
the first one's training data happened to under-represent).

This module combines the 3 ML classifiers + the signature baseline into a
single verdict using a configurable voting policy:

  - "any"      : block if ANY detector flags the payload malicious
                 (maximum recall / most paranoid -- fewer false negatives,
                 more false positives. Default for a "security-first" WAF.)
  - "majority" : block if more than half the detectors agree
                 (balanced recall/precision)
  - "all"      : block only if EVERY detector agrees
                 (maximum precision -- fewest false positives, but an
                 attacker only needs to fool one weak detector to slip
                 through the crack between them)

Also returns a per-request explanation (which detector(s) fired, and on
what predicted label) -- this is what a real WAF's "why was this blocked"
log entry looks like, which matters for both debugging and for justifying
false positives to whoever's app you just blocked.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

VotingPolicy = Literal["any", "majority", "all"]


@dataclass
class Verdict:
    blocked: bool
    final_label: str                 # "benign" | "sqli" | "xss"
    votes: dict[str, str]             # {detector_name: predicted_label}
    triggered_by: list[str] = field(default_factory=list)  # detectors that voted malicious


class EnsembleDetector:
    def __init__(self, detectors: dict[str, object], policy: VotingPolicy = "any"):
        """
        detectors : {name: object with .predict(list[str]) -> list[str]}
                    typically {"logistic_regression": ..., "naive_bayes": ...,
                               "svm": ..., "signature_baseline": ...}
        policy    : "any" | "majority" | "all" (see module docstring)
        """
        if not detectors:
            raise ValueError("EnsembleDetector needs at least one detector")
        self.detectors = detectors
        self.policy = policy

    def classify(self, payload: str) -> Verdict:
        votes = {name: det.predict([payload])[0] for name, det in self.detectors.items()}
        triggered = [name for name, label in votes.items() if label != "benign"]

        n = len(self.detectors)
        n_triggered = len(triggered)

        if self.policy == "any":
            blocked = n_triggered >= 1
        elif self.policy == "all":
            blocked = n_triggered == n
        elif self.policy == "majority":
            blocked = n_triggered > n / 2
        else:
            raise ValueError(f"Unknown policy: {self.policy}")

        if blocked and triggered:
            # report the most common non-benign label among triggered detectors
            labels = [votes[t] for t in triggered]
            final_label = max(set(labels), key=labels.count)
        else:
            final_label = "benign"

        return Verdict(blocked=blocked, final_label=final_label, votes=votes, triggered_by=triggered)


if __name__ == "__main__":
    # tiny smoke test with fake detectors (no need to load real models here)
    class _FakeDetector:
        def __init__(self, fixed_label): self.fixed_label = fixed_label
        def predict(self, payloads): return [self.fixed_label] * len(payloads)

    detectors = {
        "d1": _FakeDetector("benign"),
        "d2": _FakeDetector("sqli"),
        "d3": _FakeDetector("benign"),
    }

    for policy in ("any", "majority", "all"):
        ens = EnsembleDetector(detectors, policy=policy)
        v = ens.classify("' OR 1=1 --")
        print(f"policy={policy:9} blocked={v.blocked!s:5} label={v.final_label:8} "
              f"triggered_by={v.triggered_by} votes={v.votes}")
