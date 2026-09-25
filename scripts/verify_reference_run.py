"""
verify_reference_run.py
------------------------
Checks that a fresh definitive_experiment.py run reproduces the paper's
reference run (results/definitive_20260923T094339Z_42) exactly.

Compared: all 240 fold-level F1 scores (Tables I, IV), the 16 single-split
confusion matrices (Table II) and the 35 per-technique drops (Table III).
Latency (Table V) is wall-clock and is not compared.

Run (pinned environment from requirements.lock):
    python scripts/definitive_experiment.py --seed 42 --folds 5 --repeats 3
    python scripts/verify_reference_run.py            # newest run vs reference
    python scripts/verify_reference_run.py results/definitive_<ts>_42

Exits 1 on any mismatch.
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

RESULTS = Path(__file__).resolve().parent.parent / "results"
REFERENCE = RESULTS / "definitive_20260923T094339Z_42"
TOL = 1e-12


def _per_technique(run: Path) -> dict[tuple[str, str], float]:
    with open(run / "per_technique.csv") as f:
        # the reference run labels one technique "..._UNDISCLOSED" (see its NOTE.md)
        return {(r["technique"].replace("_UNDISCLOSED", ""), r["detector"]): float(r["f1_drop"])
                for r in csv.DictReader(f)}


def verify(run: Path) -> list[str]:
    errors = []

    ref = json.loads((REFERENCE / "fold_scores.json").read_text())["fold_scores"]
    new = json.loads((run / "fold_scores.json").read_text())["fold_scores"]
    n = 0
    for cfg, conds in ref.items():
        for cond, scores in conds.items():
            got = new.get(cfg, {}).get(cond, [])
            if len(got) != len(scores):
                errors.append(f"fold_scores {cfg}/{cond}: {len(got)} folds, expected {len(scores)}")
                continue
            for i, (a, b) in enumerate(zip(scores, got)):
                n += 1
                if abs(a - b) > TOL:
                    errors.append(f"fold_scores {cfg}/{cond}[{i}]: {b} != {a}")
    print(f"  fold-level F1 scores compared: {n}")

    ref = json.loads((REFERENCE / "single_split.json").read_text())["detectors"]
    new = json.loads((run / "single_split.json").read_text())["detectors"]
    n = 0
    for cfg, conds in ref.items():
        for cond in ("clean", "obf"):
            n += 1
            if new[cfg][cond]["confusion_matrix"] != conds[cond]["confusion_matrix"]:
                errors.append(f"confusion matrix {cfg}/{cond} differs")
    print(f"  confusion matrices compared:   {n}")

    ref, new = _per_technique(REFERENCE), _per_technique(run)
    for key, a in ref.items():
        if key not in new:
            errors.append(f"per_technique {key} missing")
        elif abs(new[key] - a) > TOL:
            errors.append(f"per_technique {key}: {new[key]} != {a}")
    print(f"  per-technique drops compared:  {len(ref)}")

    return errors


if __name__ == "__main__":
    if len(sys.argv) > 1:
        run = Path(sys.argv[1])
    else:
        runs = sorted(p for p in RESULTS.glob("definitive_*") if p != REFERENCE)
        if not runs:
            sys.exit("no run found; run scripts/definitive_experiment.py first")
        run = runs[-1]
    print(f"[verify] {run.name} vs {REFERENCE.name}")
    errors = verify(run)
    if errors:
        print(f"\n[verify] FAIL: {len(errors)} mismatch(es)")
        for e in errors[:20]:
            print("  " + e)
        sys.exit(1)
    print("\n[verify] OK: reproduces the reference run exactly")
