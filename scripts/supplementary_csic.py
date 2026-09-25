#!/usr/bin/env python3
"""
scripts/supplementary_csic.py
==============================
Supplementary evaluation (paper §IV-F): false-positive rate of the paper's
8 detector configurations on realistic benign traffic, the CSIC 2010 HTTP
dataset's normal test set (normalTrafficTest.txt, 36,000 requests).

Protocol
- Models: the 8 configurations are retrained with the paper's own single-split
  code, definitive_experiment.run_single_split() (749-sample training split,
  seed 42). Before anything is evaluated, all 16 single-split confusion
  matrices are asserted identical to the reference run
  results/definitive_20260923T094339Z_42/single_split.json, and the captured
  model objects are re-checked against the same matrices.
- Level: classifier only. No WAF layers (no AbstainOnUnknown, ensemble,
  rate limiting or request validation).
- Input per request: the query string for GET, the body for POST -- the
  same `k=v&k=v` shape as the paper's benign samples -- exactly as it appears
  on the wire (percent-encoding intact). Requests without parameters are
  evaluated as the empty string and counted separately.
- Raw configs get the raw input; canonicalized ML configs get
  canonicalize(input); the normalizing signature gets the raw input and
  canonicalizes internally (same routing as the paper).
- Every non-benign prediction (sqli or xss) on a CSIC normal request is a
  false positive. Nothing is tuned.

Environment: Python 3.12 + requirements.lock (versions are checked).

RUN:
    python scripts/00b_fetch_csic2010.py
    python scripts/supplementary_csic.py

Writes results/supplementary_<timestamp>/:
    csic2010_fpr.json        full results + provenance + environment
    csic2010_fpr.md          FP count and rate per configuration
    csic2010_fp_inputs.csv   every distinct flagged input, per configuration
"""
from __future__ import annotations

import csv
import hashlib
import importlib.util
import json
import math
import platform
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.baseline_normalized import NormalizedSignatureBaseline, canonicalize
from src.baseline_signature import SignatureBaseline

SEED = 42
REFERENCE = ROOT / "results" / "definitive_20260923T094339Z_42" / "single_split.json"
CSIC_FILE = ROOT / "data" / "external" / "csic2010" / "normalTrafficTest.txt"
EXPECTED_REQUESTS = 36_000

CONFIGS = [  # (key in single_split.json, paper label, input routing)
    ("logistic_regression_raw",        "LR (raw)",      "raw"),
    ("logistic_regression_normalized", "LR (canon.)",   "canonicalize(input)"),
    ("naive_bayes_raw",                "MNB (raw)",     "raw"),
    ("naive_bayes_normalized",         "MNB (canon.)",  "canonicalize(input)"),
    ("svm_raw",                        "SVM (raw)",     "raw"),
    ("svm_normalized",                 "SVM (canon.)",  "canonicalize(input)"),
    ("signature_raw",                  "Sig (raw)",     "raw"),
    ("signature_normalized",           "Sig (canon.)",  "raw; canonicalizes internally"),
]


def _load_script(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------
_LOCK_CHECKED = ("scikit-learn", "numpy", "scipy", "pandas", "joblib", "threadpoolctl")


def check_environment() -> dict:
    lock = {}
    for line in (ROOT / "requirements.lock").read_text().splitlines():
        m = re.match(r"^([A-Za-z0-9_.-]+)==(\S+)", line.strip())
        if m:
            lock[m.group(1).lower()] = m.group(2)
    problems = []
    if sys.version_info[:2] != (3, 12):
        problems.append(f"Python {platform.python_version()} (need 3.12)")
    installed = {}
    for pkg in _LOCK_CHECKED:
        installed[pkg] = version(pkg)
        if installed[pkg] != lock[pkg]:
            problems.append(f"{pkg} {installed[pkg]} (lock: {lock[pkg]})")
    if problems:
        sys.exit("[csic] environment does not match requirements.lock: "
                 + "; ".join(problems)
                 + "\n       python3.12 -m venv .venv && .venv/bin/pip install -r requirements.lock")
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        **installed,
    }


# ---------------------------------------------------------------------------
# Models: paper's single-split code, verified against the reference run
# ---------------------------------------------------------------------------
def train_paper_models(run_id: str) -> tuple[dict, dict, object]:
    """Run definitive_experiment.run_single_split() unchanged and capture the
    six ML pipelines it fits.
    Returns ({config: model}, single_split result, definitive_experiment module)."""
    de = _load_script("definitive_experiment", "definitive_experiment.py")

    calls = []
    original = de.get_model_definitions

    def recording_get_model_definitions():
        defs = original()
        calls.append(defs)
        return defs

    de.get_model_definitions = recording_get_model_definitions
    try:
        ss = de.run_single_split(SEED, run_id)
    finally:
        de.get_model_definitions = original

    # run_single_split calls get_model_definitions() once to iterate the model
    # names, then once per (model, raw) and once per (model, normalized), in
    # that order, fitting only the indexed pipeline of each call.
    names = list(original())
    assert len(calls) == 1 + 2 * len(names), f"unexpected call pattern: {len(calls)} calls"

    def fitted(pipe) -> bool:
        return hasattr(pipe[-1], "classes_")

    models = {}
    for i, name in enumerate(names):
        for j, variant in enumerate(("raw", "normalized")):
            defs = calls[1 + 2 * i + j]
            models[f"{name}_{variant}"] = defs[name]
            assert fitted(defs[name]), f"{name}_{variant} was not fitted"
            assert not any(fitted(p) for n, p in defs.items() if n != name)
    assert not any(fitted(p) for p in calls[0].values())

    models["signature_raw"] = SignatureBaseline()
    models["signature_normalized"] = NormalizedSignatureBaseline()
    return models, ss, de


def assert_reference(ss: dict, models: dict, de_full_metrics) -> int:
    """All 16 confusion matrices must equal the reference run's -- both as
    reported by run_single_split() and as recomputed from the captured models."""
    import pandas as pd

    ref = json.loads(REFERENCE.read_text())["detectors"]
    assert set(ref) == {c for c, _, _ in CONFIGS}, "reference configs differ"

    proc = ROOT / "data" / "processed"
    clean = pd.read_csv(proc / "test_clean.csv").dropna(subset=["payload", "label"])
    obf = pd.read_csv(proc / "test_obfuscated.csv").dropna(subset=["payload", "label"])
    sets = {"clean": clean, "obf": obf}

    mismatches, n = [], 0
    for cfg, _, routing in CONFIGS:
        for cond, df in sets.items():
            n += 1
            want = ref[cfg][cond]["confusion_matrix"]
            got_run = ss["detectors"][cfg][cond]["confusion_matrix"]
            X = df["payload"].tolist()
            if routing == "canonicalize(input)":
                X = [canonicalize(p) for p in X]
            got_model = de_full_metrics(df["label"].tolist(), models[cfg].predict(X))["confusion_matrix"]
            if got_run != want:
                mismatches.append(f"{cfg}/{cond}: run_single_split {got_run} != reference {want}")
            if got_model != want:
                mismatches.append(f"{cfg}/{cond}: captured model {got_model} != reference {want}")
    assert not mismatches, "reference run NOT reproduced:\n  " + "\n  ".join(mismatches)
    return n


# ---------------------------------------------------------------------------
# CSIC 2010 parsing
# ---------------------------------------------------------------------------
_REQUEST_LINE = re.compile(r"^(GET|POST|PUT) (\S+) HTTP/1\.[01]$")


def parse_csic(path: Path) -> list[dict]:
    lines = path.read_text(encoding="ascii").split("\n")
    starts = [i for i, l in enumerate(lines) if _REQUEST_LINE.match(l)]
    requests = []
    for k, s in enumerate(starts):
        block = lines[s: starts[k + 1] if k + 1 < len(starts) else len(lines)]
        method, url = _REQUEST_LINE.match(block[0]).groups()
        blank = block.index("", 1)
        headers = {}
        for h in block[1:blank]:
            key, _, value = h.partition(":")
            headers[key.strip().lower()] = value.strip()
        body_lines = block[blank + 1:]
        while body_lines and body_lines[-1] == "":
            body_lines.pop()
        body = "\n".join(body_lines)

        if method == "GET":
            inp = url.partition("?")[2]
            assert body == "", f"GET with body at line {s + 1}"
        elif method == "POST":
            inp = body
            assert len(body.encode()) == int(headers.get("content-length", -1)), \
                f"POST body length != Content-Length at line {s + 1}"
        else:
            raise AssertionError(f"unexpected method {method} at line {s + 1}")
        requests.append({"method": method, "url": url, "input": inp})
    return requests


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
def wilson(k: int, n: int, z: float = 1.959963984540054) -> tuple[float, float]:
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    lo = 0.0 if k == 0 else max(0.0, centre - half)  # exact 0 (not float noise) when k == 0
    return (lo, min(1.0, centre + half))


def fp_block(preds: list[str]) -> dict:
    n = len(preds)
    c = Counter(preds)
    fp = n - c.get("benign", 0)
    lo, hi = wilson(fp, n)
    return {
        "n": n,
        "fp": fp,
        "fp_rate": fp / n if n else float("nan"),
        "fp_rate_wilson95": [lo, hi],
        "pred_sqli": c.get("sqli", 0),
        "pred_xss": c.get("xss", 0),
    }


def pct(x: float) -> str:
    return f"{100 * x:.2f}%"


# ---------------------------------------------------------------------------
def main() -> None:
    env = check_environment()

    fetch = _load_script("fetch_csic2010", "00b_fetch_csic2010.py")
    meta = fetch.FILES["normalTrafficTest.txt"]
    if not CSIC_FILE.exists():
        sys.exit(f"[csic] {CSIC_FILE} missing; run: python scripts/00b_fetch_csic2010.py")
    digest = fetch.sha256(CSIC_FILE)
    assert digest == meta["sha256"], f"CSIC sha256 {digest} != pinned {meta['sha256']}"

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"supplementary_{ts}"
    out_dir = ROOT / "results" / run_id
    print(f"[csic] run_id = {run_id}")
    print(f"[csic] Python {env['python']} | scikit-learn {env['scikit-learn']} | numpy {env['numpy']}")

    # 1. Retrain with the paper's code and verify against the reference run
    print("[csic] Retraining 8 configurations with definitive_experiment.run_single_split ...")
    models, ss, de = train_paper_models(run_id)
    n_cm = assert_reference(ss, models, de.full_metrics)
    print(f"[csic] OK: {n_cm}/16 confusion matrices identical to {REFERENCE.parent.name}")
    print(f"       n_train={ss['n_train']} (class dist {ss['class_dist_train']})")
    assert ss["n_train"] == 749

    # 2. Parse CSIC 2010 normal test traffic
    reqs = parse_csic(CSIC_FILE)
    assert len(reqs) == EXPECTED_REQUESTS, f"parsed {len(reqs)} requests, expected {EXPECTED_REQUESTS}"
    X_raw = [r["input"] for r in reqs]
    has_params = [x != "" for x in X_raw]
    methods = Counter(r["method"] for r in reqs)
    no_params = Counter(r["method"] for r, h in zip(reqs, has_params) if not h)
    post_with_query = sum(1 for r in reqs if r["method"] == "POST" and "?" in r["url"])
    n_unique = len(set(X_raw))
    print(f"[csic] {len(reqs)} requests: {dict(methods)}; without parameters: "
          f"{sum(no_params.values())} {dict(no_params)}; distinct inputs: {n_unique}")

    X_canon = [canonicalize(x) for x in X_raw]

    # 3. Evaluate
    results, fp_rows = {}, []
    for cfg, label, routing in CONFIGS:
        X = X_canon if routing == "canonicalize(input)" else X_raw
        preds = list(models[cfg].predict(X))
        empty_pred = models[cfg].predict([""])[0]  # canonicalize("") == ""
        param_preds = [p for p, h in zip(preds, has_params) if h]
        flagged = Counter((x, p) for x, p in zip(X_raw, preds) if p != "benign")
        distinct_flagged = {x for x, _ in flagged}
        results[cfg] = {
            "label": label,
            "input_routing": routing,
            "all_requests": fp_block(preds),
            "parameterized_requests": fp_block(param_preds),
            "by_method": {m: fp_block([p for p, r in zip(preds, reqs) if r["method"] == m])
                          for m in sorted(methods)},
            "empty_input_prediction": str(empty_pred),
            "distinct_inputs_flagged": len(distinct_flagged),
            "distinct_inputs_total": n_unique,
        }
        for (x, p), cnt in sorted(flagged.items(), key=lambda kv: (-kv[1], kv[0])):
            fp_rows.append({"config": cfg, "prediction": p, "count": cnt, "input": x})
        a = results[cfg]["all_requests"]
        print(f"       {label:13} FP {a['fp']:>6}/{a['n']}  {pct(a['fp_rate']):>7}  "
              f"(sqli {a['pred_sqli']}, xss {a['pred_xss']}; empty -> {empty_pred})")

    # 4. Write outputs
    out_dir.mkdir(parents=True, exist_ok=False)
    doc = {
        "run_id": run_id,
        "description": "False-positive rate of the paper's 8 detector configurations on "
                       "CSIC 2010 normal test traffic (classifier level, no WAF layers).",
        "environment": env,
        "models": {
            "source": "scripts/definitive_experiment.py::run_single_split",
            "seed": SEED,
            "n_train": ss["n_train"],
            "class_dist_train": ss["class_dist_train"],
            "reference_run": REFERENCE.parent.name,
            "confusion_matrices_verified_identical": n_cm,
        },
        "dataset": {
            "name": "CSIC 2010 HTTP dataset, normalTrafficTest.txt",
            "path": CSIC_FILE.relative_to(ROOT).as_posix(),
            "mirror_repo": fetch.MIRROR_REPO,
            "mirror_commit": fetch.MIRROR_COMMIT,
            "sha256": digest,
            "n_requests": len(reqs),
            "by_method": dict(methods),
            "input_definition": "GET: query string after '?'; POST: request body; "
                                "as on the wire (percent-encoded)",
            "n_without_parameters": sum(no_params.values()),
            "without_parameters_by_method": dict(no_params),
            "n_with_parameters": sum(has_params),
            "n_distinct_inputs": n_unique,
            "post_requests_with_url_query": post_with_query,
        },
        "false_positive_definition": "any prediction other than 'benign'",
        "results": results,
    }
    (out_dir / "csic2010_fpr.json").write_text(json.dumps(doc, indent=2) + "\n")

    with open(out_dir / "csic2010_fp_inputs.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["config", "prediction", "count", "input"])
        w.writeheader()
        w.writerows(fp_rows)

    n_np, n_p = sum(no_params.values()), sum(has_params)
    md = [
        "# Supplementary: false positives on CSIC 2010 normal traffic",
        "",
        f"run_id: `{run_id}`",
        "",
        f"- Data: CSIC 2010 `normalTrafficTest.txt`, {len(reqs):,} benign requests "
        f"({methods['GET']:,} GET, {methods['POST']:,} POST), sha256 `{digest[:16]}…`",
        "- Input: GET query string / POST body, as on the wire (percent-encoded)",
        f"- Requests without parameters (empty input): {n_np:,} "
        f"({', '.join(f'{m} {c:,}' for m, c in sorted(no_params.items())) or 'none'}); "
        f"with parameters: {n_p:,}; distinct inputs: {n_unique:,}",
        f"- Models: retrained with `definitive_experiment.run_single_split` "
        f"(n_train = {ss['n_train']}, seed {SEED}); all {n_cm} single-split confusion "
        f"matrices identical to `{REFERENCE.parent.name}`",
        "- Classifier level only (no WAF layers); FP = prediction other than `benign`",
        f"- Environment: Python {env['python']}, scikit-learn {env['scikit-learn']}, "
        f"NumPy {env['numpy']}, SciPy {env['scipy']}",
        "",
        f"| Config | Input | FP (n = {len(reqs):,}) | FP rate | 95% CI (Wilson) | → SQLi | → XSS "
        f"| FP, with params (n = {n_p:,}) | FP rate, with params | Empty input → |",
        "|---|---|---:|---:|---|---:|---:|---:|---:|---|",
    ]
    for cfg, label, routing in CONFIGS:
        r = results[cfg]
        a, p = r["all_requests"], r["parameterized_requests"]
        lo, hi = a["fp_rate_wilson95"]
        md.append(
            f"| {label} | {routing} | {a['fp']:,} | {pct(a['fp_rate'])} | "
            f"[{pct(lo)}, {pct(hi)}] | {a['pred_sqli']:,} | {a['pred_xss']:,} | "
            f"{p['fp']:,} | {pct(p['fp_rate'])} | {r['empty_input_prediction']} |")
    md.append("")
    (out_dir / "csic2010_fpr.md").write_text("\n".join(md))

    print(f"[csic] Results -> {out_dir.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
