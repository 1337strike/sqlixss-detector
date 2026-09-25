#!/usr/bin/env python3
"""
scripts/supplementary_httpparams.py
====================================
Supplementary evaluation: detection rate of the paper's 8 detector
configurations on an independent public SQLi/XSS benchmark,
HttpParamsDataset (Morzeux/HttpParamsDataset, payload_full.csv). Its SQLi
samples were generated with sqlmap and its XSS samples with XSSYA and FuzzDB,
not taken from InfoSecWarrior/Offensive-Payloads, the paper's corpus.

Protocol
- Models: the 8 configurations are retrained with the paper's own single-split
  code, definitive_experiment.run_single_split() (749-sample training split,
  seed 42). Before anything is evaluated, all 16 single-split confusion
  matrices are asserted identical to the reference run
  results/definitive_20260923T094339Z_42/single_split.json, both as reported
  by run_single_split() and as recomputed from the captured model objects
  (same code path as scripts/supplementary_csic.py).
- Level: classifier only. No WAF layers.
- Test items: every row with attack_type 'sqli' (10,852) or 'xss' (532).
  The 'cmdi' and 'path-traversal' rows are out of scope.
- Benign control: the 19,304 'norm' rows (parameter values from CSIC 2010
  normal traffic: names, addresses, numbers) have the same bare-value shape as
  the attack items, so their flag rate is reported next to the detection
  rates. A detector that flags most benign values too has a high detection
  rate without separating attacks from benign input. The paper's benign
  training samples are all `k=v&k=v` strings, a shape no attack item has.
- Overlap removal. The paper corpus is every string the paper used: the
  InfoSecWarrior corpus (data/raw/real_sqli_payloads.txt,
  data/raw/real_xss_payloads.txt) and all payloads of data/processed/train.csv,
  test_clean.csv and test_obfuscated.csv.
    primary      drop an item whose string equals a paper-corpus string after
                 case folding and whitespace collapsing (HttpParamsDataset is
                 lowercased throughout, so exact matching alone would miss
                 case-only duplicates; exact matches are a subset and are
                 counted separately).
    sensitivity  additionally drop an item whose family_key() (the paper's
                 near-duplicate key: digits -> N, quoted strings -> 'S',
                 whitespace collapsed, lowercase) equals that of any
                 paper-corpus string.
- Input routing as in the paper: raw configs get the payload as given; the
  canonicalized ML configs get canonicalize(payload); the normalizing
  signature gets the payload and canonicalizes internally.
- Per class c in {sqli, xss}:
    detection rate      share of class-c items predicted as any attack class
                        (sqli or xss), i.e. not 'benign'
    correct-class rate  share of class-c items predicted as exactly c
  with Wilson 95% intervals. Family-weighted rates (every family_key group of
  the benchmark weighted equally) are also reported, since sqlmap emits many
  variants of each template.
- Nothing is tuned; no threshold is changed.

Environment: Python 3.12 + requirements.lock (versions are checked).

RUN:
    python scripts/00c_download_httpparams.py
    python scripts/supplementary_httpparams.py

Writes results/supplementary_<timestamp>/:
    httpparams_detection.json      full results + provenance + environment
    httpparams_detection.md        detection / correct-class rates per configuration,
                                   benign-control flag rates
    httpparams_predictions.csv     every SQLi/XSS item: class, exclusion flags,
                                   prediction of each configuration
"""
from __future__ import annotations

import csv
import importlib.util
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.baseline_normalized import canonicalize

HTTPPARAMS_FILE = ROOT / "data" / "external" / "httpparams" / "payload_full.csv"
EXPECTED_COLUMNS = ["payload", "length", "attack_type", "label"]
EXPECTED_COUNTS = {"norm": 19_304, "sqli": 10_852, "xss": 532, "path-traversal": 290, "cmdi": 89}
CLASSES = ("sqli", "xss")
PAPER_CORPUS_FILES = [
    "data/raw/real_sqli_payloads.txt",
    "data/raw/real_xss_payloads.txt",
    "data/processed/train.csv",
    "data/processed/test_clean.csv",
    "data/processed/test_obfuscated.csv",
]
SUBSETS = {  # key: (description, exclusion flag that removes an item)
    "primary": ("paper-corpus strings removed (case- and whitespace-insensitive)", "overlap_string"),
    "sensitivity_family": ("additionally, paper-corpus family_key matches removed", "overlap_family"),
}


def _load_script(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------
def load_httpparams(path: Path) -> tuple[list[dict], list[str]]:
    """Returns (SQLi/XSS items, benign 'norm' values)."""
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        assert reader.fieldnames == EXPECTED_COLUMNS, f"columns {reader.fieldnames}"
        rows = list(reader)
    counts = Counter(r["attack_type"] for r in rows)
    assert dict(counts) == EXPECTED_COUNTS, f"attack_type counts {dict(counts)}"
    for r in rows:
        assert r["label"] == ("norm" if r["attack_type"] == "norm" else "anom")
    items = [{"payload": r["payload"], "cls": r["attack_type"]}
             for r in rows if r["attack_type"] in CLASSES]
    payloads = [it["payload"] for it in items]
    assert len(set(payloads)) == len(payloads), "duplicate SQLi/XSS payloads"
    assert all(p.strip() and "\n" not in p and "\r" not in p for p in payloads)
    norm = [r["payload"] for r in rows if r["attack_type"] == "norm"]
    return items, norm


def load_paper_corpus() -> tuple[list[str], dict]:
    import pandas as pd

    strings, per_file = [], {}
    for rel in PAPER_CORPUS_FILES:
        path = ROOT / rel
        if path.suffix == ".txt":
            got = [l for l in path.read_text(encoding="utf-8").split("\n") if l]
        else:
            got = pd.read_csv(path).dropna(subset=["payload", "label"])["payload"].tolist()
        per_file[rel] = len(got)
        strings.extend(got)
    return strings, per_file


def fold(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().casefold()


def mark_overlap(items: list[dict], corpus: list[str], family_key) -> None:
    exact = set(corpus)
    folded = {fold(c) for c in corpus}
    families = {family_key(c) for c in corpus}
    for it in items:
        p = it["payload"]
        it["family"] = family_key(p)
        it["overlap_exact"] = p in exact
        it["overlap_string"] = fold(p) in folded
        it["overlap_family"] = it["overlap_string"] or it["family"] in families
        assert it["overlap_string"] or not it["overlap_exact"]


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
def rate_block(k: int, n: int, wilson) -> dict:
    lo, hi = wilson(k, n)
    return {"k": k, "n": n, "rate": k / n if n else float("nan"), "wilson95": [lo, hi]}


def class_block(cls: str, preds: list[str], fams: list[str], wilson) -> dict:
    n = len(preds)
    c = Counter(preds)
    detected = n - c.get("benign", 0)
    correct = c.get(cls, 0)
    by_fam = defaultdict(list)
    for p, f in zip(preds, fams):
        by_fam[f].append(p)
    n_fam = len(by_fam)
    fam_det = sum(sum(p != "benign" for p in ps) / len(ps) for ps in by_fam.values()) / n_fam
    fam_cor = sum(sum(p == cls for p in ps) / len(ps) for ps in by_fam.values()) / n_fam
    return {
        "n": n,
        "n_families": n_fam,
        "detection": rate_block(detected, n, wilson),
        "correct_class": rate_block(correct, n, wilson),
        "predicted": {lbl: c.get(lbl, 0) for lbl in ("benign", "sqli", "xss")},
        "family_weighted_detection_rate": fam_det,
        "family_weighted_correct_class_rate": fam_cor,
    }


# ---------------------------------------------------------------------------
def main() -> None:
    csic = _load_script("supplementary_csic", "supplementary_csic.py")
    fetch = _load_script("download_httpparams", "00c_download_httpparams.py")
    env = csic.check_environment()

    pinned = fetch.EXPECTED_SHA256["payload_full.csv"]
    if not HTTPPARAMS_FILE.exists():
        sys.exit(f"[httpparams] {HTTPPARAMS_FILE} missing; run: python scripts/00c_download_httpparams.py")
    digest = fetch._sha256(HTTPPARAMS_FILE)
    assert digest == pinned, f"HttpParamsDataset sha256 {digest} != pinned {pinned}"

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"supplementary_{ts}"
    out_dir = ROOT / "results" / run_id
    print(f"[httpparams] run_id = {run_id}")
    print(f"[httpparams] Python {env['python']} | scikit-learn {env['scikit-learn']} | numpy {env['numpy']}")

    # 1. Retrain with the paper's code and verify against the reference run
    print("[httpparams] Retraining 8 configurations with definitive_experiment.run_single_split ...")
    models, ss, de = csic.train_paper_models(run_id)
    n_cm = csic.assert_reference(ss, models, de.full_metrics)
    print(f"[httpparams] OK: {n_cm}/16 confusion matrices identical to {csic.REFERENCE.parent.name}")
    assert n_cm == 16 and ss["n_train"] == 749

    # 2. Benchmark items and overlap with the paper corpus
    items, norm = load_httpparams(HTTPPARAMS_FILE)
    corpus, corpus_files = load_paper_corpus()
    mark_overlap(items, corpus, de.family_key)
    overlap = {
        cls: {
            "n_total": sum(it["cls"] == cls for it in items),
            "exact": sum(it["cls"] == cls and it["overlap_exact"] for it in items),
            "string_casefold_ws": sum(it["cls"] == cls and it["overlap_string"] for it in items),
            "string_or_family": sum(it["cls"] == cls and it["overlap_family"] for it in items),
        }
        for cls in CLASSES
    }
    removed = {
        cls: {
            "string_casefold_ws": sorted(it["payload"] for it in items
                                         if it["cls"] == cls and it["overlap_string"]),
            "family_only": sorted(it["payload"] for it in items
                                  if it["cls"] == cls and it["overlap_family"] and not it["overlap_string"]),
        }
        for cls in CLASSES
    }
    for cls in CLASSES:
        o = overlap[cls]
        print(f"[httpparams] {cls}: {o['n_total']} items; overlap exact {o['exact']}, "
              f"case/ws-folded {o['string_casefold_ws']}, +family_key {o['string_or_family']}")

    # 3. Predict every in-scope item once per configuration
    X_raw = [it["payload"] for it in items]
    X_canon = [canonicalize(x) for x in X_raw]
    preds = {}
    for cfg, _, routing in csic.CONFIGS:
        X = X_canon if routing == "canonicalize(input)" else X_raw
        preds[cfg] = [str(p) for p in models[cfg].predict(X)]
        assert len(preds[cfg]) == len(items)

    # 4. Metrics per subset / configuration / class
    results = {}
    for sub, (_, flag) in SUBSETS.items():
        keep = [i for i, it in enumerate(items) if not it[flag]]
        results[sub] = {}
        for cfg, label, routing in csic.CONFIGS:
            r = {"label": label, "input_routing": routing, "per_class": {}}
            for cls in CLASSES:
                idx = [i for i in keep if items[i]["cls"] == cls]
                r["per_class"][cls] = class_block(
                    cls, [preds[cfg][i] for i in idx], [items[i]["family"] for i in idx], csic.wilson)
            idx = keep
            pooled_det = sum(preds[cfg][i] != "benign" for i in idx)
            pooled_cor = sum(preds[cfg][i] == items[i]["cls"] for i in idx)
            r["pooled"] = {
                "n": len(idx),
                "detection": rate_block(pooled_det, len(idx), csic.wilson),
                "correct_class": rate_block(pooled_cor, len(idx), csic.wilson),
            }
            results[sub][cfg] = r

    # Benign control: same routing, 'norm' values
    norm_canon = [canonicalize(x) for x in norm]
    control = {}
    for cfg, label, routing in csic.CONFIGS:
        X = norm_canon if routing == "canonicalize(input)" else norm
        p = [str(q) for q in models[cfg].predict(X)]
        c = Counter(p)
        control[cfg] = {
            "label": label,
            "flagged": rate_block(len(p) - c.get("benign", 0), len(p), csic.wilson),
            "predicted": {lbl: c.get(lbl, 0) for lbl in ("benign", "sqli", "xss")},
        }

    for cfg, label, _ in csic.CONFIGS:
        r = results["primary"][cfg]["per_class"]
        print(f"       {label:13} SQLi det {csic.pct(r['sqli']['detection']['rate']):>7} "
              f"correct {csic.pct(r['sqli']['correct_class']['rate']):>7} | "
              f"XSS det {csic.pct(r['xss']['detection']['rate']):>7} "
              f"correct {csic.pct(r['xss']['correct_class']['rate']):>7} | "
              f"benign flagged {csic.pct(control[cfg]['flagged']['rate']):>7}")

    # 5. Write outputs
    out_dir.mkdir(parents=True, exist_ok=False)
    n_in = {sub: {cls: results[sub][csic.CONFIGS[0][0]]["per_class"][cls]["n"] for cls in CLASSES}
            for sub in SUBSETS}
    doc = {
        "run_id": run_id,
        "description": "Detection rate of the paper's 8 detector configurations on the SQLi/XSS "
                       "items of HttpParamsDataset, with paper-corpus overlap removed "
                       "(classifier level, no WAF layers).",
        "environment": env,
        "models": {
            "source": "scripts/definitive_experiment.py::run_single_split",
            "seed": csic.SEED,
            "n_train": ss["n_train"],
            "class_dist_train": ss["class_dist_train"],
            "reference_run": csic.REFERENCE.parent.name,
            "confusion_matrices_verified_identical": n_cm,
        },
        "dataset": {
            "name": "HttpParamsDataset, payload_full.csv",
            "path": HTTPPARAMS_FILE.relative_to(ROOT).as_posix(),
            "upstream_repo": fetch.UPSTREAM_REPO,
            "upstream_commit": fetch.UPSTREAM_COMMIT,
            "license": "MIT",
            "sha256": digest,
            "attack_type_counts": EXPECTED_COUNTS,
            "in_scope": list(CLASSES),
            "generators": {"sqli": "sqlmap", "xss": "XSSYA, FuzzDB"},
            "n_benign_control": len(norm),
            "note": "all payloads are lowercase in the upstream file",
        },
        "paper_corpus": {
            "files": corpus_files,
            "n_strings": len(corpus),
            "n_distinct": len(set(corpus)),
        },
        "overlap": overlap,
        "removed_payloads": removed,
        "subsets": {sub: {"description": desc, "n": n_in[sub]} for sub, (desc, _) in SUBSETS.items()},
        "definitions": {
            "detection_rate": "share of class-c items predicted 'sqli' or 'xss' (not 'benign')",
            "correct_class_rate": "share of class-c items predicted exactly c",
            "family_weighted": "mean over the benchmark's family_key groups of the per-group rate",
            "benign_control_flag_rate": "share of 'norm' values predicted 'sqli' or 'xss'",
        },
        "results": results,
        "benign_control": control,
    }
    (out_dir / "httpparams_detection.json").write_text(json.dumps(doc, indent=2) + "\n")

    with open(out_dir / "httpparams_predictions.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["payload", "class", "overlap_exact", "overlap_string", "overlap_family"]
                   + [cfg for cfg, _, _ in csic.CONFIGS])
        for i, it in enumerate(items):
            w.writerow([it["payload"], it["cls"], int(it["overlap_exact"]),
                        int(it["overlap_string"]), int(it["overlap_family"])]
                       + [preds[cfg][i] for cfg, _, _ in csic.CONFIGS])

    pct = csic.pct

    def ci(b: dict) -> str:
        lo, hi = b["wilson95"]
        return f"[{pct(lo)}, {pct(hi)}]"

    def table(sub: str) -> list[str]:
        ns, nx = n_in[sub]["sqli"], n_in[sub]["xss"]
        out = [
            f"| Config | Input | SQLi detection (n = {ns:,}) | 95% CI | SQLi correct class | 95% CI "
            f"| XSS detection (n = {nx:,}) | 95% CI | XSS correct class | 95% CI |",
            "|---|---|---:|---|---:|---|---:|---|---:|---|",
        ]
        for cfg, label, routing in csic.CONFIGS:
            s = results[sub][cfg]["per_class"]["sqli"]
            x = results[sub][cfg]["per_class"]["xss"]
            out.append(
                f"| {label} | {routing} | {pct(s['detection']['rate'])} | {ci(s['detection'])} "
                f"| {pct(s['correct_class']['rate'])} | {ci(s['correct_class'])} "
                f"| {pct(x['detection']['rate'])} | {ci(x['detection'])} "
                f"| {pct(x['correct_class']['rate'])} | {ci(x['correct_class'])} |")
        return out

    def counts_table(sub: str) -> list[str]:
        out = [
            "| Config | SQLi → benign / sqli / xss | XSS → benign / sqli / xss "
            "| SQLi det. / correct, family-weighted | XSS det. / correct, family-weighted |",
            "|---|---|---|---|---|",
        ]
        for cfg, label, _ in csic.CONFIGS:
            s = results[sub][cfg]["per_class"]["sqli"]
            x = results[sub][cfg]["per_class"]["xss"]
            fmt = lambda b: " / ".join(f"{b['predicted'][l]:,}" for l in ("benign", "sqli", "xss"))
            out.append(
                f"| {label} | {fmt(s)} | {fmt(x)} "
                f"| {pct(s['family_weighted_detection_rate'])} / {pct(s['family_weighted_correct_class_rate'])} "
                f"| {pct(x['family_weighted_detection_rate'])} / {pct(x['family_weighted_correct_class_rate'])} |")
        return out

    fam = {sub: {cls: results[sub][csic.CONFIGS[0][0]]["per_class"][cls]["n_families"] for cls in CLASSES}
           for sub in SUBSETS}
    o = overlap
    md = [
        "# Supplementary: detection on an independent SQLi/XSS benchmark (HttpParamsDataset)",
        "",
        f"run_id: `{run_id}`",
        "",
        f"- Data: `{fetch.UPSTREAM_REPO}` @ `{fetch.UPSTREAM_COMMIT[:8]}`, `payload_full.csv`, "
        f"sha256 `{digest[:16]}…` (MIT). In scope: attack_type `sqli` ({o['sqli']['n_total']:,}, sqlmap) "
        f"and `xss` ({o['xss']['n_total']:,}, XSSYA + FuzzDB); upstream payloads are lowercase",
        f"- Paper corpus for overlap removal: {len(set(corpus)):,} distinct strings "
        "(InfoSecWarrior SQLi + XSS files, train / test_clean / test_obfuscated payloads)",
        f"- Overlap removed (primary): SQLi {o['sqli']['string_casefold_ws']} "
        f"(exact {o['sqli']['exact']}), XSS {o['xss']['string_casefold_ws']} (exact {o['xss']['exact']}), "
        "matched after case folding and whitespace collapsing",
        f"- Sensitivity: also remove `family_key` matches; SQLi {o['sqli']['string_or_family']}, "
        f"XSS {o['xss']['string_or_family']} removed in total",
        f"- Models: retrained with `definitive_experiment.run_single_split` "
        f"(n_train = {ss['n_train']}, seed {csic.SEED}); all {n_cm} single-split confusion "
        f"matrices identical to `{csic.REFERENCE.parent.name}`",
        "- Classifier level only (no WAF layers). Detection = predicted `sqli` or `xss`; "
        "correct class = predicted the item's own class. Nothing tuned",
        f"- Environment: Python {env['python']}, scikit-learn {env['scikit-learn']}, "
        f"NumPy {env['numpy']}, SciPy {env['scipy']}",
        "",
        f"## Primary: paper-corpus strings removed (SQLi n = {n_in['primary']['sqli']:,}, "
        f"{fam['primary']['sqli']:,} families; XSS n = {n_in['primary']['xss']:,}, "
        f"{fam['primary']['xss']:,} families)",
        "",
        *table("primary"),
        "",
        *counts_table("primary"),
        "",
        f"## Benign control: HttpParamsDataset `norm` values (n = {len(norm):,})",
        "",
        "Same bare-value shape as the attack items (the paper's benign training samples are "
        "`k=v&k=v` strings). A configuration that flags most of these also flags most attacks "
        "regardless of content, so read its detection rate together with this row.",
        "",
        "| Config | Flagged as attack | 95% CI | → SQLi | → XSS |",
        "|---|---:|---|---:|---:|",
        *[f"| {label} | {pct(control[cfg]['flagged']['rate'])} | {ci(control[cfg]['flagged'])} "
          f"| {control[cfg]['predicted']['sqli']:,} | {control[cfg]['predicted']['xss']:,} |"
          for cfg, label, _ in csic.CONFIGS],
        "",
        f"## Sensitivity: family_key matches also removed (SQLi n = {n_in['sensitivity_family']['sqli']:,}, "
        f"XSS n = {n_in['sensitivity_family']['xss']:,})",
        "",
        *table("sensitivity_family"),
        "",
    ]
    (out_dir / "httpparams_detection.md").write_text("\n".join(md))

    print(f"[httpparams] Results -> {out_dir.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
