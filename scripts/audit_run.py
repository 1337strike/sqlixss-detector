#!/usr/bin/env python3
"""
audit_run.py
============
Single authoritative run for the ICITDA paper audit.
Generates every artefact required by the audit specification in one pass.

RUN ID is embedded in every output file so results are traceable.

Usage:
    python scripts/audit_run.py
    python scripts/audit_run.py --folds 5 --repeats 3 --seed 42
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import random
import re
import sqlite3
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import numpy as np
import pandas as pd
from scipy import stats
from sklearn.metrics import (
    accuracy_score, confusion_matrix,
    precision_recall_fscore_support,
)
from sklearn.model_selection import StratifiedGroupKFold

from src.baseline_normalized import NormalizedSignatureBaseline, canonicalize
from src.baseline_signature import SignatureBaseline
from src.dataset import _BENIGN_TEMPLATES, _fill_template
from src.models import get_model_definitions
from src.obfuscation import _TECHNIQUES, random_obfuscate
from src.statistics import holm_correct, nadeau_bengio_ttest

# ── constants ────────────────────────────────────────────────────────────────
LABELS   = ["benign", "sqli", "xss"]
RAW_DIR  = Path(__file__).resolve().parent.parent / "data" / "raw"
RES_DIR  = Path(__file__).resolve().parent.parent / "results" / "audit"
RES_DIR.mkdir(parents=True, exist_ok=True)


# ── environment snapshot ──────────────────────────────────────────────────────
def env_snapshot() -> dict:
    import sklearn, scipy as sp, numpy as _np
    return {
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "platform":    platform.platform(),
        "cpu":         platform.processor() or os.popen("lscpu | grep 'Model name'").read().strip(),
        "python":      platform.python_version(),
        "numpy":       _np.__version__,
        "sklearn":     sklearn.__version__,
        "scipy":       sp.__version__,
        "n_cpus":      os.cpu_count(),
    }


# ── corpus ────────────────────────────────────────────────────────────────────
def family_key(payload: str) -> str:
    f = re.sub(r"\d+", "N", payload)
    f = re.sub(r"'[^']*'", "'S'", f)
    f = re.sub(r'"[^"]*"', '"S"', f)
    return re.sub(r"\s+", " ", f).strip().lower()


def load_corpus(seed: int, benign_extra: int = 200) -> pd.DataFrame:
    frames = []
    provenance = {}
    for fname, label in [("real_sqli_payloads.txt", "sqli"),
                          ("real_xss_payloads.txt",  "xss")]:
        path = RAW_DIR / fname
        if not path.exists():
            raise SystemExit(f"Missing {path} — run scripts/00_download_payloads.py")
        raw = path.read_text(encoding="utf-8").splitlines()
        lines = list(dict.fromkeys(l.strip() for l in raw if l.strip()))
        h = hashlib.sha256(path.read_bytes()).hexdigest()[:16]
        provenance[fname] = {"count": len(lines), "sha256_prefix": h}
        frames.append(pd.DataFrame({
            "payload": lines,
            "label":   label,
            "source":  fname,
        }))

    rng = random.Random(seed)
    n_mal = sum(len(f) for f in frames)
    rows = []
    for i in range(n_mal + benign_extra):
        combo = rng.sample(_BENIGN_TEMPLATES, k=rng.randint(1, 3))
        rows.append({
            "payload": "&".join(_fill_template(t, rng) for t in combo),
            "label":   "benign",
            "source":  f"template_seed{seed}_{i}",
        })
    frames.append(
        pd.DataFrame(rows).drop_duplicates(subset="payload").reset_index(drop=True)
    )

    df = (pd.concat(frames, ignore_index=True)
            .drop_duplicates(subset="payload")
            .sample(frac=1.0, random_state=seed)
            .reset_index(drop=True))
    df["sample_id"] = [f"s{i:05d}" for i in range(len(df))]
    df["family_id"] = df["payload"].map(family_key)
    return df, provenance


# ── metrics ───────────────────────────────────────────────────────────────────
def full_metrics(y_true, y_pred, labels=LABELS) -> dict:
    p, r, f, sup = precision_recall_fscore_support(
        y_true, y_pred, labels=labels, zero_division=0)
    acc = accuracy_score(y_true, y_pred)
    cm  = confusion_matrix(y_true, y_pred, labels=labels)
    n_total = len(y_true)
    n_correct = int((np.array(y_true) == np.array(y_pred)).sum())

    # Verify accuracy from confusion matrix
    assert n_correct == cm.diagonal().sum(), "CM diagonal != n_correct"
    acc_from_cm = cm.diagonal().sum() / cm.sum()
    assert abs(acc - acc_from_cm) < 1e-9, "accuracy mismatch"

    errors = {
        "benign_to_attack": int(cm[0, 1] + cm[0, 2]),
        "attack_to_benign": int(cm[1, 0] + cm[2, 0]),
        "sqli_to_xss":      int(cm[1, 2]),
        "xss_to_sqli":      int(cm[2, 1]),
    }
    return {
        "n_total":   n_total,
        "n_correct": n_correct,
        "accuracy":  round(float(acc), 6),
        "macro_f1":  round(float(f.mean()), 6),
        "per_class": {
            lbl: {
                "precision": round(float(p[i]), 6),
                "recall":    round(float(r[i]), 6),
                "f1":        round(float(f[i]), 6),
                "support":   int(sup[i]),
            }
            for i, lbl in enumerate(labels)
        },
        "confusion_matrix": cm.tolist(),
        "cm_labels": labels,
        "errors": errors,
    }


# ── CV experiment ─────────────────────────────────────────────────────────────
def run_cv(df: pd.DataFrame, n_folds: int, n_reps: int, seed: int,
           run_id: str) -> dict:
    X      = df["payload"].to_numpy()
    y      = df["label"].to_numpy()
    groups = df["family_id"].to_numpy()

    configs = (
        [f"{m}_raw"        for m in get_model_definitions()] +
        [f"{m}_normalized" for m in get_model_definitions()] +
        ["signature_raw", "signature_normalized"]
    )
    fold_scores   = {c: {"f1_clean": [], "f1_obf": []} for c in configs}
    fold_meta     = []
    predictions   = []   # per-prediction rows

    fold_id = 0
    for rep in range(n_reps):
        sgkf = StratifiedGroupKFold(
            n_splits=n_folds, shuffle=True, random_state=seed + rep)
        for tr_idx, te_idx in sgkf.split(X, y, groups=groups):
            fold_id += 1
            Xtr, ytr = X[tr_idx], y[tr_idx]
            Xte, yte = X[te_idx],  y[te_idx]
            sid_te   = df["sample_id"].to_numpy()[te_idx]
            fam_te   = df["family_id"].to_numpy()[te_idx]

            # Anti-leakage assertion
            overlap = set(groups[tr_idx]) & set(groups[te_idx])
            assert not overlap, f"Family leakage fold {fold_id}: {overlap}"

            fold_meta.append({
                "run_id": run_id, "fold_id": fold_id,
                "repeat": rep + 1, "fold_within_rep": (fold_id - 1) % n_folds + 1,
                "n_train": len(Xtr), "n_test": len(Xte),
                "seed_used": seed + rep,
            })

            rng = random.Random(seed + fold_id * 1000)

            # Build obfuscated test set — record per-sample transformation
            Xte_obf = []
            obf_records = []
            for payload, label, sid in zip(Xte, yte, sid_te):
                if label in ("sqli", "xss"):
                    obf, techs = random_obfuscate(
                        payload, seed=rng.randint(0, 10**6))
                    changed = (obf != payload)
                else:
                    obf, techs, changed = payload, [], False
                Xte_obf.append(obf)
                obf_records.append({
                    "run_id": run_id, "fold_id": fold_id,
                    "sample_id": sid, "label": label,
                    "techniques": "+".join(techs),
                    "changed": changed,
                    "obf_hash": hashlib.sha256(obf.encode()).hexdigest()[:12],
                })

            # Canonicalized versions — single pass only
            Xtr_n      = [canonicalize(p) for p in Xtr]
            Xte_n      = [canonicalize(p) for p in Xte]
            Xte_obf_n  = [canonicalize(p) for p in Xte_obf]

            def mf1(yt, yp):
                return float(precision_recall_fscore_support(
                    yt, yp, labels=LABELS, average="macro", zero_division=0)[2])

            def record_preds(detector, preprocessing, condition, X_in, yt, sids, fams):
                ypred = model.predict(X_in)
                for sid, fam, ytrue, ypred_i in zip(sids, fams, yt, ypred):
                    predictions.append({
                        "run_id": run_id, "fold_id": fold_id,
                        "repeat": rep + 1,
                        "fold_within_rep": (fold_id - 1) % n_folds + 1,
                        "seed": seed + rep,
                        "detector": detector,
                        "preprocessing": preprocessing,
                        "condition": condition,
                        "sample_id": sid,
                        "family_id": fam,
                        "y_true": ytrue,
                        "y_pred": ypred_i,
                    })

            for mname in get_model_definitions():
                # raw
                model = get_model_definitions()[mname]
                model.fit(Xtr, ytr)
                key_r = f"{mname}_raw"
                fold_scores[key_r]["f1_clean"].append(mf1(yte, model.predict(Xte)))
                fold_scores[key_r]["f1_obf"].append(  mf1(yte, model.predict(Xte_obf)))
                record_preds(mname, "raw", "clean", Xte, yte, sid_te, fam_te)
                record_preds(mname, "raw", "obf",   Xte_obf, yte, sid_te, fam_te)

                # canonicalized — NO double canonicalization
                model_n = get_model_definitions()[mname]
                model_n.fit(Xtr_n, ytr)
                key_n = f"{mname}_normalized"
                fold_scores[key_n]["f1_clean"].append(mf1(yte, model_n.predict(Xte_n)))
                fold_scores[key_n]["f1_obf"].append(  mf1(yte, model_n.predict(Xte_obf_n)))
                record_preds(mname, "normalized", "clean", Xte_n, yte, sid_te, fam_te)
                record_preds(mname, "normalized", "obf",   Xte_obf_n, yte, sid_te, fam_te)

            # Signature baselines
            sig_raw  = SignatureBaseline()
            sig_norm = NormalizedSignatureBaseline()

            # BUG FIX: sig_norm gets RAW input (it calls canonicalize internally)
            # Previous version passed Xte_obf_n to sig_norm which caused
            # double canonicalization. Correct: always pass raw strings.
            fold_scores["signature_raw"]["f1_clean"].append(
                mf1(yte, sig_raw.predict(list(Xte))))
            fold_scores["signature_raw"]["f1_obf"].append(
                mf1(yte, sig_raw.predict(list(Xte_obf))))
            fold_scores["signature_normalized"]["f1_clean"].append(
                mf1(yte, sig_norm.predict(list(Xte))))
            fold_scores["signature_normalized"]["f1_obf"].append(
                mf1(yte, sig_norm.predict(list(Xte_obf))))  # raw obf, not pre-canonicalized

    return {
        "fold_scores":  fold_scores,
        "fold_meta":    fold_meta,
        "predictions":  predictions,
    }


# ── statistics ────────────────────────────────────────────────────────────────
def compute_stats(fold_scores: dict,
                  n_train_mean: float, n_test_mean: float) -> dict:
    configs = list(fold_scores.keys())
    results = {}

    for cfg in configs:
        fc = np.array(fold_scores[cfg]["f1_clean"])
        fo = np.array(fold_scores[cfg]["f1_obf"])
        ci = stats.t.interval(0.95, len(fo)-1, loc=fo.mean(), scale=stats.sem(fo))
        results[cfg] = {
            "n_fits":         len(fc),
            "f1_clean_mean":  round(float(fc.mean()), 6),
            "f1_clean_sd":    round(float(fc.std(ddof=1)), 6),
            "f1_obf_mean":    round(float(fo.mean()), 6),
            "f1_obf_sd":      round(float(fo.std(ddof=1)), 6),
            "f1_obf_ci95_lo": round(float(ci[0]), 6),
            "f1_obf_ci95_hi": round(float(ci[1]), 6),
            "obf_drop":       round(float(fc.mean() - fo.mean()), 6),
        }

    # Canonicalization effects with NB-corrected t-test
    effects = {}
    p_raws = []
    effect_keys = []
    for mname in list(get_model_definitions()) + ["signature"]:
        ka, kb = f"{mname}_raw", f"{mname}_normalized"
        if ka not in fold_scores or kb not in fold_scores:
            continue
        a = np.array(fold_scores[ka]["f1_obf"])
        b = np.array(fold_scores[kb]["f1_obf"])
        diff = b - a

        sd_a   = float(a.std(ddof=1))
        sd_b   = float(b.std(ddof=1))
        sd_d   = float(diff.std(ddof=1))
        corr   = float(np.corrcoef(a, b)[0, 1])

        # Triangle inequality check
        lo, hi = abs(sd_a - sd_b), sd_a + sd_b
        triangle_ok = (lo <= sd_d <= hi)

        t, p_raw = nadeau_bengio_ttest(
            list(a), list(b), n_train=int(n_train_mean), n_test=int(n_test_mean))
        p_raws.append(p_raw)
        effect_keys.append(mname)
        effects[mname] = {
            "raw_f1_obf_mean":  round(float(a.mean()), 6),
            "norm_f1_obf_mean": round(float(b.mean()), 6),
            "gain":             round(float(diff.mean()), 6),
            "sd_raw":           round(sd_a, 6),
            "sd_norm":          round(sd_b, 6),
            "sd_diff":          round(sd_d, 6),
            "corr_raw_norm":    round(corr, 6),
            "triangle_ok":      triangle_ok,
            "triangle_bounds":  [round(lo, 6), round(hi, 6)],
            "t_nb":             round(float(t), 4),
            "p_raw":            round(p_raw, 8),
        }

    holm_ps = holm_correct(p_raws)
    for key, ph in zip(effect_keys, holm_ps):
        effects[key]["p_holm"] = round(ph, 8)
        effects[key]["significant_holm_005"] = bool(ph < 0.05)

    return {"cv_summary": results, "canon_effects": effects}


# ── single split ──────────────────────────────────────────────────────────────
def run_single_split(df: pd.DataFrame, seed: int, run_id: str) -> dict:
    """Fixed 75/25 stratified split — matches the paper's single-split table."""
    from sklearn.model_selection import train_test_split
    from src.obfuscation import random_obfuscate

    train_df, test_df = train_test_split(
        df, test_size=0.25, stratify=df["label"], random_state=seed)

    Xtr, ytr = train_df["payload"].tolist(), train_df["label"].tolist()
    Xte, yte = test_df["payload"].tolist(),  test_df["label"].tolist()

    rng = random.Random(seed + 99999)
    Xte_obf, obf_info = [], []
    unchanged_count = 0
    for payload, label in zip(Xte, yte):
        if label in ("sqli", "xss"):
            obf, techs = random_obfuscate(payload, seed=rng.randint(0, 10**6))
            changed = (obf != payload)
            if not changed:
                unchanged_count += 1
        else:
            obf, techs, changed = payload, [], False
        Xte_obf.append(obf)
        obf_info.append({"techniques": techs, "changed": changed})

    Xtr_n     = [canonicalize(p) for p in Xtr]
    Xte_n     = [canonicalize(p) for p in Xte]
    Xte_obf_n = [canonicalize(p) for p in Xte_obf]

    results = {
        "run_id": run_id,
        "n_train": len(Xtr),
        "n_test":  len(Xte),
        "class_dist_test": {
            l: int(sum(1 for y in yte if y == l)) for l in LABELS},
        "unchanged_obfuscated": unchanged_count,
        "obf_techniques_available": sorted(_TECHNIQUES.keys()),
        "n_obf_techniques": len(_TECHNIQUES),
        "detectors": {},
    }

    import time as _time

    def measure(model, X_in, y_true, label_tag, lat_X=None):
        pred = model.predict(X_in)
        m = full_metrics(y_true, pred)
        # Latency: 100 predictions after 5 warmup
        lat_X_use = lat_X if lat_X is not None else X_in
        for _ in lat_X_use[:5]:
            model.predict([_])
        times = []
        for p in lat_X_use[:100]:
            t0 = _time.perf_counter()
            model.predict([p])
            times.append((_time.perf_counter() - t0) * 1000)
        m["latency_ms"] = {
            "mean":   round(float(np.mean(times)), 4),
            "median": round(float(np.median(times)), 4),
            "p95":    round(float(np.percentile(times, 95)), 4),
            "p99":    round(float(np.percentile(times, 99)), 4),
            "n_samples": len(times),
        }
        m["label_tag"] = label_tag
        return m, list(pred)

    for mname in get_model_definitions():
        det = {}
        # raw
        model_r = get_model_definitions()[mname]
        model_r.fit(Xtr, ytr)
        det["raw_clean"], _ = measure(model_r, Xte, yte, "raw_clean", Xte)
        det["raw_obf"],   _ = measure(model_r, Xte_obf, yte, "raw_obf", Xte_obf)
        det["raw_obf_drop"] = round(
            det["raw_clean"]["macro_f1"] - det["raw_obf"]["macro_f1"], 6)

        # normalized
        model_n = get_model_definitions()[mname]
        model_n.fit(Xtr_n, ytr)
        det["norm_clean"], _ = measure(model_n, Xte_n, yte, "norm_clean", Xte_n)
        det["norm_obf"],   _ = measure(model_n, Xte_obf_n, yte, "norm_obf", Xte_obf_n)
        det["norm_obf_drop"] = round(
            det["norm_clean"]["macro_f1"] - det["norm_obf"]["macro_f1"], 6)
        det["canon_gain_obf"] = round(
            det["norm_obf"]["macro_f1"] - det["raw_obf"]["macro_f1"], 6)

        results["detectors"][mname] = det

    # Signature baselines — single canonicalization pass
    sig_raw  = SignatureBaseline()
    sig_norm = NormalizedSignatureBaseline()
    for tag, model, xc, xo in [
        ("signature_raw",        sig_raw,  Xte,   Xte_obf),
        ("signature_normalized", sig_norm, Xte,   Xte_obf),
    ]:
        det = {}
        det["clean"], _ = measure(model, xc, yte, "clean", xc)
        det["obf"],   _ = measure(model, xo, yte, "obf",   xo)
        det["obf_drop"] = round(det["clean"]["macro_f1"] - det["obf"]["macro_f1"], 6)
        results["detectors"][tag] = det

    return results


# ── semantic validation ───────────────────────────────────────────────────────
def semantic_validation(df: pd.DataFrame, run_id: str) -> dict:
    """SQLi oracle with positive and negative controls."""
    conn = sqlite3.connect(":memory:")
    conn.execute("""CREATE TABLE users (
        id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)""")
    conn.executemany("INSERT INTO users VALUES (?,?,?,?)", [
        (1, "admin",  "secret123", "admin"),
        (2, "alice",  "pass456",   "user"),
        (3, "bob",    "qwerty789", "user"),
    ])

    # Template: deliberately vulnerable string interpolation
    TEMPLATE = "SELECT * FROM users WHERE username='{u}' AND password='{p}'"
    BASELINE_ROWS = 0  # safe baseline returns 0 rows

    def test_sqli(payload: str) -> str:
        try:
            sql = TEMPLATE.format(u=payload, p="x")
            rows = conn.execute(sql).fetchall()
            if len(rows) > BASELINE_ROWS:
                return "valid_attack"
            return "invalid_in_context"
        except sqlite3.OperationalError:
            return "syntax_error"
        except Exception as e:
            return f"error:{type(e).__name__}"

    # Positive controls — must return "valid_attack"
    pos_controls = [
        ("' OR '1'='1", "classic OR"),
        ("' OR 1=1 --",  "OR with comment"),
        ("admin' --",    "comment bypass"),
        ("' OR 'a'='a", "string comparison"),
    ]
    # Negative controls — must NOT be valid
    neg_controls = [
        ("admin",         "safe username"),
        ("alice",         "safe username 2"),
        ("'; DROP TABLE", "destructive — syntax error expected"),
    ]

    ctrl_results = {"positive": [], "negative": []}
    for payload, name in pos_controls:
        r = test_sqli(payload)
        ctrl_results["positive"].append({
            "name": name, "payload": payload,
            "result": r, "pass": r == "valid_attack"})
    for payload, name in neg_controls:
        r = test_sqli(payload)
        ctrl_results["negative"].append({
            "name": name, "payload": payload,
            "result": r, "pass": r != "valid_attack"})

    pos_pass = all(c["pass"] for c in ctrl_results["positive"])
    neg_pass = all(c["pass"] for c in ctrl_results["negative"])

    # Test all SQLi payloads
    sqli_df = df[df["label"] == "sqli"]
    counts = {"valid_attack": 0, "invalid_in_context": 0,
              "syntax_error": 0, "error": 0, "total": len(sqli_df)}
    payload_results = []
    for _, row in sqli_df.iterrows():
        r = test_sqli(row["payload"])
        category = r if r in counts else "error"
        counts[category] = counts.get(category, 0) + 1
        payload_results.append({
            "sample_id": row["sample_id"],
            "payload":   row["payload"][:80],
            "oracle":    r,
        })

    # XSS: structural pattern check only
    import re as _re
    XSS_PATTERNS = [
        _re.compile(r"<script[^>]*>", _re.I),
        _re.compile(r"on\w+\s*=",     _re.I),
        _re.compile(r"javascript\s*:", _re.I),
        _re.compile(r"<svg[^>]*onload", _re.I),
        _re.compile(r"<img[^>]+onerror", _re.I),
        _re.compile(r"<iframe[^>]*>",   _re.I),
    ]
    xss_df = df[df["label"] == "xss"]
    xss_counts = {"structurally_plausible": 0, "structurally_implausible": 0,
                  "total": len(xss_df)}
    for _, row in xss_df.iterrows():
        if any(p.search(row["payload"]) for p in XSS_PATTERNS):
            xss_counts["structurally_plausible"] += 1
        else:
            xss_counts["structurally_implausible"] += 1

    return {
        "run_id": run_id,
        "oracle_type": "SQLite_string_interpolation",
        "oracle_controls_pass": pos_pass and neg_pass,
        "positive_controls": ctrl_results["positive"],
        "negative_controls": ctrl_results["negative"],
        "sqli_oracle_counts": counts,
        "sqli_limitation": (
            "Oracle uses a single equality-template query. Many SQLi payloads "
            "(UNION SELECT, stacked queries) require a different query structure. "
            "'invalid_in_context' does NOT mean the payload is inert against all targets."
        ),
        "xss_pattern_counts": xss_counts,
        "xss_limitation": "Structural pattern check only; not browser execution.",
        "n_payload_results_sqli": len(payload_results),
    }


# ── main ──────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--folds",   type=int, default=5)
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--seed",    type=int, default=42)
    ap.add_argument("--benign-extra", type=int, default=200)
    args = ap.parse_args()

    run_id = f"audit_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_{args.seed}"
    print(f"[audit] run_id = {run_id}")
    print(f"[audit] CV: {args.folds}-fold × {args.repeats} repeats, seed={args.seed}")

    # 0. Environment
    env = env_snapshot()
    print(f"[audit] env: {env['platform'][:60]} | Python {env['python']} | sklearn {env['sklearn']}")

    # 1. Corpus
    print("[audit] loading corpus ...")
    df, prov = load_corpus(args.seed, args.benign_extra)
    print(f"[audit] corpus: {len(df)} samples, {df['family_id'].nunique()} families")
    print(f"        {df['label'].value_counts().to_dict()}")

    # Bug check: obfuscation technique count
    n_techniques = len(_TECHNIQUES)
    print(f"[audit] obfuscation techniques in _TECHNIQUES: {n_techniques} "
          f"({sorted(_TECHNIQUES.keys())})")
    if n_techniques != 6:
        print(f"  WARNING: paper claims 6 techniques but code has {n_techniques}")

    # 2. Semantic validation
    print("[audit] running semantic validation ...")
    sem = semantic_validation(df, run_id)
    print(f"        oracle controls pass: {sem['oracle_controls_pass']}")
    print(f"        SQLi counts: {sem['sqli_oracle_counts']}")
    print(f"        XSS counts:  {sem['xss_pattern_counts']}")

    # 3. Single split
    print("[audit] single split ...")
    ss = run_single_split(df, args.seed, run_id)
    print(f"        n_train={ss['n_train']}, n_test={ss['n_test']}")
    print(f"        test distribution: {ss['class_dist_test']}")
    print(f"        unchanged obfuscated: {ss['unchanged_obfuscated']}")
    for det_name, det_res in ss["detectors"].items():
        if isinstance(det_res, dict) and "norm_clean" in det_res:
            nc = det_res["norm_clean"]["macro_f1"]
            no = det_res["norm_obf"]["macro_f1"]
            print(f"        {det_name:25} norm_clean={nc:.4f} norm_obf={no:.4f} drop={det_res['norm_obf_drop']:.4f}")

    # 4. CV
    print(f"[audit] CV ({args.folds}×{args.repeats}) ...")
    t0 = time.perf_counter()
    cv_out = run_cv(df, args.folds, args.repeats, args.seed, run_id)
    elapsed = time.perf_counter() - t0
    print(f"        done in {elapsed:.1f}s, {len(cv_out['fold_meta'])} folds")

    fold_sizes = [(m["n_train"], m["n_test"]) for m in cv_out["fold_meta"]]
    n_train_mean = np.mean([x[0] for x in fold_sizes])
    n_test_mean  = np.mean([x[1] for x in fold_sizes])
    print(f"        fold sizes: n_train_mean={n_train_mean:.1f}, n_test_mean={n_test_mean:.1f}")

    # 5. Statistics
    print("[audit] computing statistics ...")
    stat_out = compute_stats(cv_out["fold_scores"], n_train_mean, n_test_mean)

    print("\n=== CV SUMMARY ===")
    for cfg, s in stat_out["cv_summary"].items():
        if "normalized" in cfg or "raw" in cfg:
            print(f"  {cfg:40} F1_clean={s['f1_clean_mean']:.4f}±{s['f1_clean_sd']:.4f} "
                  f"F1_obf={s['f1_obf_mean']:.4f}±{s['f1_obf_sd']:.4f} drop={s['obf_drop']:.4f}")

    print("\n=== CANONICALIZATION EFFECTS ===")
    for m, e in stat_out["canon_effects"].items():
        print(f"  {m:20} gain={e['gain']:.4f} SD_raw={e['sd_raw']:.4f} "
              f"SD_norm={e['sd_norm']:.4f} SD_diff={e['sd_diff']:.4f} "
              f"triangle={'OK' if e['triangle_ok'] else 'VIOLATION'} "
              f"p_holm={e['p_holm']:.2e}")

    # 6. Save all artefacts
    print("\n[audit] saving artefacts ...")
    artefacts = {}

    # environment
    p = RES_DIR / f"{run_id}_environment.json"
    p.write_text(json.dumps(env, indent=2))
    artefacts["environment"] = str(p)

    # dataset provenance + manifest
    ds_manifest = {
        "run_id":    run_id,
        "seed":      args.seed,
        "n_samples": len(df),
        "n_families": int(df["family_id"].nunique()),
        "class_dist": {k: int(v) for k, v in df["label"].value_counts().items()},
        "raw_file_hashes": prov,
        "benign_extra": args.benign_extra,
        "obfuscation_techniques": sorted(_TECHNIQUES.keys()),
        "n_obfuscation_techniques": len(_TECHNIQUES),
    }
    p = RES_DIR / f"{run_id}_dataset_manifest.json"
    p.write_text(json.dumps(ds_manifest, indent=2))
    artefacts["dataset_manifest"] = str(p)

    # fold metadata
    p = RES_DIR / f"{run_id}_fold_metadata.csv"
    pd.DataFrame(cv_out["fold_meta"]).to_csv(p, index=False)
    artefacts["fold_metadata"] = str(p)

    # predictions
    p = RES_DIR / f"{run_id}_predictions.csv"
    pd.DataFrame(cv_out["predictions"]).to_csv(p, index=False)
    artefacts["predictions"] = str(p)

    # fold scores
    p = RES_DIR / f"{run_id}_fold_scores.json"
    p.write_text(json.dumps({
        "run_id": run_id,
        "n_folds": args.folds, "n_reps": args.repeats, "seed": args.seed,
        "fold_sizes_mean": {"n_train": round(n_train_mean, 1), "n_test": round(n_test_mean, 1)},
        "fold_scores": cv_out["fold_scores"],
    }, indent=2))
    artefacts["fold_scores"] = str(p)

    # CV summary + effects
    p = RES_DIR / f"{run_id}_cv_summary.json"
    p.write_text(json.dumps({
        "run_id": run_id,
        "cv_summary": stat_out["cv_summary"],
        "canon_effects": stat_out["canon_effects"],
    }, indent=2))
    artefacts["cv_summary"] = str(p)

    # single split
    p = RES_DIR / f"{run_id}_single_split.json"
    p.write_text(json.dumps(ss, indent=2, default=str))
    artefacts["single_split"] = str(p)

    # semantic validation
    p = RES_DIR / f"{run_id}_semantic_validation.json"
    p.write_text(json.dumps(sem, indent=2))
    artefacts["semantic_validation"] = str(p)

    # audit index
    index = {
        "run_id":          run_id,
        "timestamp":       env["timestamp"],
        "seed":            args.seed,
        "n_folds":         args.folds,
        "n_reps":          args.repeats,
        "n_samples":       len(df),
        "bugs_found": {
            "double_canonicalization_sig_norm": {
                "description": (
                    "scripts/08_final_experiment.py L164 passed Xte_obf_n "
                    "(already canonicalized) to NormalizedSignatureBaseline.predict(), "
                    "which calls canonicalize() internally. This caused double "
                    "canonicalization for the signature_normalized/obf condition."
                ),
                "status": "FIXED in audit_run.py — passing raw Xte_obf instead",
                "effect": "Inflated signature_normalized obf F1 in prior runs",
            },
            "obfuscation_technique_count_mismatch": {
                "description": (
                    f"_TECHNIQUES has {len(_TECHNIQUES)} entries "
                    f"({sorted(_TECHNIQUES.keys())}), "
                    "but paper and experiment scripts claim 6 techniques. "
                    "partial_url_encode is the undisclosed 7th."
                ),
                "status": "DOCUMENTED — not removing, but paper must acknowledge",
            },
            "sd_triangle_violation_in_paper_table": {
                "description": (
                    "Paper Table I claimed SD_raw=0.046, SD_norm=0.008, SD_diff=0.027 "
                    "for LR. This violates |SD_raw-SD_norm|<=SD_diff<=SD_raw+SD_norm "
                    "(0.038 <= 0.027 is false). Numbers came from a different run/dataset."
                ),
                "status": "REPLACED — actual values from this run recorded in cv_summary",
            },
        },
        "artefacts":       artefacts,
        "n_predictions":   len(cv_out["predictions"]),
        "open_work": [
            "Independent test dataset (CSIC 2010) not yet integrated",
            "Realistic benign traffic not yet collected",
            "XSS validation requires headless browser — not implemented",
            "SQLi oracle limited to single equality-template context",
            "VM benchmark (E7) pending aiohttp installation on WAF VM",
        ],
    }
    p = RES_DIR / f"{run_id}_experiment_audit_index.json"
    p.write_text(json.dumps(index, indent=2))
    artefacts["audit_index"] = str(p)

    print(f"\n[audit] All artefacts written to {RES_DIR}")
    for k, v in artefacts.items():
        print(f"  {k:25} {Path(v).name}")
    print(f"\n[audit] run_id = {run_id}")
    return run_id, index


if __name__ == "__main__":
    main()
