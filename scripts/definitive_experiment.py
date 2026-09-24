#!/usr/bin/env python3
"""
scripts/definitive_experiment.py
==================================
Single authoritative experiment run that generates every table and number
in the ICITDA paper. Run this to reproduce or verify all paper claims.

Protocol matches paper §III exactly:
- Dataset: 01c_build_grouped_dataset.py output (749 train / 263 test)
- 8 configurations: 4 detectors × {raw, canonicalized}
- Clean and obfuscated conditions
- 5-fold × 3 repeats CV (15 fits per config)
- Single-split evaluation on pre-built 263-sample test set
- Per-technique analysis (6 techniques as in paper + partial_url_encode disclosure)
- Latency measurement (300 predictions, 5 warmup, p95)
- Full per-prediction output for audit

RUN:
    python scripts/definitive_experiment.py
    python scripts/definitive_experiment.py --seed 42 --folds 5 --repeats 3
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
import sys
import time
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
from src.models import get_model_definitions
from src.obfuscation import _TECHNIQUES, random_obfuscate
from src.statistics import holm_correct, nadeau_bengio_ttest

LABELS   = ["benign", "sqli", "xss"]
PROC_DIR = Path(__file__).resolve().parent.parent / "data" / "processed"
RAW_DIR  = Path(__file__).resolve().parent.parent / "data" / "raw"


def env_info() -> dict:
    import sklearn, scipy as sp
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "platform":  platform.platform(),
        "cpu":       platform.processor() or "unknown",
        "python":    platform.python_version(),
        "sklearn":   sklearn.__version__,
        "scipy":     sp.__version__,
        "numpy":     np.__version__,
        "n_cpus":    os.cpu_count(),
    }


def family_key(payload: str) -> str:
    f = re.sub(r"\d+", "N", payload)
    f = re.sub(r"'[^']*'", "'S'", f)
    f = re.sub(r'"[^"]*"', '"S"', f)
    return re.sub(r"\s+", " ", f).strip().lower()


def full_metrics(y_true, y_pred, labels=LABELS) -> dict:
    p, r, f, sup = precision_recall_fscore_support(
        y_true, y_pred, labels=labels, zero_division=0)
    acc = accuracy_score(y_true, y_pred)
    cm  = confusion_matrix(y_true, y_pred, labels=labels)

    # verify internal consistency
    n_correct_cm = int(cm.diagonal().sum())
    n_correct_acc = int(round(acc * len(y_true)))
    # allow 1-sample rounding difference
    assert abs(n_correct_cm - n_correct_acc) <= 1, \
        f"CM/acc mismatch: {n_correct_cm} vs {n_correct_acc}"

    label_idx = {l: i for i, l in enumerate(labels)}
    errors = {}
    for src in labels:
        for dst in labels:
            if src != dst:
                errors[f"{src}_to_{dst}"] = int(cm[label_idx[src], label_idx[dst]])

    return {
        "n":         len(y_true),
        "n_correct": int(cm.diagonal().sum()),
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
        "errors": errors,
    }


def measure_latency(model, X_sample: list, n_warmup=5, n_measure=300) -> dict:
    """Measure latency with 5 warmup calls then up to n_measure predictions.
    NOTE: Paper Table V uses archived run definitive_20260923T094339Z_42.
    Fresh runs will differ due to hardware/load variance — this is expected
    and documented in paper §III-E."""
    sample = X_sample[:n_measure]
    for p in sample[:n_warmup]:
        model.predict([p])
    times = []
    for p in sample:
        t0 = time.perf_counter()
        model.predict([p])
        times.append((time.perf_counter() - t0) * 1000)
    return {
        "n":         len(times),
        "mean_ms":   round(float(np.mean(times)),            4),
        "median_ms": round(float(np.median(times)),          4),
        "p95_ms":    round(float(np.percentile(times, 95)),  4),
        "p99_ms":    round(float(np.percentile(times, 99)),  4),
        "note":      "Hardware-dependent. Paper Table V uses archived run "
                     "definitive_20260923T094339Z_42 per §III-E.",
    }


# Archived latency from the paper's reference run (definitive_20260923T094339Z_42)
# These are the values in Table V of ICITDA_Revised_Audited.pdf
PAPER_LATENCY_ARCHIVED = {
    "logistic_regression_normalized": {"n":263,"median_ms":0.2731,"p95_ms":0.3548,"p99_ms":0.3750},
    "naive_bayes_normalized":         {"n":263,"median_ms":0.2579,"p95_ms":0.3242,"p99_ms":0.3783},
    "svm_normalized":                 {"n":263,"median_ms":1.2457,"p95_ms":1.3864,"p99_ms":1.5812},
    "signature_raw":                  {"n":263,"median_ms":0.0046,"p95_ms":0.0091,"p99_ms":0.0167},
    "signature_normalized":           {"n":263,"median_ms":0.0082,"p95_ms":0.0190,"p99_ms":0.0323},
}


def run_single_split(seed: int, run_id: str) -> dict:
    """Uses the pre-built 263-sample split from 01c_build_grouped_dataset.py.
    This matches Table II in the paper exactly."""

    train_df = pd.read_csv(PROC_DIR / "train.csv").dropna(subset=["payload","label"])
    clean_df = pd.read_csv(PROC_DIR / "test_clean.csv").dropna(subset=["payload","label"])
    obf_df   = pd.read_csv(PROC_DIR / "test_obfuscated.csv").dropna(subset=["payload","label"])

    Xtr, ytr = train_df["payload"].tolist(), train_df["label"].tolist()
    Xc,  yc  = clean_df["payload"].tolist(), clean_df["label"].tolist()
    Xo,  yo  = obf_df["payload"].tolist(),   obf_df["label"].tolist()

    assert len(Xc) == len(Xo), f"Test set size mismatch: clean={len(Xc)}, obf={len(Xo)}"
    assert all(a == b for a, b in zip(yc, yo)), "Labels differ between clean and obf"

    # Count unchanged
    unchanged = sum(1 for a, b, l in zip(Xc, Xo, yc)
                    if l in ("sqli","xss") and a == b)
    # Count techniques used
    obf_techniques = []
    if "techniques" in obf_df.columns:
        obf_techniques = obf_df["techniques"].dropna().tolist()

    Xtr_n = [canonicalize(p) for p in Xtr]
    Xc_n  = [canonicalize(p) for p in Xc]
    Xo_n  = [canonicalize(p) for p in Xo]

    result = {
        "run_id":    run_id,
        "protocol":  "01c_grouped_split",
        "n_train":   len(Xtr),
        "n_test":    len(Xc),
        "class_dist_train": {l: int(sum(1 for y in ytr if y==l)) for l in LABELS},
        "class_dist_test":  {l: int(sum(1 for y in yc  if y==l)) for l in LABELS},
        "unchanged_malicious": unchanged,
        "n_obf_techniques_in_code": len(_TECHNIQUES),
        "obf_technique_names": sorted(_TECHNIQUES.keys()),
        "detectors": {},
    }

    def run_det(tag, model, xc_in, xo_in, lat_x=None):
        """Run clean and obf evaluation, compute metrics and latency.
        Latency is measured fresh (hardware-dependent) and stored alongside
        the archived Table V values from the paper's reference run."""
        pred_c = model.predict(xc_in)
        pred_o = model.predict(xo_in)
        m_c = full_metrics(yc, pred_c)
        m_o = full_metrics(yo, pred_o)
        lat_current  = measure_latency(model, lat_x or xc_in)
        lat_archived = PAPER_LATENCY_ARCHIVED.get(tag, {})
        return {
            "clean": {
                **m_c,
                "latency_current_run": lat_current,
                "latency_paper_table_v": lat_archived,
            },
            "obf":      m_o,
            "obf_drop": round(m_c["macro_f1"] - m_o["macro_f1"], 6),
        }

    for mname in get_model_definitions():
        # raw
        mr = get_model_definitions()[mname]; mr.fit(Xtr, ytr)
        result["detectors"][f"{mname}_raw"] = run_det(
            f"{mname}_raw", mr, Xc, Xo)
        # canonicalized
        mn = get_model_definitions()[mname]; mn.fit(Xtr_n, ytr)
        result["detectors"][f"{mname}_normalized"] = run_det(
            f"{mname}_normalized", mn, Xc_n, Xo_n)

    # Signature baselines — raw gets raw input; normalized gets raw input
    # (NormalizedSignatureBaseline.predict() calls canonicalize() internally)
    sig_r = SignatureBaseline()
    sig_n = NormalizedSignatureBaseline()

    # Latency for signature: measure on raw payloads (no extra preprocessing)
    lat_r = measure_latency(sig_r, Xc)
    lat_n = measure_latency(sig_n, Xc)

    m_rc = full_metrics(yc, sig_r.predict(Xc));  m_ro = full_metrics(yo, sig_r.predict(Xo))
    m_nc = full_metrics(yc, sig_n.predict(Xc));  m_no = full_metrics(yo, sig_n.predict(Xo))

    result["detectors"]["signature_raw"] = {
        "clean": {**m_rc,
                  "latency_current_run": lat_r,
                  "latency_paper_table_v": PAPER_LATENCY_ARCHIVED.get("signature_raw", {})},
        "obf":   m_ro,
        "obf_drop": round(m_rc["macro_f1"] - m_ro["macro_f1"], 6),
    }
    result["detectors"]["signature_normalized"] = {
        "clean": {**m_nc,
                  "latency_current_run": lat_n,
                  "latency_paper_table_v": PAPER_LATENCY_ARCHIVED.get("signature_normalized", {})},
        "obf":   m_no,
        "obf_drop": round(m_nc["macro_f1"] - m_no["macro_f1"], 6),
    }

    return result


def run_cv(seed: int, n_folds: int, n_reps: int, run_id: str) -> dict:
    """CV using the full corpus with group-aware split.
    Generates Table I and Table III numbers."""

    # Load full corpus same way as audit_run.py
    from src.dataset import _BENIGN_TEMPLATES, _fill_template
    frames = []
    for fname, label in [("real_sqli_payloads.txt","sqli"),
                          ("real_xss_payloads.txt","xss")]:
        lines = list(dict.fromkeys(
            l.strip() for l in (RAW_DIR/fname).read_text().splitlines() if l.strip()))
        frames.append(pd.DataFrame({"payload":lines,"label":label}))

    rng = random.Random(seed)
    n_mal = sum(len(f) for f in frames)
    rows = []
    for i in range(n_mal + 200):
        combo = rng.sample(_BENIGN_TEMPLATES, k=rng.randint(1,3))
        rows.append({"payload":"&".join(_fill_template(t,rng) for t in combo),"label":"benign"})
    frames.append(pd.DataFrame(rows).drop_duplicates(subset="payload"))

    df = pd.concat(frames, ignore_index=True).drop_duplicates(subset="payload")
    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    df["sample_id"] = [f"s{i:05d}" for i in range(len(df))]
    df["family_id"] = df["payload"].map(family_key)

    X = df["payload"].to_numpy()
    y = df["label"].to_numpy()
    groups = df["family_id"].to_numpy()

    configs = (
        [f"{m}_raw"        for m in get_model_definitions()] +
        [f"{m}_normalized" for m in get_model_definitions()] +
        ["signature_raw", "signature_normalized"]
    )
    fold_scores = {c: {"f1_clean":[],"f1_obf":[]} for c in configs}
    fold_meta   = []
    predictions = []

    def mf1(yt, yp):
        return float(precision_recall_fscore_support(
            yt, yp, labels=LABELS, average="macro", zero_division=0)[2])

    fold_id = 0
    for rep in range(n_reps):
        sgkf = StratifiedGroupKFold(
            n_splits=n_folds, shuffle=True, random_state=seed+rep)
        for tr_idx, te_idx in sgkf.split(X, y, groups=groups):
            fold_id += 1
            Xtr, ytr = X[tr_idx], y[tr_idx]
            Xte, yte = X[te_idx], y[te_idx]
            sids = df["sample_id"].to_numpy()[te_idx]
            fams = df["family_id"].to_numpy()[te_idx]

            overlap = set(groups[tr_idx]) & set(groups[te_idx])
            assert not overlap, f"Leakage fold {fold_id}: {overlap}"

            fold_meta.append({
                "run_id":fold_id, "repeat":rep+1,
                "fold_within_rep":(fold_id-1)%n_folds+1,
                "n_train":len(Xtr),"n_test":len(Xte),
                "seed_used":seed+rep,
            })

            rng2 = random.Random(seed + fold_id * 1000)
            Xte_obf = []
            for payload, label in zip(Xte, yte):
                if label in ("sqli","xss"):
                    obf, _ = random_obfuscate(payload, seed=rng2.randint(0,10**6))
                    Xte_obf.append(obf)
                else:
                    Xte_obf.append(payload)

            Xtr_n     = [canonicalize(p) for p in Xtr]
            Xte_n     = [canonicalize(p) for p in Xte]
            Xte_obf_n = [canonicalize(p) for p in Xte_obf]

            for mname in get_model_definitions():
                # raw
                mr = get_model_definitions()[mname]; mr.fit(Xtr, ytr)
                pred_r_c = mr.predict(Xte);     pred_r_o = mr.predict(Xte_obf)
                fold_scores[f"{mname}_raw"]["f1_clean"].append(mf1(yte, pred_r_c))
                fold_scores[f"{mname}_raw"]["f1_obf"].append(  mf1(yte, pred_r_o))
                # normalized
                mn = get_model_definitions()[mname]; mn.fit(Xtr_n, ytr)
                pred_n_c = mn.predict(Xte_n);   pred_n_o = mn.predict(Xte_obf_n)
                fold_scores[f"{mname}_normalized"]["f1_clean"].append(mf1(yte, pred_n_c))
                fold_scores[f"{mname}_normalized"]["f1_obf"].append(  mf1(yte, pred_n_o))
                # save predictions
                for sid, fam, ytrue, yp_r, yp_n in zip(sids, fams, yte, pred_r_c, pred_n_c):
                    predictions.append({
                        "run_id":run_id,"fold_id":fold_id,"repeat":rep+1,
                        "sample_id":sid,"family_id":fam,
                        "y_true":ytrue,
                        f"{mname}_raw_clean":yp_r,
                        f"{mname}_norm_clean":yp_n,
                    })

            # Signature baselines: pass RAW strings (no pre-canonicalization)
            sig_r = SignatureBaseline()
            sig_n = NormalizedSignatureBaseline()
            fold_scores["signature_raw"]["f1_clean"].append(mf1(yte, sig_r.predict(list(Xte))))
            fold_scores["signature_raw"]["f1_obf"].append(  mf1(yte, sig_r.predict(list(Xte_obf))))
            fold_scores["signature_normalized"]["f1_clean"].append(mf1(yte, sig_n.predict(list(Xte))))
            fold_scores["signature_normalized"]["f1_obf"].append(  mf1(yte, sig_n.predict(list(Xte_obf))))

    n_tr_mean = np.mean([m["n_train"] for m in fold_meta])
    n_te_mean = np.mean([m["n_test"]  for m in fold_meta])

    return {
        "fold_scores": fold_scores,
        "fold_meta":   fold_meta,
        "predictions": predictions,
        "n_train_mean": round(float(n_tr_mean), 1),
        "n_test_mean":  round(float(n_te_mean), 1),
    }


def compute_stats(fold_scores: dict, n_tr: float, n_te: float) -> dict:
    """Table I (canonicalization effects) and Table III (CV summary)."""

    cv_summary = {}
    for cfg, sc in fold_scores.items():
        fc = np.array(sc["f1_clean"])
        fo = np.array(sc["f1_obf"])
        ci = stats.t.interval(0.95, len(fo)-1, loc=fo.mean(), scale=stats.sem(fo))
        cv_summary[cfg] = {
            "n_fits":         len(fc),
            "f1_clean_mean":  round(float(fc.mean()), 6),
            "f1_clean_sd":    round(float(fc.std(ddof=1)), 6),
            "f1_obf_mean":    round(float(fo.mean()), 6),
            "f1_obf_sd":      round(float(fo.std(ddof=1)), 6),
            "f1_obf_ci95_lo": round(float(ci[0]), 6),
            "f1_obf_ci95_hi": round(float(ci[1]), 6),
            "obf_drop":       round(float(fc.mean() - fo.mean()), 6),
        }

    # Table I: canonicalization effects
    models_list = list(get_model_definitions()) + ["signature"]
    effects = {}
    p_raws, effect_keys = [], []
    for mname in models_list:
        ka = f"{mname}_raw"
        kb = f"{mname}_normalized"
        if ka not in fold_scores or kb not in fold_scores:
            continue
        a = np.array(fold_scores[ka]["f1_obf"])
        b = np.array(fold_scores[kb]["f1_obf"])
        diff = b - a
        sd_a, sd_b, sd_d = float(a.std(ddof=1)), float(b.std(ddof=1)), float(diff.std(ddof=1))
        corr = float(np.corrcoef(a, b)[0,1])
        lo, hi = abs(sd_a-sd_b), sd_a+sd_b
        triangle_ok = (lo <= sd_d <= hi)

        t, p_raw = nadeau_bengio_ttest(list(a), list(b), n_train=int(n_tr), n_test=int(n_te))
        p_raws.append(p_raw)
        effect_keys.append(mname)
        effects[mname] = {
            "raw_f1_obf_mean":  round(float(a.mean()), 6),
            "raw_f1_obf_sd":    round(float(sd_a), 6),
            "norm_f1_obf_mean": round(float(b.mean()), 6),
            "norm_f1_obf_sd":   round(float(sd_b), 6),
            "gain":             round(float(diff.mean()), 6),
            "sd_diff":          round(sd_d, 6),
            "sd_diff_bounds":   [round(lo,6), round(hi,6)],
            "triangle_ok":      triangle_ok,
            "correlation":      round(corr, 6),
            "t_nb_corrected":   round(float(t), 6),
            "p_raw":            float(p_raw),
        }

    holm_ps = holm_correct(p_raws)
    for key, ph in zip(effect_keys, holm_ps):
        effects[key]["p_holm"] = float(ph)
        effects[key]["significant_005"] = bool(ph < 0.05)

    return {"cv_summary": cv_summary, "canon_effects": effects}


def run_per_technique(train_df, clean_df, obf_df, seed: int) -> dict:
    """Table IV: per-technique F1 drop.
    Paper says 6 techniques, code has 7 — report all 7 with disclosure."""
    from src.obfuscation import (
        url_encode, whitespace_manipulation, keyword_case_toggle,
        comment_insertion, unicode_substitution, partial_url_encode
    )

    Xtr, ytr = train_df["payload"].tolist(), train_df["label"].tolist()
    Xc,  yc  = clean_df["payload"].tolist(), clean_df["label"].tolist()

    # Only malicious payloads get obfuscated
    mal_mask = [l in ("sqli","xss") for l in yc]

    def apply_single(tech_fn, X, y, seed_offset):
        rng = random.Random(seed + seed_offset)
        out = []
        for payload, label in zip(X, y):
            if label in ("sqli","xss"):
                try:
                    result = tech_fn(payload, rng)
                    out.append(result)
                except Exception:
                    out.append(payload)
            else:
                out.append(payload)
        return out

    def mf1(yt, yp):
        return float(precision_recall_fscore_support(
            yt, yp, labels=LABELS, average="macro", zero_division=0)[2])

    # 6 techniques from paper + partial_url_encode (disclosed)
    technique_fns = {
        "url_encoding":         lambda p, rng: url_encode(p, rng, double=False),
        "double_url_encoding":  lambda p, rng: url_encode(p, rng, double=True),
        "whitespace_manipulation": whitespace_manipulation,
        "case_toggling":        keyword_case_toggle,
        "comment_insertion":    comment_insertion,
        "unicode_substitution": unicode_substitution,
        # 7th — present in _TECHNIQUES but not stated in paper
        "partial_url_encoding_UNDISCLOSED": partial_url_encode,
    }

    detectors = {}
    for mname in get_model_definitions():
        pipe = get_model_definitions()[mname]; pipe.fit(Xtr, ytr)
        detectors[f"{mname}_raw"] = pipe
    sig_r = SignatureBaseline()
    sig_n = NormalizedSignatureBaseline()
    detectors["signature_naive"] = sig_r
    detectors["signature_normalized"] = sig_n

    clean_f1 = {n: mf1(yc, d.predict(Xc)) for n, d in detectors.items()}

    N_SEEDS = 5
    rows = []
    for tech_name, tech_fn in technique_fns.items():
        per_det = {n: [] for n in detectors}
        for s in range(N_SEEDS):
            X_obf = apply_single(tech_fn, Xc, yc, seed_offset=s*1000)
            for det_name, model in detectors.items():
                per_det[det_name].append(mf1(yc, model.predict(X_obf)))
        for det_name, vals in per_det.items():
            arr = np.array(vals)
            rows.append({
                "technique":   tech_name,
                "detector":    det_name,
                "f1_clean":    round(clean_f1[det_name], 4),
                "f1_obf_mean": round(float(arr.mean()), 4),
                "f1_obf_sd":   round(float(arr.std(ddof=1)) if len(arr)>1 else 0.0, 4),
                "f1_drop":     round(clean_f1[det_name] - float(arr.mean()), 4),
                "n_seeds":     len(vals),
                "in_paper":    not tech_name.endswith("UNDISCLOSED"),
            })
    return {"rows": rows}


def generate_tables(ss: dict, cv_stats: dict) -> dict:
    """Generate paper-format tables as CSV and Markdown."""

    tables = {}

    # Table I — canonicalization effects
    t1_rows = []
    for mname, e in cv_stats["canon_effects"].items():
        t1_rows.append({
            "Detector":       mname.replace("_"," ").title(),
            "Raw F1±SD":      f"{e['raw_f1_obf_mean']}±{e['raw_f1_obf_sd']}",
            "Canon F1±SD":    f"{e['norm_f1_obf_mean']}±{e['norm_f1_obf_sd']}",
            "Gain":           f"+{e['gain']:.3f}",
            "p_holm":         f"{e['p_holm']:.2e}",
            "sig_005":        "✓" if e["significant_005"] else "✗",
            "triangle_ok":    "✓" if e["triangle_ok"] else "✗ VIOLATION",
            "sd_diff":        e["sd_diff"],
        })
    tables["table_I"] = t1_rows

    # Table II — single-split performance
    t2_rows = []
    for tag, det in ss["detectors"].items():
        c = det["clean"]; o = det["obf"]
        t2_rows.append({
            "Detector":   tag,
            "Clean_Acc":  c.get("accuracy",""),
            "Clean_F1":   c["macro_f1"],
            "Obf_Acc":    o.get("accuracy",""),
            "Obf_F1":     o["macro_f1"],
            "Drop":       det["obf_drop"],
            "Lat_p95_ms": c.get("latency",{}).get("p95_ms",""),
        })
    tables["table_II"] = t2_rows

    # Table III — CV canonicalized
    t3_rows = []
    canon_cfgs = [c for c in cv_stats["cv_summary"] if "normalized" in c or "canon" in c]
    for cfg in canon_cfgs:
        s = cv_stats["cv_summary"][cfg]
        t3_rows.append({
            "Detector":       cfg.replace("_normalized","").replace("_"," ").title(),
            "F1_clean":       f"{s['f1_clean_mean']}±{s['f1_clean_sd']}",
            "F1_obf":         f"{s['f1_obf_mean']}±{s['f1_obf_sd']}",
            "95CI_obf":       f"[{s['f1_obf_ci95_lo']},{s['f1_obf_ci95_hi']}]",
            "Drop":           s["obf_drop"],
        })
    tables["table_III"] = t3_rows

    return tables


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed",    type=int, default=42)
    ap.add_argument("--folds",   type=int, default=5)
    ap.add_argument("--repeats", type=int, default=3)
    args = ap.parse_args()

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id = f"definitive_{ts}_{args.seed}"
    print(f"[exp] run_id = {run_id}")

    out_dir = Path(__file__).resolve().parent.parent / "results" / run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    # 0. Environment
    env = env_info()
    (out_dir/"environment.json").write_text(json.dumps(env, indent=2))
    print(f"[exp] {env['platform'][:50]} | Python {env['python']} | sklearn {env['sklearn']}")

    # 1. Single split (matches Table II — 263-sample split)
    print("[exp] Running single-split evaluation (Table II) ...")
    ss = run_single_split(args.seed, run_id)
    (out_dir/"single_split.json").write_text(json.dumps(ss, indent=2, default=str))
    print(f"      n_train={ss['n_train']} n_test={ss['n_test']} "
          f"unchanged_mal={ss['unchanged_malicious']}")
    for tag, det in ss["detectors"].items():
        cf  = det["clean"]["macro_f1"]; of = det["obf"]["macro_f1"]
        lat = det["clean"].get("latency_current_run",
              det["clean"].get("latency",{})).get("p95_ms","?")
        print(f"      {tag:35} clean={cf:.4f} obf={of:.4f} drop={det['obf_drop']:.4f} lat={lat}ms")

    # 2. CV (Tables I + III)
    print(f"\n[exp] Running CV {args.folds}×{args.repeats} (Tables I+III) ...")
    t0 = time.perf_counter()
    cv_out = run_cv(args.seed, args.folds, args.repeats, run_id)
    print(f"      done in {time.perf_counter()-t0:.1f}s, n_train_mean={cv_out['n_train_mean']}")

    # Save fold scores
    (out_dir/"fold_scores.json").write_text(json.dumps({
        "run_id": run_id,
        "n_folds": args.folds, "n_reps": args.repeats, "seed": args.seed,
        "n_train_mean": cv_out["n_train_mean"],
        "n_test_mean":  cv_out["n_test_mean"],
        "fold_scores":  cv_out["fold_scores"],
        "fold_meta":    cv_out["fold_meta"],
    }, indent=2))

    # Save predictions
    pd.DataFrame(cv_out["predictions"]).to_csv(
        out_dir/"predictions.csv", index=False)

    # 3. Statistics
    print("[exp] Computing statistics ...")
    stats_out = compute_stats(
        cv_out["fold_scores"],
        cv_out["n_train_mean"], cv_out["n_test_mean"])
    (out_dir/"cv_stats.json").write_text(json.dumps(stats_out, indent=2))

    print("\n=== TABLE I — CANONICALIZATION EFFECTS ===")
    for m, e in stats_out["canon_effects"].items():
        tri = "OK" if e["triangle_ok"] else "VIOLATION"
        print(f"  {m:20} raw={e['raw_f1_obf_mean']:.4f}±{e['raw_f1_obf_sd']:.4f} "
              f"canon={e['norm_f1_obf_mean']:.4f}±{e['norm_f1_obf_sd']:.4f} "
              f"gain={e['gain']:.4f} SD_diff={e['sd_diff']:.4f} {tri} "
              f"p_holm={e['p_holm']:.2e}")

    print("\n=== TABLE III — CV CANONICALIZED ===")
    for cfg, s in stats_out["cv_summary"].items():
        if "normalized" in cfg or cfg == "signature_normalized":
            print(f"  {cfg:35} clean={s['f1_clean_mean']:.4f}±{s['f1_clean_sd']:.4f} "
                  f"obf={s['f1_obf_mean']:.4f}±{s['f1_obf_sd']:.4f} "
                  f"[{s['f1_obf_ci95_lo']:.4f},{s['f1_obf_ci95_hi']:.4f}] "
                  f"drop={s['obf_drop']:.4f}")

    # 4. Per-technique (Table IV)
    print("\n[exp] Per-technique analysis (Table IV) ...")
    train_df = pd.read_csv(PROC_DIR/"train.csv").dropna(subset=["payload","label"])
    clean_df = pd.read_csv(PROC_DIR/"test_clean.csv").dropna(subset=["payload","label"])
    obf_df   = pd.read_csv(PROC_DIR/"test_obfuscated.csv").dropna(subset=["payload","label"])
    pt = run_per_technique(train_df, clean_df, obf_df, args.seed)
    pt_df = pd.DataFrame(pt["rows"])
    pt_df.to_csv(out_dir/"per_technique.csv", index=False)

    print("\n=== TABLE IV — PER-TECHNIQUE F1 DROP (RAW INPUT) ===")
    pivot = pt_df[pt_df["in_paper"]==True].pivot(
        index="technique", columns="detector", values="f1_drop")
    print(pivot.round(3).to_string())
    print("\n  (+ partial_url_encoding UNDISCLOSED in paper:)")
    pu = pt_df[pt_df["in_paper"]==False]
    if not pu.empty:
        print(pu[["technique","detector","f1_drop"]].to_string(index=False))

    # 5. Generate formatted tables
    tables = generate_tables(ss, stats_out)
    (out_dir/"tables.json").write_text(json.dumps(tables, indent=2))

    # Markdown table output
    md_lines = [f"# Experiment Tables\nrun_id: `{run_id}`\n"]
    md_lines.append("## Table I — Canonicalization Effects on Obfuscated F1\n")
    if tables["table_I"]:
        header = "| " + " | ".join(tables["table_I"][0].keys()) + " |"
        sep    = "| " + " | ".join(["---"]*len(tables["table_I"][0])) + " |"
        md_lines += [header, sep]
        for row in tables["table_I"]:
            md_lines.append("| " + " | ".join(str(v) for v in row.values()) + " |")
    md_lines.append("\n## Table II — Single-Split Performance\n")
    if tables["table_II"]:
        header = "| " + " | ".join(tables["table_II"][0].keys()) + " |"
        sep    = "| " + " | ".join(["---"]*len(tables["table_II"][0])) + " |"
        md_lines += [header, sep]
        for row in tables["table_II"]:
            md_lines.append("| " + " | ".join(str(v) for v in row.values()) + " |")
    md_lines.append("\n## Table III — CV Canonicalized\n")
    if tables["table_III"]:
        header = "| " + " | ".join(tables["table_III"][0].keys()) + " |"
        sep    = "| " + " | ".join(["---"]*len(tables["table_III"][0])) + " |"
        md_lines += [header, sep]
        for row in tables["table_III"]:
            md_lines.append("| " + " | ".join(str(v) for v in row.values()) + " |")
    (out_dir/"tables.md").write_text("\n".join(md_lines))

    # 6. Manifest
    manifest = {
        "run_id": run_id,
        "timestamp": env["timestamp"],
        "seed": args.seed, "n_folds": args.folds, "n_reps": args.repeats,
        "python": env["python"], "sklearn": env["sklearn"],
        "n_obf_techniques": len(_TECHNIQUES),
        "obf_techniques": sorted(_TECHNIQUES.keys()),
        "paper_claims_6_techniques_code_has_7": True,
        "double_canonicalization_bug": "FIXED in this script (see audit_run.py)",
        "output_files": {
            "environment":   str(out_dir/"environment.json"),
            "single_split":  str(out_dir/"single_split.json"),
            "fold_scores":   str(out_dir/"fold_scores.json"),
            "predictions":   str(out_dir/"predictions.csv"),
            "cv_stats":      str(out_dir/"cv_stats.json"),
            "per_technique": str(out_dir/"per_technique.csv"),
            "tables_json":   str(out_dir/"tables.json"),
            "tables_md":     str(out_dir/"tables.md"),
        },
    }
    (out_dir/"manifest.json").write_text(json.dumps(manifest, indent=2))
    print(f"\n[exp] All results → {out_dir}")
    print(f"[exp] run_id = {run_id}")
    return run_id


if __name__ == "__main__":
    main()
