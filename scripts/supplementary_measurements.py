#!/usr/bin/env python3
"""
scripts/supplementary_measurements.py
======================================
SUPPLEMENTARY measurements for the paper revision. Nothing here replaces or
edits the archived reference run (results/definitive_20260923T094339Z_42),
which remains the source of Table V.

1. Calibration ablation
   Canonicalized linear SVM trained on the paper's 749-sample split
   (data/processed/train.csv), with and without CalibratedClassifierCV:
     svm_normalized              TF-IDF -> CalibratedClassifierCV(LinearSVC, cv=3)
                                 (the paper's configuration, src/models.py)
     svm_normalized_uncalibrated TF-IDF -> LinearSVC(C=1.0, dual="auto")
   Macro-F1 on the clean and obfuscated 263-sample test sets. The calibrated
   variant's confusion matrices are checked against the reference run.

2. Timing, Table V protocol, repeated sessions
   Per configuration: 5 warm-up predict() calls on the first 5 inputs, then
   one predict([x]) per sample over the 263 clean test inputs, timed with
   time.perf_counter(). Same inputs as definitive_experiment.run_det():
   ML "_normalized" models receive pre-canonicalized strings; the signature
   baselines receive raw strings (NormalizedSignatureBaseline canonicalizes
   inside predict()). Each session is a fresh Python process that trains the
   models and times all configurations. The uncalibrated SVM is timed in the
   same sessions so the ablation latency is directly comparable.

RUN (pinned environment, requirements.lock, Python 3.12):
    python3.12 -m venv .venv && .venv/bin/pip install -r requirements.lock
    .venv/bin/python scripts/supplementary_measurements.py --sessions 5

Output: results/supplementary_<UTC timestamp>/
    environment.json          CPU model, cores, RAM, OS, Python, package versions
    calibration_ablation.json macro-F1, confusion matrices, reference check
    timing_raw.csv            every timed call (session, config, i, ms)
    timing_sessions.csv       median/p95/p99 per session per config
    timing_summary.csv        range across sessions per config
    supplementary_tables.md   Markdown tables
    paper_paragraph.md        paragraph for the revision, numbers filled in
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC

from definitive_experiment import LABELS, PAPER_LATENCY_ARCHIVED, PROC_DIR, full_metrics
from src.baseline_normalized import NormalizedSignatureBaseline, canonicalize
from src.baseline_signature import SignatureBaseline
from src.features import build_vectorizer
from src.models import get_model_definitions

REFERENCE_RUN = ROOT / "results" / "definitive_20260923T094339Z_42"

# Table V rows, in the paper's order, plus the ablation variant.
TABLE_V_CONFIGS = [
    "logistic_regression_normalized",
    "naive_bayes_normalized",
    "svm_normalized",
    "signature_raw",
    "signature_normalized",
]
ABLATION_CONFIG = "svm_normalized_uncalibrated"
TIMED_CONFIGS = TABLE_V_CONFIGS + [ABLATION_CONFIG]

N_WARMUP = 5


# ── data / models ────────────────────────────────────────────────────────────

def load_split():
    train = pd.read_csv(PROC_DIR / "train.csv").dropna(subset=["payload", "label"])
    clean = pd.read_csv(PROC_DIR / "test_clean.csv").dropna(subset=["payload", "label"])
    obf = pd.read_csv(PROC_DIR / "test_obfuscated.csv").dropna(subset=["payload", "label"])
    Xtr, ytr = train["payload"].tolist(), train["label"].tolist()
    Xc, yc = clean["payload"].tolist(), clean["label"].tolist()
    Xo, yo = obf["payload"].tolist(), obf["label"].tolist()
    assert len(Xtr) == 749, f"expected 749 training samples, got {len(Xtr)}"
    assert len(Xc) == len(Xo) == 263, f"expected 263 test samples, got {len(Xc)}/{len(Xo)}"
    assert yc == yo, "labels differ between clean and obfuscated test sets"
    return Xtr, ytr, Xc, yc, Xo, yo


def svm_pipeline(calibrated: bool) -> Pipeline:
    if calibrated:
        # identical to src.models.get_model_definitions()["svm"]
        return get_model_definitions()["svm"]
    return Pipeline([
        ("tfidf", build_vectorizer()),
        ("clf", LinearSVC(C=1.0, dual="auto")),
    ])


def build_detectors(Xtr, ytr):
    """Train every timed configuration. Returns {config: (model, uses_canon_input)}."""
    Xtr_n = [canonicalize(p) for p in Xtr]
    defs = get_model_definitions()
    lr = defs["logistic_regression"]; lr.fit(Xtr_n, ytr)
    nb = defs["naive_bayes"];         nb.fit(Xtr_n, ytr)
    svm_cal = svm_pipeline(True);     svm_cal.fit(Xtr_n, ytr)
    svm_unc = svm_pipeline(False);    svm_unc.fit(Xtr_n, ytr)
    return {
        "logistic_regression_normalized": (lr, True),
        "naive_bayes_normalized":         (nb, True),
        "svm_normalized":                 (svm_cal, True),
        "signature_raw":                  (SignatureBaseline(), False),
        "signature_normalized":           (NormalizedSignatureBaseline(), False),
        ABLATION_CONFIG:                  (svm_unc, True),
    }


# ── timing ───────────────────────────────────────────────────────────────────

def time_calls(model, X) -> list[float]:
    """Table V protocol (definitive_experiment.measure_latency), raw times kept."""
    for p in X[:N_WARMUP]:
        model.predict([p])
    times = []
    for p in X:
        t0 = time.perf_counter()
        model.predict([p])
        times.append((time.perf_counter() - t0) * 1000.0)
    return times


def timing_worker() -> None:
    """One session: fresh process, train, time every config, JSON to stdout."""
    Xtr, ytr, Xc, _, _, _ = load_split()
    Xc_n = [canonicalize(p) for p in Xc]
    dets = build_detectors(Xtr, ytr)
    out = {}
    for cfg in TIMED_CONFIGS:
        model, canon = dets[cfg]
        out[cfg] = time_calls(model, Xc_n if canon else Xc)
    json.dump(out, sys.stdout)


def pct(times, q) -> float:
    return float(np.percentile(times, q))


# ── environment ──────────────────────────────────────────────────────────────

def _read(path: str) -> str:
    try:
        return Path(path).read_text()
    except OSError:
        return ""


def env_info() -> dict:
    cpuinfo = _read("/proc/cpuinfo")
    model = next((l.split(":", 1)[1].strip() for l in cpuinfo.splitlines()
                  if l.startswith("model name")), platform.processor() or "unknown")
    phys = {(l1, l2) for l1, l2 in zip(
        [l.split(":", 1)[1].strip() for l in cpuinfo.splitlines() if l.startswith("physical id")],
        [l.split(":", 1)[1].strip() for l in cpuinfo.splitlines() if l.startswith("core id")])}
    mem_kb = next((int(l.split()[1]) for l in _read("/proc/meminfo").splitlines()
                   if l.startswith("MemTotal:")), None)
    os_release = dict(
        l.split("=", 1) for l in _read("/etc/os-release").splitlines() if "=" in l)
    try:
        affinity = len(os.sched_getaffinity(0))
    except AttributeError:
        affinity = None
    lock = ROOT / "requirements.lock"
    pinned = [l.split("==")[0].strip() for l in lock.read_text().splitlines()
              if "==" in l and not l.lstrip().startswith("#")]
    packages = {}
    for name in pinned:
        try:
            packages[name] = metadata.version(name)
        except metadata.PackageNotFoundError:
            packages[name] = None
    try:
        from threadpoolctl import threadpool_info
        threadpools = [{k: d.get(k) for k in ("internal_api", "num_threads", "version")}
                       for d in threadpool_info()]
    except Exception:
        threadpools = []
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cpu_model": model,
        "logical_cpus": os.cpu_count(),
        "physical_cores": len(phys) or None,
        "cpus_usable_by_process": affinity,
        "ram_total_gib": round(mem_kb / 1024 ** 2, 2) if mem_kb else None,
        "os": os_release.get("PRETTY_NAME", "").strip('"') or platform.system(),
        "kernel": platform.release(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "packages": packages,
        "packages_match_lock": all(
            packages.get(n) == v for n, v in
            (l.split("==") for l in lock.read_text().splitlines()
             if "==" in l and not l.lstrip().startswith("#"))),
        "threadpools": threadpools,
        "thread_env": {k: os.environ.get(k) for k in
                       ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS")},
        "timer": "time.perf_counter",
        "timer_resolution_s": time.get_clock_info("perf_counter").resolution,
    }


# ── part 1: calibration ablation ─────────────────────────────────────────────

def calibration_ablation() -> dict:
    Xtr, ytr, Xc, yc, Xo, yo = load_split()
    Xtr_n = [canonicalize(p) for p in Xtr]
    Xc_n = [canonicalize(p) for p in Xc]
    Xo_n = [canonicalize(p) for p in Xo]

    ref = json.loads((REFERENCE_RUN / "single_split.json").read_text())["detectors"]
    out = {}
    for cfg, calibrated in (("svm_normalized", True), (ABLATION_CONFIG, False)):
        model = svm_pipeline(calibrated)
        t0 = time.perf_counter()
        model.fit(Xtr_n, ytr)
        fit_s = time.perf_counter() - t0
        m_c = full_metrics(yc, model.predict(Xc_n))
        m_o = full_metrics(yo, model.predict(Xo_n))
        entry = {
            "calibrated": calibrated,
            "fit_seconds": round(fit_s, 4),
            "clean": m_c,
            "obf": m_o,
            "obf_drop": round(m_c["macro_f1"] - m_o["macro_f1"], 6),
        }
        if cfg in ref:
            entry["matches_reference_run"] = (
                m_c["confusion_matrix"] == ref[cfg]["clean"]["confusion_matrix"]
                and m_o["confusion_matrix"] == ref[cfg]["obf"]["confusion_matrix"])
        out[cfg] = entry
    return out


# ── reporting ────────────────────────────────────────────────────────────────

def md_table(header: list[str], rows: list[list]) -> list[str]:
    lines = ["| " + " | ".join(header) + " |",
             "|" + "|".join("---:" if i else "---" for i in range(len(header))) + "|"]
    lines += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return lines


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sessions", type=int, default=5)
    ap.add_argument("--timing-worker", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args()

    if args.timing_worker:
        timing_worker()
        return

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = ROOT / "results" / f"supplementary_{ts}"
    out_dir.mkdir(parents=True, exist_ok=False)
    print(f"[supp] output → {out_dir.relative_to(ROOT)}")

    env = env_info()
    (out_dir / "environment.json").write_text(json.dumps(env, indent=2))
    print(f"[supp] {env['cpu_model']} | {env['logical_cpus']} logical CPUs | "
          f"{env['ram_total_gib']} GiB | {env['os']} | Python {env['python']} | "
          f"lock match: {env['packages_match_lock']}")
    if not env["packages_match_lock"]:
        print("[supp] WARNING: installed packages differ from requirements.lock")

    # 1. calibration ablation
    print("[supp] calibration ablation ...")
    abl = calibration_ablation()
    (out_dir / "calibration_ablation.json").write_text(json.dumps(abl, indent=2))
    for cfg, e in abl.items():
        print(f"       {cfg:30} clean={e['clean']['macro_f1']:.4f} "
              f"obf={e['obf']['macro_f1']:.4f} "
              f"ref_match={e.get('matches_reference_run', 'n/a')}")

    # 2. timing sessions, each a fresh interpreter
    raw: dict[int, dict[str, list[float]]] = {}
    for s in range(1, args.sessions + 1):
        print(f"[supp] timing session {s}/{args.sessions} ...")
        proc = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--timing-worker"],
            check=True, capture_output=True, text=True, cwd=ROOT)
        raw[s] = json.loads(proc.stdout)

    with open(out_dir / "timing_raw.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["session", "config", "call_index", "ms"])
        for s, cfgs in raw.items():
            for cfg, times in cfgs.items():
                for i, t in enumerate(times):
                    w.writerow([s, cfg, i, f"{t:.6f}"])

    sess_rows = []
    for s, cfgs in raw.items():
        for cfg in TIMED_CONFIGS:
            t = cfgs[cfg]
            sess_rows.append({"session": s, "config": cfg, "n": len(t),
                              "median_ms": pct(t, 50), "p95_ms": pct(t, 95),
                              "p99_ms": pct(t, 99), "mean_ms": float(np.mean(t))})
    sess_df = pd.DataFrame(sess_rows)
    sess_df.round(4).to_csv(out_dir / "timing_sessions.csv", index=False)

    summ_rows = []
    for cfg in TIMED_CONFIGS:
        d = sess_df[sess_df.config == cfg]
        row = {"config": cfg, "sessions": len(d), "calls_per_session": int(d.n.iloc[0])}
        for m in ("median_ms", "p95_ms", "p99_ms"):
            row[f"{m}_min"] = float(d[m].min())
            row[f"{m}_max"] = float(d[m].max())
            row[f"{m}_median_of_sessions"] = float(d[m].median())
        arch = PAPER_LATENCY_ARCHIVED.get(cfg, {})
        row["archived_table_v_median_ms"] = arch.get("median_ms")
        row["archived_table_v_p95_ms"] = arch.get("p95_ms")
        row["archived_table_v_p99_ms"] = arch.get("p99_ms")
        summ_rows.append(row)
    summ_df = pd.DataFrame(summ_rows)
    summ_df.round(4).to_csv(out_dir / "timing_summary.csv", index=False)

    write_markdown(out_dir, env, abl, sess_df, summ_df, args.sessions)
    print(f"[supp] done → {out_dir.relative_to(ROOT)}")


def write_markdown(out_dir, env, abl, sess_df, summ_df, n_sessions) -> None:
    f4 = lambda x: f"{x:.4f}"
    rng = lambda r, m: f"{r[m + '_min']:.4f}–{r[m + '_max']:.4f}"
    pk = env["packages"]

    L = [f"# Supplementary Measurements (not part of archived Table V)",
         "",
         f"Run folder: `{out_dir.relative_to(ROOT).as_posix()}`  ",
         f"Generated by `scripts/supplementary_measurements.py` at {env['timestamp']}.",
         "",
         "> **Supplementary.** These numbers were measured separately from the paper's "
         "archived reference run `definitive_20260923T094339Z_42`. Table V in the paper "
         "is unchanged and still reports that archived run.",
         "",
         "## Environment", ""]
    L += md_table(["Item", "Value"], [
        ["CPU model", env["cpu_model"]],
        ["Logical CPUs / physical cores / usable by process",
         f"{env['logical_cpus']} / {env['physical_cores']} / {env['cpus_usable_by_process']}"],
        ["RAM", f"{env['ram_total_gib']} GiB"],
        ["OS / kernel", f"{env['os']} / {env['kernel']}"],
        ["Python", f"{env['python']} ({env['python_implementation']})"],
        ["scikit-learn / NumPy / SciPy",
         f"{pk.get('scikit-learn')} / {pk.get('numpy')} / {pk.get('scipy')}"],
        ["pandas / joblib / threadpoolctl",
         f"{pk.get('pandas')} / {pk.get('joblib')} / {pk.get('threadpoolctl')}"],
        ["All packages match requirements.lock", env["packages_match_lock"]],
        ["Timer", f"{env['timer']} (resolution {env['timer_resolution_s']} s)"],
    ])

    L += ["", "## S1. Calibration ablation (canonicalized linear SVM, 749 train / 263 test)", ""]
    rows = []
    for cfg, e in abl.items():
        s = sess_df[sess_df.config == cfg]
        rows.append([
            "LinearSVC + CalibratedClassifierCV (cv=3)" if e["calibrated"] else "LinearSVC (no calibration)",
            f4(e["clean"]["macro_f1"]), f4(e["obf"]["macro_f1"]), f4(e["obf_drop"]),
            f"{s.median_ms.median():.4f} ({s.median_ms.min():.4f}–{s.median_ms.max():.4f})",
            f"{s.p95_ms.median():.4f} ({s.p95_ms.min():.4f}–{s.p95_ms.max():.4f})",
            e.get("matches_reference_run", "n/a"),
        ])
    L += md_table(["SVM variant", "Clean macro-F1", "Obf. macro-F1", "Drop",
                   f"Median ms, median of {n_sessions} sessions (range)",
                   f"p95 ms, median of {n_sessions} sessions (range)",
                   "Matches reference run"], rows)

    L += ["", f"## S2. Latency, Table V protocol, {n_sessions} repeated sessions", "",
          "Per session: fresh process, models retrained, 5 warm-up calls, then one "
          "`predict([x])` per clean test input (263 calls). Range = min–max of the "
          "per-session statistic.", ""]
    L += md_table(["Configuration", "Median ms (range)", "p95 ms (range)", "p99 ms (range)",
                   "Archived Table V median / p95 / p99"],
                  [[r["config"], rng(r, "median_ms"), rng(r, "p95_ms"), rng(r, "p99_ms"),
                    (f"{r['archived_table_v_median_ms']} / {r['archived_table_v_p95_ms']} / "
                     f"{r['archived_table_v_p99_ms']}")
                    if pd.notna(r["archived_table_v_median_ms"]) else "—"]
                   for _, r in summ_df.iterrows()])

    L += ["", "### Per-session values (ms)", ""]
    L += md_table(["Configuration", "Session", "Median", "p95", "p99"],
                  [[r.config, r.session, f4(r.median_ms), f4(r.p95_ms), f4(r.p99_ms)]
                   for r in sess_df.itertuples()])
    (out_dir / "supplementary_tables.md").write_text("\n".join(L) + "\n")

    # paper paragraph, numbers filled from this run
    cal, unc = abl["svm_normalized"], abl[ABLATION_CONFIG]
    S = {r["config"]: r for _, r in summ_df.iterrows()}
    sc, su = S["svm_normalized"], S[ABLATION_CONFIG]
    fastest = min(TABLE_V_CONFIGS, key=lambda c: S[c]["median_ms_median_of_sessions"])
    slowest = max(TABLE_V_CONFIGS, key=lambda c: S[c]["median_ms_median_of_sessions"])
    same_f1 = (cal["clean"]["macro_f1"] == unc["clean"]["macro_f1"]
               and cal["obf"]["macro_f1"] == unc["obf"]["macro_f1"])
    speedup = sc["median_ms_median_of_sessions"] / su["median_ms_median_of_sessions"]
    if speedup > 1:
        lat_sentence = (
            f"Median single-request latency fell from {sc['median_ms_median_of_sessions']:.3f} ms "
            f"to {su['median_ms_median_of_sessions']:.3f} ms ({speedup:.1f}× faster); the "
            "calibrated model evaluates three LinearSVC fits and their sigmoid calibrators "
            "per call. ")
    else:
        lat_sentence = (
            f"Median single-request latency was {sc['median_ms_median_of_sessions']:.3f} ms with "
            f"calibration and {su['median_ms_median_of_sessions']:.3f} ms without it. ")
    ranking_sentence = ("The ranking of the configurations was the same in every session"
                        if _same_ranking(sess_df) else
                        "The ranking of the configurations changed between sessions")
    para = (
        "**Supplementary measurements.** To separate the cost of probability "
        "calibration from the linear decision function, we retrained the canonicalized "
        "linear SVM on the same 749-sample training split without "
        "`CalibratedClassifierCV`. "
        f"Macro-F1 was {cal['clean']['macro_f1']:.4f} (clean) and "
        f"{cal['obf']['macro_f1']:.4f} (obfuscated) with calibration, and "
        f"{unc['clean']['macro_f1']:.4f} and {unc['obf']['macro_f1']:.4f} without it"
        + (" (identical)" if same_f1 else "") + ". "
        + lat_sentence +
        f"We also repeated the Table V timing protocol in {n_sessions} independent sessions "
        f"on a {env['cpu_model']} ({env['cpus_usable_by_process']} usable CPU(s), "
        f"{env['ram_total_gib']} GiB RAM, {env['os']}, Python {env['python']}, "
        f"scikit-learn {pk.get('scikit-learn')}). "
        f"Across sessions, median latency ranged from {rng(S[fastest], 'median_ms')} ms "
        f"({fastest}) to {rng(S[slowest], 'median_ms')} ms ({slowest}), and the "
        f"canonicalized SVM's p99 ranged from {rng(sc, 'p99_ms')} ms. "
        + ranking_sentence
    )
    para += (". These values are supplementary. Table V still reports the archived "
             "reference run, and absolute latencies depend on hardware.")
    (out_dir / "paper_paragraph.md").write_text(para + "\n")


def _same_ranking(sess_df) -> bool:
    ranks = set()
    for s, d in sess_df[sess_df.config.isin(TABLE_V_CONFIGS)].groupby("session"):
        ranks.add(tuple(d.sort_values("median_ms").config))
    return len(ranks) == 1


if __name__ == "__main__":
    main()
