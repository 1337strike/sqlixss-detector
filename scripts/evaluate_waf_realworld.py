"""
evaluate_waf_realworld.py
--------------------------
Deployment-level evaluation of the WAF's content inspection on data the
models never saw. Separate from the paper's experiment; it does not change
any paper number.

Runs WafProxy.classify_payload() -- the exact decision the live proxy makes
-- plus the recon pre-filter, for several detector configurations:

  * False positives: CSIC 2010 normal traffic (36,000 HTTP requests from an
    e-commerce application; Spanish text, Latin-1 percent-encoding).
  * Detection: independent SQLi / XSS payload lists (e.g. the
    PayloadsAllTheThings "Intruder" files), with strings that also occur in
    the training corpus removed so this is a true holdout. Each payload is
    injected into a query parameter, a form body and a JSON value.

Datasets are not bundled (third-party licensing). Download them first:

    CSIC 2010 normal traffic: normalTrafficTest.txt
      http://www.isi.csic.es/dataset/  (or a research mirror)
    PayloadsAllTheThings: https://github.com/swisskyrepo/PayloadsAllTheThings
      "SQL Injection/Intruder/*.txt", "XSS Injection/Intruders/*.txt"

Run:
    python scripts/evaluate_waf_realworld.py \\
        --csic normalTrafficTest.txt --sqli sqli_all.txt --xss xss_all.txt
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
import tempfile
import time
import urllib.parse
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import pandas as pd  # noqa: E402

from src.recon_detection import classify_recon  # noqa: E402
from src.waf_proxy import WafProxy, load_config  # noqa: E402

# name -> (model_set, detectors). "paper" = models/*.joblib as evaluated in
# the paper; "deploy" = models/deploy/ (scripts/train_deploy_models.py).
CONFIGS = {
    "deploy LR+SVM+Sig": ("deploy", ["logistic_regression", "svm", "signature_baseline"]),
    "deploy LR+Sig": ("deploy", ["logistic_regression", "signature_baseline"]),
    "paper LR+SVM+Sig": ("paper", ["logistic_regression", "svm", "signature_baseline"]),
    "paper LR+Sig": ("paper", ["logistic_regression", "signature_baseline"]),
    "paper LR+MNB+Sig": ("paper", ["logistic_regression", "naive_bayes", "signature_baseline"]),
    "Sig only": ("paper", ["signature_baseline"]),
}

# Short, ordinary values (plus a few deliberately ambiguous ones) paired with
# parameter names HELD OUT from deployment-model training.
GRID_VALUES = (list("abcdefghijklmnopqrstuvwxyz0123456789") + [
    "yes", "no", "true", "false", "null", "none", "all", "asc", "desc", "new", "top", "x1", "ab",
    "abc", "test", "admin", "user", "guest", "home", "login", "select", "update", "delete", "insert",
    "union", "from", "where", "script", "alert", "table", "drop", "and", "or", "not", "1-2",
    "2019-2020", "10%", "a+b", "hello world", "it's", "o'neil", "don't", "rock & roll", "c:\\temp",
    "/home/user", "<3", "a=b", "order by name", "5' 10\""])


def parse_csic(path: Path) -> list[dict]:
    """Parse CSIC 2010 raw HTTP dumps into {method, path_qs, headers, body}."""
    text = path.read_bytes().decode("latin-1")
    requests, lines, i = [], text.split("\n"), 0
    while i < len(lines):
        line = lines[i].rstrip("\r")
        if not line.startswith(("GET ", "POST ", "PUT ")):
            i += 1
            continue
        method, url, _ = line.split(" ", 2)
        parts = urllib.parse.urlsplit(url)
        path_qs = parts.path + (f"?{parts.query}" if parts.query else "")
        headers, i = {}, i + 1
        while i < len(lines) and lines[i].rstrip("\r"):
            k, _, v = lines[i].rstrip("\r").partition(": ")
            headers[k] = v
            i += 1
        i += 1
        body = ""
        if method in ("POST", "PUT") and i < len(lines):
            body = lines[i].rstrip("\r")
            i += 1
        requests.append({"method": method, "path_qs": path_qs, "headers": headers, "body": body})
    return requests


def load_payloads(path: Path, training: set[str]) -> tuple[list[str], int]:
    seen, out, overlap = set(), [], 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if not s or s in seen:
            continue
        seen.add(s)
        if s in training:
            overlap += 1
            continue
        out.append(s)
    return out, overlap


# Fuzzing wordlists mix complete payloads with probe fragments that are not
# attacks on their own and would be ordinary text in real traffic: comment
# lines, bare event-handler names ("onclick"), a lone encoded "<", and
# 1-3 character tokens ("1", "=", "[1]"). Detection is reported both over
# all lines and over complete payloads only.
_FRAGMENT_RES = [
    re.compile(r"^#"),                                     # wordlist comment
    re.compile(r"^on[a-z]+$", re.I),                       # bare handler name
    re.compile(r"^(&#x?0*3c;?|&lt;?|%3c|\\u003c|\\x3c)$", re.I),  # lone "<"
    re.compile(r"^(&#0*60;?)$"),
]


def is_fragment(p: str) -> bool:
    return len(p) <= 3 or any(r.search(p) for r in _FRAGMENT_RES)


def build_proxy(models: list[str], log_dir: Path, model_set: str = "deploy") -> WafProxy:
    config = load_config()
    config.update(models=models, model_set=model_set, voting_policy="any",
                  log_path=str(log_dir / f"eval_{model_set}.log"))
    config["rate_limit"] = {**config.get("rate_limit", {}), "backend": "memory"}
    return WafProxy(config)


def inject(payload: str, where: str) -> tuple[str, dict, bytes, str]:
    enc = urllib.parse.quote(payload, safe="")
    if where == "query":
        return f"/search?q={enc}", {}, b"", ""
    if where == "form":
        return "/comment", {}, f"comment={enc}&submit=Send".encode(), "application/x-www-form-urlencoded"
    if where == "json":
        return "/api/profile", {}, json.dumps({"bio": payload}).encode(), "application/json"
    raise ValueError(where)


def load_sqlmap_attacks(log: Path) -> list[str]:
    """Attack requests from a WAF log of a sqlmap run (plain numeric or
    alphanumeric probes such as q=1 are baseline requests, not attacks)."""
    probe = re.compile(r"^-?[0-9]+$|^[A-Za-z0-9]{1,12}$")
    out = []
    for line in log.read_text().splitlines():
        e = json.loads(line)
        if e["decision"] not in ("blocked", "allowed"):
            continue
        qs = urllib.parse.parse_qs(urllib.parse.urlsplit(e["path"]).query, keep_blank_values=True)
        if not probe.match(qs.get("q", [""])[0]):
            out.append(e["path"])
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csic", type=Path, required=True)
    ap.add_argument("--sqli", type=Path, required=True)
    ap.add_argument("--xss", type=Path, required=True)
    ap.add_argument("--sqlmap-log", type=Path, help="WAF log from a sqlmap run, replayed per config")
    ap.add_argument("--configs", nargs="*", default=list(CONFIGS))
    ap.add_argument("--json-out", type=Path)
    args = ap.parse_args()

    training = set()
    for f in ("real_sqli_payloads.txt", "real_xss_payloads.txt"):
        training |= set((ROOT / "data" / "raw" / f).read_text(encoding="utf-8").splitlines())

    csic = parse_csic(args.csic)
    sqli, sqli_overlap = load_payloads(args.sqli, training)
    xss, xss_overlap = load_payloads(args.xss, training)
    print(f"CSIC normal requests: {len(csic)}")
    print(f"SQLi holdout payloads: {len(sqli)} ({sqli_overlap} removed: in training corpus), "
          f"{sum(not is_fragment(p) for p in sqli)} complete")
    print(f"XSS  holdout payloads: {len(xss)} ({xss_overlap} removed: in training corpus), "
          f"{sum(not is_fragment(p) for p in xss)} complete\n")

    from train_deploy_models import split_param_names
    grid = [f"{n}={v}" for n in split_param_names()[1] for v in GRID_VALUES]
    grid = random.Random(0).sample(grid, min(20000, len(grid)))
    test_clean = pd.read_csv(ROOT / "data" / "processed" / "test_clean.csv")
    test_obf = pd.read_csv(ROOT / "data" / "processed" / "test_obfuscated.csv")
    sqlmap_paths = load_sqlmap_attacks(args.sqlmap_log) if args.sqlmap_log else []
    print(f"Held-out-name grid: {len(grid)} inputs; paper test split: {len(test_clean)} clean / "
          f"{len(test_obf)} obfuscated; sqlmap attack requests: {len(sqlmap_paths)}")

    recon_fp = sum(classify_recon(r["path_qs"], r["headers"], "203.0.113.5", []).flagged for r in csic)

    results = {}
    with tempfile.TemporaryDirectory() as tmp:
        for name in args.configs:
            model_set, models = CONFIGS[name]
            waf = build_proxy(models, Path(tmp), model_set)
            t0 = time.perf_counter()

            fp, fp_by = 0, Counter()
            fp_examples = []
            for r in csic:
                ct = r["headers"].get("Content-Type", "")
                v = waf.classify_payload(r["path_qs"], r["headers"], r["body"].encode("latin-1"), ct)
                if v is not None:
                    fp += 1
                    fp_by.update(v.triggered_by)
                    if len(fp_examples) < 5:
                        fp_examples.append((r["path_qs"][:90] + (" | " + r["body"][:60] if r["body"] else ""),
                                            v.triggered_by))

            det, det_full = {}, {}
            for label, payloads in (("sqli", sqli), ("xss", xss)):
                for where in ("query", "form", "json"):
                    hits = {p: waf.classify_payload(*inject(p, where)) is not None for p in payloads}
                    full = [p for p in payloads if not is_fragment(p)]
                    det[f"{label}_{where}"] = sum(hits.values()) / len(payloads)
                    det_full[f"{label}_{where}"] = sum(hits[p] for p in full) / len(full)

            ms = (time.perf_counter() - t0) * 1000

            def q(v):
                return waf.classify_payload("/p?q=" + urllib.parse.quote(v, safe=""), {}, b"", "") is not None
            grid_fp = [g for g in grid
                       if waf.classify_payload("/p?" + urllib.parse.quote(g, safe="=&"), {}, b"", "") is not None]
            ben = test_clean[test_clean.label == "benign"].payload.astype(str)
            paper_split = {
                "benign_fp": sum(q(v) for v in ben) / len(ben),
                "clean_attack_detect": test_clean[test_clean.label != "benign"].payload.astype(str).map(q).mean(),
                "obf_attack_detect": test_obf[test_obf.label != "benign"].payload.astype(str).map(q).mean(),
            }
            sqlmap_det = (sum(waf.classify_payload(p, {}, b"", "") is not None for p in sqlmap_paths)
                          / len(sqlmap_paths)) if sqlmap_paths else None
            n_calls = len(csic) + 3 * (len(sqli) + len(xss))
            results[name] = {
                "fp_rate": fp / len(csic), "fp": fp, "fp_by_detector": dict(fp_by),
                "grid_fp_rate": len(grid_fp) / len(grid), "grid_fp_examples": grid_fp[:15],
                "paper_split": paper_split, "sqlmap_detect": sqlmap_det,
                "fp_examples": fp_examples, "detection_all_lines": det, "detection": det_full, "mean_ms_per_request": ms / n_calls,
            }

    print(f"Recon pre-filter false positives on CSIC normal: {recon_fp}/{len(csic)}\n")
    hdr = f"{'config':22} {'FP rate':>9} {'FP':>6} | " + " ".join(
        f"{k:>10}" for k in ("sqli_query", "sqli_form", "sqli_json", "xss_query", "xss_form", "xss_json"))
    for key, title in (("detection", "complete payloads"), ("detection_all_lines", "all wordlist lines")):
        print(f"Detection over {title}:")
        print(hdr + "   ms/req")
        print("-" * len(hdr) + "---------")
        for name, r in results.items():
            d = r[key]
            print(f"{name:22} {r['fp_rate']:>8.2%} {r['fp']:>6} | " + " ".join(
                f"{d[k]:>10.1%}" for k in ("sqli_query", "sqli_form", "sqli_json", "xss_query", "xss_form", "xss_json"))
                + f"   {r['mean_ms_per_request']:.2f}")
        print()
    print(f"{'config':22} {'CSIC FP':>8} {'grid FP':>8} | {'paper-split benign FP':>21} {'clean det':>9} "
          f"{'obf det':>8} | {'sqlmap':>7}")
    for name, r in results.items():
        ps = r["paper_split"]
        sm = f"{r['sqlmap_detect']:.2%}" if r["sqlmap_detect"] is not None else "-"
        print(f"{name:22} {r['fp_rate']:>8.2%} {r['grid_fp_rate']:>8.2%} | {ps['benign_fp']:>21.2%} "
              f"{ps['clean_attack_detect']:>9.2%} {ps['obf_attack_detect']:>8.2%} | {sm:>7}")
    for name, r in results.items():
        if r["grid_fp_examples"]:
            print(f"\n{name} held-out-name grid FP examples: {r['grid_fp_examples'][:10]}")
    for name, r in results.items():
        if r["fp"]:
            print(f"\n{name} FPs by detector: {r['fp_by_detector']}")
            for ex, by in r["fp_examples"]:
                print(f"   {by}  {ex}")

    if args.json_out:
        args.json_out.write_text(json.dumps({
            "csic_normal": len(csic), "sqli_holdout": len(sqli), "xss_holdout": len(xss),
            "recon_fp": recon_fp, "results": results}, indent=2, default=str))


if __name__ == "__main__":
    main()
