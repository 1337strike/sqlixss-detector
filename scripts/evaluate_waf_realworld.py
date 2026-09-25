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
import re
import sys
import tempfile
import time
import urllib.parse
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.recon_detection import classify_recon  # noqa: E402
from src.waf_proxy import WafProxy, load_config  # noqa: E402

CONFIGS = {
    "LR+MNB+Sig (default)": ["logistic_regression", "naive_bayes", "signature_baseline"],
    "LR+Sig": ["logistic_regression", "signature_baseline"],
    "LR+SVM+Sig": ["logistic_regression", "svm", "signature_baseline"],
    "LR+MNB+SVM+Sig": ["logistic_regression", "naive_bayes", "svm", "signature_baseline"],
    "Sig only": ["signature_baseline"],
}


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


def build_proxy(models: list[str], log_dir: Path) -> WafProxy:
    config = load_config()
    config.update(models=models, voting_policy="any", log_path=str(log_dir / "eval.log"))
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


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csic", type=Path, required=True)
    ap.add_argument("--sqli", type=Path, required=True)
    ap.add_argument("--xss", type=Path, required=True)
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

    recon_fp = sum(classify_recon(r["path_qs"], r["headers"], "203.0.113.5", []).flagged for r in csic)

    results = {}
    with tempfile.TemporaryDirectory() as tmp:
        for name in args.configs:
            waf = build_proxy(CONFIGS[name], Path(tmp))
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
            n_calls = len(csic) + 3 * (len(sqli) + len(xss))
            results[name] = {
                "fp_rate": fp / len(csic), "fp": fp, "fp_by_detector": dict(fp_by),
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
