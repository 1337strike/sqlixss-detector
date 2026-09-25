"""
00_download_payloads.py
------------------------
Downloads the real-world SQLi and XSS payload corpus used in the thesis
experiments, so results are reproducible from a clean checkout without
shipping third-party payload files inside the repo.

Source: InfoSecWarrior/Offensive-Payloads (GitHub), an actively maintained
penetration-testing payload repository. These are real attack strings
documented and used in security assessments.

Run:
    python scripts/00_download_payloads.py                  # pinned paper corpus
    python scripts/00_download_payloads.py --upstream-main  # latest upstream

Writes:
    data/raw/real_sqli_payloads.txt   (307 unique payloads)
    data/raw/real_xss_payloads.txt    (135 unique payloads)
    data/raw/provenance.json          (source metadata for reproducibility)
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
import urllib.request
from pathlib import Path

RAW_DIR = Path(__file__).resolve().parent.parent / "data" / "raw"

# Pinned upstream commit. The source repository is actively maintained, so
# fetching `main` would silently change the corpus (and every paper number)
# whenever upstream edits these files. This commit reproduces the committed
# data/raw/*.txt byte-for-byte; pass --upstream-main to fetch the latest
# revision instead (checksums are then not enforced).
UPSTREAM_COMMIT = "9e67029a4fa4bfd6a2776f99d2df9c1e660abcab"
_BASE = "https://raw.githubusercontent.com/InfoSecWarrior/Offensive-Payloads/{ref}/"

SOURCES = {
    "real_sqli_payloads.txt": ("SQL-Injection-Payloads.txt", "sqli"),
    "real_xss_payloads.txt": ("Cross-Site-Scripting-XSS-Payloads.txt", "xss"),
}

# SHA-256 of the processed (filtered, de-duplicated) files used in the paper.
EXPECTED_SHA256 = {
    "real_sqli_payloads.txt": "01c4ddf71c865791175436cabbc7b81772e1e0c82061da788475c68b5c5eadc3",
    "real_xss_payloads.txt": "4910570126f9ce1afea38880c2cf1fd105e6a9a61690dc87f8cbd0cc4587cebb",
}

# Lines in the SQLi file that are prose annotations rather than payloads.
_ANNOTATION_MARKERS = (
    "addition, concatenate",
    "(double pipe) concatenate",
    "wildcard attribute indicator",
    "local variable",
    "global variable",
)


def is_payload(line: str) -> bool:
    s = line.strip()
    if not s:
        return False
    return not any(marker in s for marker in _ANNOTATION_MARKERS)


def download(url: str, dest: Path) -> list[str]:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "sqlixss-detector/research-script"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        text = resp.read().decode("utf-8", errors="replace")

    lines = [l.rstrip("\n") for l in text.splitlines()]
    kept = [l for l in lines if is_payload(l)]
    # de-duplicate while preserving order
    seen, unique = set(), []
    for l in kept:
        if l not in seen:
            seen.add(l)
            unique.append(l)

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("\n".join(unique) + "\n", encoding="utf-8")
    return unique


if __name__ == "__main__":
    use_main = "--upstream-main" in sys.argv[1:]
    ref = "main" if use_main else UPSTREAM_COMMIT
    print(f"[00] Downloading real payload corpora (upstream ref {ref}) ...\n")
    RAW_DIR.mkdir(parents=True, exist_ok=True)

    provenance = {}
    total = 0
    failed = []
    mismatched = []

    for filename, (upstream_name, category) in SOURCES.items():
        dest = RAW_DIR / filename
        url = _BASE.format(ref=ref) + upstream_name
        try:
            payloads = download(url, dest)
            total += len(payloads)
            digest = hashlib.sha256(dest.read_bytes()).hexdigest()
            provenance[filename] = {
                "url": url,
                "upstream_commit": ref,
                "category": category,
                "count": len(payloads),
                "sha256": digest,
                "downloaded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            if not use_main and digest != EXPECTED_SHA256[filename]:
                mismatched.append(filename)
                print(f"  FAIL  {filename:32} sha256 {digest[:16]}… != paper corpus")
            else:
                print(f"  OK    {filename:32} {len(payloads):>4} unique payloads")
        except Exception as e:
            failed.append(filename)
            print(f"  FAIL  {filename:32} {type(e).__name__}: {e}")

    if mismatched:
        print(f"\n[00] {len(mismatched)} file(s) differ from the paper corpus; "
              f"results will not match the paper. Restore with: git checkout data/raw")
        sys.exit(1)

    # write provenance record for reproducibility section
    (RAW_DIR / "provenance.json").write_text(
        json.dumps(provenance, indent=2) + "\n", encoding="utf-8"
    )

    if failed:
        print(f"\n[00] {len(failed)} download(s) failed.")
        print("     Download manually from:")
        for f in failed:
            print(f"       {_BASE.format(ref=ref) + SOURCES[f][0]}")
        print(f"     and save into {RAW_DIR}")
        sys.exit(1)

    print(f"\n[00] Done — {total} payloads total in {RAW_DIR}")
    print("[00] Next: python scripts/01c_build_grouped_dataset.py")
