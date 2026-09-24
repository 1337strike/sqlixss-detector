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
    python scripts/00_download_payloads.py

Writes:
    data/raw/real_sqli_payloads.txt   (307 unique payloads)
    data/raw/real_xss_payloads.txt    (135 unique payloads)
    data/raw/provenance.json          (source metadata for reproducibility)
"""

from __future__ import annotations

import json
import sys
import time
import urllib.request
from pathlib import Path

RAW_DIR = Path(__file__).resolve().parent.parent / "data" / "raw"

SOURCES = {
    "real_sqli_payloads.txt": (
        "https://raw.githubusercontent.com/InfoSecWarrior/Offensive-Payloads/"
        "main/SQL-Injection-Payloads.txt",
        "sqli",
    ),
    "real_xss_payloads.txt": (
        "https://raw.githubusercontent.com/InfoSecWarrior/Offensive-Payloads/"
        "main/Cross-Site-Scripting-XSS-Payloads.txt",
        "xss",
    ),
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
    print("[00] Downloading real payload corpora ...\n")
    RAW_DIR.mkdir(parents=True, exist_ok=True)

    provenance = {}
    total = 0
    failed = []

    for filename, (url, category) in SOURCES.items():
        dest = RAW_DIR / filename
        try:
            payloads = download(url, dest)
            total += len(payloads)
            provenance[filename] = {
                "url": url,
                "category": category,
                "count": len(payloads),
                "downloaded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            print(f"  OK    {filename:32} {len(payloads):>4} unique payloads")
        except Exception as e:
            failed.append(filename)
            print(f"  FAIL  {filename:32} {type(e).__name__}: {e}")

    # write provenance record for reproducibility section
    (RAW_DIR / "provenance.json").write_text(
        json.dumps(provenance, indent=2) + "\n", encoding="utf-8"
    )

    if failed:
        print(f"\n[00] {len(failed)} download(s) failed.")
        print("     Download manually from:")
        for f in failed:
            print(f"       {SOURCES[f][0]}")
        print(f"     and save into {RAW_DIR}")
        sys.exit(1)

    print(f"\n[00] Done — {total} payloads total in {RAW_DIR}")
    print("[00] Next: python scripts/01c_build_grouped_dataset.py")
