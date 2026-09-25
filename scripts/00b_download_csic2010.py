"""
00b_download_csic2010.py
------------------------
Downloads the CSIC 2010 HTTP dataset (Spanish National Research Council),
used ONLY to validate the WAF's behavioral rate limiter against independent
normal traffic (scripts/09_csic_rate_limit_validation.py). It plays no part
in the paper's training or evaluation.

The original CSIC host is no longer reliably online, so the raw dumps are
fetched from a GitHub mirror pinned to a fixed commit and SHA-256-verified.

Run:
    python scripts/00b_download_csic2010.py

Writes (gitignored, ~56 MB):
    data/external/csic2010/normalTrafficTraining.txt   (36,000 requests)
    data/external/csic2010/normalTrafficTest.txt       (36,000 requests)
    data/external/csic2010/anomalousTrafficTest.txt    (25,065 requests)
"""

from __future__ import annotations

import hashlib
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.csic2010 import CSIC_DIR

MIRROR_COMMIT = "424c6e1c1951570473d9d6c0227eaaac6fdd6d02"
_BASE = (f"https://raw.githubusercontent.com/msudol/Web-Application-Attack-Datasets/"
         f"{MIRROR_COMMIT}/OriginalDataSets/csic_2010/")

EXPECTED_SHA256 = {
    "normalTrafficTraining.txt": "d51de812d9201ef2b173b6ae3e3e740c309047ac85545c06c51d6fb1ddbc1e63",
    "normalTrafficTest.txt": "f05dfc312d5d14fd1ed8371de27a9e4deab3dc09265f5d7f9df2643df8385089",
    "anomalousTrafficTest.txt": "12fa4f0d496ceb859bb2652abf7f0f0ed8c59e1d9ce501b8a9a0ef38a625c046",
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fetch(url: str, retries: int = 4) -> bytes:
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(url, timeout=60) as resp:
                return resp.read()
        except OSError as e:
            if attempt == retries:
                raise
            wait = 2 ** (attempt + 1)
            print(f"  fetch failed ({e}); retrying in {wait}s")
            time.sleep(wait)
    raise AssertionError("unreachable")


def main() -> int:
    CSIC_DIR.mkdir(parents=True, exist_ok=True)
    for name, expected in EXPECTED_SHA256.items():
        dest = CSIC_DIR / name
        if dest.exists() and _sha256(dest) == expected:
            print(f"[csic2010] {name}: present, checksum OK")
            continue
        print(f"[csic2010] downloading {name} ...")
        data = _fetch(_BASE + name)
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            print(f"[csic2010] ERROR: {name} SHA-256 {actual} != expected {expected}")
            return 1
        dest.write_bytes(data)
        print(f"[csic2010] {name}: {len(data):,} bytes, checksum OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
