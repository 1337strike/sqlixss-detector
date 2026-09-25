"""
00c_download_httpparams.py
--------------------------
Downloads HttpParamsDataset (Morzeux/HttpParamsDataset, MIT licence), a public
labelled benchmark of HTTP parameter values. It is used ONLY by
scripts/supplementary_httpparams.py to measure the paper's detectors on
SQLi/XSS payloads from a source independent of the training corpus
(InfoSecWarrior/Offensive-Payloads): its SQLi samples were generated with
sqlmap, its XSS samples with XSSYA and FuzzDB. It plays no part in the paper's
training or evaluation.

Pinned to a fixed commit and SHA-256-verified.

Run:
    python scripts/00c_download_httpparams.py

Writes (gitignored, ~2 MB):
    data/external/httpparams/payload_full.csv   (31,067 rows; = payload_train.csv + payload_test.csv)
"""

from __future__ import annotations

import hashlib
import sys
import time
import urllib.request
from pathlib import Path

HTTPPARAMS_DIR = Path(__file__).resolve().parent.parent / "data" / "external" / "httpparams"

UPSTREAM_REPO = "Morzeux/HttpParamsDataset"
UPSTREAM_COMMIT = "926670a710283f87c05b554680facf3f9530548c"
_BASE = f"https://raw.githubusercontent.com/{UPSTREAM_REPO}/{UPSTREAM_COMMIT}/"

EXPECTED_SHA256 = {
    "payload_full.csv": "a4e62ba13435ad3dd583c5790db2175629020fc41c56e1b26baa02a9ae45f03d",
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
    HTTPPARAMS_DIR.mkdir(parents=True, exist_ok=True)
    for name, expected in EXPECTED_SHA256.items():
        dest = HTTPPARAMS_DIR / name
        if dest.exists() and _sha256(dest) == expected:
            print(f"[httpparams] {name}: present, checksum OK")
            continue
        print(f"[httpparams] downloading {name} ...")
        data = _fetch(_BASE + name)
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            print(f"[httpparams] ERROR: {name} SHA-256 {actual} != expected {expected}")
            return 1
        dest.write_bytes(data)
        print(f"[httpparams] {name}: {len(data):,} bytes, checksum OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
