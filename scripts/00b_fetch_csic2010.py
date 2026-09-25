"""
00b_fetch_csic2010.py
----------------------
Downloads the CSIC 2010 HTTP dataset's normal test traffic
(normalTrafficTest.txt, 36,000 benign requests) for the supplementary
false-positive evaluation (scripts/supplementary_csic.py).

The original host (isi.csic.es) is no longer reliably reachable, so the file
is fetched from a GitHub mirror pinned to a fixed commit and verified by
SHA-256. The mirror's README documents the file as the unmodified original:
    https://github.com/msudol/Web-Application-Attack-Datasets
    OriginalDataSets/csic_2010/normalTrafficTest.txt

The dataset is third-party data and is NOT committed: it lands in
data/external/ (gitignored).

Run:
    python scripts/00b_fetch_csic2010.py

Writes:
    data/external/csic2010/normalTrafficTest.txt
    data/external/csic2010/provenance.json
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
import urllib.request
from pathlib import Path

OUT_DIR = Path(__file__).resolve().parent.parent / "data" / "external" / "csic2010"

MIRROR_REPO = "msudol/Web-Application-Attack-Datasets"
MIRROR_COMMIT = "424c6e1c1951570473d9d6c0227eaaac6fdd6d02"
_BASE = f"https://raw.githubusercontent.com/{MIRROR_REPO}/{MIRROR_COMMIT}/"

FILES = {
    "normalTrafficTest.txt": {
        "path": "OriginalDataSets/csic_2010/normalTrafficTest.txt",
        "sha256": "f05dfc312d5d14fd1ed8371de27a9e4deab3dc09265f5d7f9df2643df8385089",
        "bytes": 20151204,
    },
}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(url: str, dest: Path) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "sqlixss-detector/research-script"})
    tmp = dest.with_suffix(dest.suffix + ".part")
    with urllib.request.urlopen(req, timeout=120) as resp, open(tmp, "wb") as out:
        while chunk := resp.read(1 << 20):
            out.write(chunk)
    tmp.replace(dest)


if __name__ == "__main__":
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    print(f"[00b] CSIC 2010 from {MIRROR_REPO} @ {MIRROR_COMMIT[:8]}\n")

    provenance, bad = {}, []
    for name, meta in FILES.items():
        dest = OUT_DIR / name
        url = _BASE + meta["path"]
        if dest.exists() and sha256(dest) == meta["sha256"]:
            print(f"  OK    {name:24} already present, sha256 verified")
        else:
            try:
                fetch(url, dest)
            except Exception as e:
                bad.append(name)
                print(f"  FAIL  {name:24} {type(e).__name__}: {e}")
                continue
            digest = sha256(dest)
            if digest != meta["sha256"]:
                bad.append(name)
                dest.unlink()
                print(f"  FAIL  {name:24} sha256 {digest[:16]}… != pinned {meta['sha256'][:16]}…")
                continue
            print(f"  OK    {name:24} {dest.stat().st_size:>10} bytes, sha256 verified")
        provenance[name] = {
            "url": url,
            "mirror_repo": MIRROR_REPO,
            "mirror_commit": MIRROR_COMMIT,
            "sha256": meta["sha256"],
            "bytes": meta["bytes"],
            "downloaded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

    if bad:
        print(f"\n[00b] {len(bad)} file(s) failed; nothing usable was kept for them.")
        sys.exit(1)

    (OUT_DIR / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    print(f"\n[00b] Done -> {OUT_DIR}")
    print("[00b] Next: python scripts/supplementary_csic.py")
