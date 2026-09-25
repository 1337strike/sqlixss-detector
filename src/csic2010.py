"""
csic2010.py
-----------
Parser for the CSIC 2010 HTTP dataset (Spanish National Research Council),
used as an independent source of *normal* web traffic for validating the
WAF's behavioral rate limiter (scripts/09_csic_rate_limit_validation.py).

The dataset ships as three raw HTTP dumps:
  normalTrafficTraining.txt   36,000 normal requests
  normalTrafficTest.txt       36,000 normal requests
  anomalousTrafficTest.txt    25,065 anomalous requests

Each request is a request line, headers, a blank line, then -- for POST
and PUT -- a body of exactly Content-Length bytes. Requests are separated
by one or more blank lines. Bodies are single-line form data, so parsing
line-by-line and honouring Content-Length is sufficient.

This module is not part of the paper's pipeline; it only feeds the WAF.
"""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

CSIC_DIR = Path(__file__).resolve().parent.parent / "data" / "external" / "csic2010"

NORMAL_FILES = ("normalTrafficTraining.txt", "normalTrafficTest.txt")
ANOMALOUS_FILES = ("anomalousTrafficTest.txt",)

_METHODS = ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ")


@dataclass
class CsicRequest:
    method: str
    path_qs: str                                  # origin-form: "/tienda1/x.jsp?a=b"
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""

    def header(self, name: str, default: str = "") -> str:
        lname = name.lower()
        for k, v in self.headers:
            if k.lower() == lname:
                return v
        return default


def _origin_form(target: str) -> str:
    """CSIC request lines use absolute-form ("http://localhost:8080/x");
    a client talking to the WAF sends origin-form ("/x")."""
    parts = urllib.parse.urlsplit(target)
    if not parts.scheme:
        return target
    path = parts.path or "/"
    return f"{path}?{parts.query}" if parts.query else path


def parse_csic_file(path: Path) -> list[CsicRequest]:
    # latin-1 round-trips every byte, so bodies are re-encoded exactly.
    lines = path.read_text(encoding="latin-1").splitlines()
    requests: list[CsicRequest] = []
    i, n = 0, len(lines)
    while i < n:
        line = lines[i]
        if not line.startswith(_METHODS):
            i += 1
            continue
        method, target, _version = line.split(" ", 2)
        req = CsicRequest(method=method, path_qs=_origin_form(target))
        i += 1
        while i < n and lines[i] != "":
            name, _, value = lines[i].partition(":")
            req.headers.append((name.strip(), value.strip()))
            i += 1
        i += 1  # blank line after headers
        length = int(req.header("Content-Length", "0") or 0)
        if length > 0 and i < n:
            body = lines[i].encode("latin-1")
            req.body = body[:length]
            i += 1
        requests.append(req)
    return requests


def load_csic(kind: str = "normal", data_dir: Path = CSIC_DIR) -> list[CsicRequest]:
    files = NORMAL_FILES if kind == "normal" else ANOMALOUS_FILES
    out: list[CsicRequest] = []
    for name in files:
        path = data_dir / name
        if not path.exists():
            raise FileNotFoundError(
                f"{path} not found -- run `python scripts/00b_download_csic2010.py` first"
            )
        out.extend(parse_csic_file(path))
    return out
