"""
realtime_sniffer.py
--------------------
Real-time HTTP payload classification pipeline (Chapter 3, Section 3.5,
Figure 3.2 -- Modules 1-4 wired together end to end).

Module 1 (Data Acquisition): Scapy sniffs live traffic on a BPF filter
         restricted to TCP port 80 (plaintext HTTP only, per Chapter 1
         scope/limitations -- HTTPS is explicitly out of scope).
Module 2 (Preprocessing):     extract the GET query string / POST body
         from the raw TCP payload bytes and URL-decode it.
Module 3+4 (Feature Extraction + Classification): handled in one call by
         the trained sklearn Pipeline loaded from models/.

Requires root privileges (raw sockets) -- see README.md for how to run
this without full `sudo` using Linux capabilities on Arch.

This tool only ever reads and classifies traffic that is already flowing
on the host you run it on. It does not craft, send, replay, or inject any
packets, and it does not exploit any target -- it is a passive, defensive
monitoring script (the same category of tool as tcpdump/Snort), built for
the benchmarking described in Chapter 3.
"""

from __future__ import annotations

import argparse
import re
import sys
import time
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import psutil
from scapy.all import sniff, TCP, IP, Raw

from src.models import load_model
from src.baseline_signature import SignatureBaseline

# --------------------------------------------------------------------------
# Module 2: Preprocessing -- pull the payload text out of a raw TCP segment
# --------------------------------------------------------------------------

_REQUEST_LINE_RE = re.compile(
    rb"^(GET|POST) +(\S+) +HTTP/1\.[01]", re.MULTILINE
)


def extract_http_payload(tcp_bytes: bytes) -> str | None:
    """
    Given the raw bytes of a TCP segment, return the text this pipeline
    should classify:
      - for GET, the query string portion of the URL (after '?')
      - for POST, the request body (after the blank line \\r\\n\\r\\n)
    Returns None if this segment doesn't look like the start of an HTTP
    GET/POST request (e.g. it's a TCP ACK with no HTTP data, or a response).
    """
    match = _REQUEST_LINE_RE.search(tcp_bytes)
    if not match:
        return None

    method, url = match.group(1), match.group(2)
    url = url.decode("latin-1", errors="replace")

    if method == b"GET":
        if "?" in url:
            query = url.split("?", 1)[1]
            return urllib.parse.unquote(query)
        return None  # GET with no query string -> nothing to classify

    if method == b"POST":
        header_end = tcp_bytes.find(b"\r\n\r\n")
        if header_end == -1:
            return None
        body = tcp_bytes[header_end + 4:]
        if not body:
            return None
        return urllib.parse.unquote(body.decode("latin-1", errors="replace"))

    return None


# --------------------------------------------------------------------------
# Module 1 + 3 + 4: sniff -> preprocess -> classify -> log
# --------------------------------------------------------------------------

class RealtimeClassifier:
    def __init__(self, model_name: str = "logistic_regression"):
        if model_name == "signature_baseline":
            self.model = SignatureBaseline()
        else:
            self.model = load_model(model_name)
        self.model_name = model_name
        self.process = psutil.Process()
        self.packet_count = 0
        self.malicious_count = 0

    def handle_packet(self, pkt) -> None:
        if not (pkt.haslayer(TCP) and pkt.haslayer(Raw)):
            return

        payload_text = extract_http_payload(bytes(pkt[Raw].load))
        if payload_text is None:
            return

        t0 = time.perf_counter()
        label = self.model.predict([payload_text])[0]
        t1 = time.perf_counter()
        latency_ms = (t1 - t0) * 1000.0

        self.packet_count += 1
        src = pkt[IP].src if pkt.haslayer(IP) else "?"
        dst_port = pkt[TCP].dport

        if label != "benign":
            self.malicious_count += 1
            tag = f"\033[91m[{label.upper()}]\033[0m"   # red
        else:
            tag = f"\033[92m[{label}]\033[0m"            # green

        cpu = self.process.cpu_percent(interval=None)
        mem_mb = self.process.memory_info().rss / (1024 * 1024)

        print(
            f"{tag} src={src:>15} dstport={dst_port:<5} "
            f"latency={latency_ms:6.3f}ms cpu={cpu:5.1f}% mem={mem_mb:6.1f}MB "
            f"payload={payload_text[:80]!r}"
        )

    def summary(self) -> None:
        print("\n--- session summary ---")
        print(f"model            : {self.model_name}")
        print(f"packets analyzed : {self.packet_count}")
        print(f"flagged malicious: {self.malicious_count}")


def main():
    parser = argparse.ArgumentParser(description="Real-time HTTP payload classifier (Scapy).")
    parser.add_argument("--iface", default=None, help="Network interface, e.g. eth0 / wlan0 (default: scapy auto-selects)")
    parser.add_argument("--model", default="logistic_regression",
                         choices=["logistic_regression", "naive_bayes", "svm", "signature_baseline"])
    parser.add_argument("--port", type=int, default=80, help="TCP port to filter on (default 80, plaintext HTTP)")
    parser.add_argument("--count", type=int, default=0, help="Stop after N packets (0 = run until Ctrl+C)")
    args = parser.parse_args()

    classifier = RealtimeClassifier(model_name=args.model)
    bpf_filter = f"tcp port {args.port}"

    print(f"[realtime] model={args.model}  iface={args.iface or '(auto)'}  filter='{bpf_filter}'")
    print("[realtime] this requires raw-socket capability -- see README if you get a Permission error.")
    print("[realtime] Ctrl+C to stop.\n")

    try:
        sniff(
            iface=args.iface,
            filter=bpf_filter,
            prn=classifier.handle_packet,
            store=False,
            count=args.count if args.count > 0 else 0,
        )
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("\n[realtime] Permission denied opening a raw socket.")
        print("See README.md 'Running the sniffer without full sudo' for the setcap fix.")
        sys.exit(1)
    finally:
        classifier.summary()


if __name__ == "__main__":
    main()
