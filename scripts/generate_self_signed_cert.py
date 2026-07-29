"""
Usage:
    python scripts/generate_self_signed_cert.py

Generates a self-signed TLS certificate + key under config/certs/, valid
for 365 days, CN=localhost -- good enough to test the WAF's HTTPS mode on
your own machine. Browsers/curl will complain it's not from a trusted CA
(expected for a self-signed cert); use `curl -k` to ignore that during
local testing.

For anything actually exposed to the internet, replace these with a real
certificate (Let's Encrypt via certbot, or your organization's CA) --
self-signed certs are for local development only.
"""
import subprocess
import sys
from pathlib import Path

CERT_DIR = Path(__file__).resolve().parent.parent / "config" / "certs"

if __name__ == "__main__":
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    cert_path = CERT_DIR / "waf.crt"
    key_path = CERT_DIR / "waf.key"

    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", str(key_path), "-out", str(cert_path),
        "-days", "365", "-nodes",
        "-subj", "/CN=localhost",
    ]

    try:
        subprocess.run(cmd, check=True)
    except FileNotFoundError:
        print("ERROR: 'openssl' command not found.")
        print("  Arch Linux : sudo pacman -S openssl")
        print("  Windows    : install Git for Windows (bundles openssl) or use WSL")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"openssl failed: {e}")
        sys.exit(1)

    print(f"\nCertificate : {cert_path}")
    print(f"Private key : {key_path}")
    print("\nNow set tls.enabled: true in config/waf_config.yaml and re-run scripts/05_run_waf.py")
