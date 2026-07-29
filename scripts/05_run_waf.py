"""
Usage:
    python scripts/05_run_waf.py [--config config/waf_config.yaml]

Starts the inline reverse-proxy WAF. Traffic flow:

    client --> WAF (this process, config['listen_port']) --> backend (config['backend_url'])

Make sure your real backend (or test_target/app.py for a demo) is already
running at the address in `backend_url` before starting this.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.waf_proxy import main

if __name__ == "__main__":
    main()
