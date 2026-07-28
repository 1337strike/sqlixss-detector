"""
Usage (needs raw-socket privileges -- see README.md):
    sudo python scripts/04_run_realtime.py --iface lo --model logistic_regression
    sudo python scripts/04_run_realtime.py --iface wlan0 --model naive_bayes --port 80

While this is running, generate traffic in another terminal, e.g.:
    curl "http://127.0.0.1:8080/search?q=laptop"
    curl "http://127.0.0.1:8080/search?q=%27%20OR%201%3D1%20--"
    curl "http://127.0.0.1:8080/profile?id=<script>alert(1)</script>"
    curl -X POST http://127.0.0.1:8080/login -d "username=admin'--&password=x"

(see test_target/app.py -- run that first in its own terminal on port 8080)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.realtime_sniffer import main

if __name__ == "__main__":
    main()
