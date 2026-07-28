# SQLi/XSS TF-IDF + Lightweight ML Detector

Reference implementation for the thesis *"Real-Time HTTP Payload
Classification for SQL Injection and XSS Detection Using TF-IDF and
Lightweight Machine Learning."* Implements every module described in
Chapter 3: dataset builder, obfuscation engine, TF-IDF + 3 classifiers,
signature-based baseline, and a real-time Scapy sniffer.

This tool is defensive security research tooling (an IDS/WAF-style
classifier). It only reads and classifies HTTP traffic already flowing on
the machine it runs on — it never crafts, sends, or replays packets, and
the bundled `test_target/app.py` is a harmless echo server, not a real
vulnerable application.

---

## 1. Setup on Arch Linux

```bash
# System packages
sudo pacman -Syu --needed python python-pip base-devel tcpdump

# (tcpdump isn't strictly required by the Python code, but it's handy for
#  double-checking what's actually on the wire while you debug the sniffer)

# Clone / copy this project, then:
cd sqlixss-detector

# Create an isolated virtual environment (recommended — keeps this off
# your system Python, which Arch's pacman also manages)
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Opening the project in VS Code (Code - OSS)

```bash
code .
```

Recommended extensions (VS Code will usually prompt you): **Python** and
**Pylance** (both available on Open VSX / AUR `code-marketplace` if you're
on the pure Code - OSS build rather than proprietary VS Code). After
opening the folder:

1. `Ctrl+Shift+P` → "Python: Select Interpreter" → pick `.venv/bin/python`.
2. Open any `scripts/*.py` file and use the built-in "Run Python File"
   button, or just use the integrated terminal (`` Ctrl+` ``) and run the
   commands below directly — that's actually the more predictable option
   for the real-time sniffer since it needs a real terminal for `sudo`.

---

## 2. Run the full pipeline (offline, no root needed)

```bash
source .venv/bin/activate   # if not already active

# Step 1 — build the dataset (synthetic generator by default, see §4 to
# swap in the real CSIC 2010 / OWASP data later)
python scripts/01_build_dataset.py

# Step 2 — train Logistic Regression, Naive Bayes, and linear SVM
python scripts/02_train_models.py

# Step 3 — evaluate all 3 models + the signature baseline, on both clean
# and obfuscated test payloads
python scripts/03_evaluate_offline.py
```

After Step 3, check:
- `results/metrics.csv` — accuracy/F1 on clean vs obfuscated, latency, CPU/memory (this is your Table 4.x)
- `results/confusion_matrices.txt` — full confusion matrices per detector

Quick sanity check any time with:
```bash
python -m tests.test_pipeline
```

---

## 3. Run the real-time sniffer (needs raw-socket access)

Terminal 1 — start the local traffic-generator app:
```bash
source .venv/bin/activate
python test_target/app.py
# Flask app now listening on http://127.0.0.1:8080
```

Terminal 2 — start the sniffer on the loopback interface:
```bash
source .venv/bin/activate
sudo .venv/bin/python scripts/04_run_realtime.py --iface lo --model logistic_regression
```

Terminal 3 — generate some traffic to watch it classify live:
```bash
curl "http://127.0.0.1:8080/search?q=laptop"
curl "http://127.0.0.1:8080/search?q=%27%20OR%201%3D1%20--"
curl "http://127.0.0.1:8080/profile?id=<script>alert(1)</script>"
curl -X POST http://127.0.0.1:8080/login -d "username=admin'--&password=x"
```

You'll see each request classified in real time in Terminal 2, with a
per-packet latency figure in milliseconds — this is exactly the
measurement described in Section 3.6.

### Running the sniffer without full `sudo`

`sudo`-ing into your venv works but runs as root, which is more than the
sniffer actually needs. On Arch you can instead grant the Python
interpreter just the one capability it needs for raw sockets:

```bash
sudo setcap cap_net_raw+eip $(readlink -f .venv/bin/python3)
python scripts/04_run_realtime.py --iface lo --model logistic_regression   # no sudo
```

Re-run the `setcap` command again any time you recreate the venv (a fresh
interpreter binary loses the capability).

### Sniffing a real interface instead of loopback

```bash
ip link show                 # find your interface name, e.g. wlan0 / enp3s0
sudo .venv/bin/python scripts/04_run_realtime.py --iface wlan0 --model naive_bayes
```

Remember Chapter 1's scope: this only inspects **plaintext HTTP (port
80)**. It will not see anything on HTTPS (443) unless you terminate TLS in
front of it — that's an explicit, documented limitation, not a bug.

---

## 4. Swapping in real data (recommended datasets)

The synthetic generator in `src/dataset.py` exists so the whole pipeline
runs immediately with zero downloads. For your actual thesis results,
replace it with real data. Two options — **Option A is recommended**,
it's newer, larger, and much easier to work with than raw CSIC 2010.

### Option A (recommended): newer Kaggle datasets

These are the datasets actually used in several 2024–2025 published papers
referenced in Chapter 2, and they're already flat CSVs (no ARFF/XML
conversion needed like CSIC 2010):

1. **SQL Injection Dataset** (Syed Saqlain Hussain Shah, 2021, ~33.7k rows)
   https://www.kaggle.com/datasets/syedsaqlainhussain/sql-injection-dataset
   → download, save as `data/raw/kaggle_sqli.csv`
2. **Cross-Site Scripting (XSS) dataset for Deep Learning** (same author,
   2020, ~13.7k rows, sourced from PortSwigger + OWASP Cheat Sheets)
   https://www.kaggle.com/datasets/syedsaqlainhussain/cross-site-scripting-xss-dataset-for-deep-learning
   → download, save as `data/raw/kaggle_xss.csv`

(Kaggle requires a free account to download — click "Download" on each
page, no API key needed for a manual download.)

Then run:
```powershell
python scripts\01_build_dataset.py --real-data --source kaggle
python scripts\02_train_models.py
python scripts\03_evaluate_offline.py
```

The loader (`src/dataset.py: load_kaggle_sqli / load_kaggle_xss`)
auto-detects common column-name variants (`Query`/`Sentence`/`payload` for
the text, `Label`/`label`/`class` for 0/1 or string labels), so it should
work even if your downloaded copy has slightly different headers.

### Option B: classic CSIC 2010 + OWASP payload lists

1. **CSIC 2010**: download from Kaggle (`ispangler/csic-2010-web-application-attacks`)
   or another mirror, convert to CSV with columns `payload,label` (`label`
   ∈ `benign,sqli,xss,other`), save as `data/raw/csic2010.csv`.
2. **OWASP payload lists**: e.g. the `payloadbox/sql-injection-payload-list`
   and `payloadbox/xss-payload-list` GitHub repos. Convert each line to a
   row `payload,label`, save as `data/raw/owasp_payloads.csv`.
3. Run with `--source csic`:
   ```powershell
   python scripts\01_build_dataset.py --real-data --source csic
   python scripts\02_train_models.py
   python scripts\03_evaluate_offline.py
   ```

No other code changes are needed either way — `src/dataset.py` already
merges whichever source you pick with the same `payload,label` schema the
rest of the pipeline expects.

---

## 5. Project structure

```
sqlixss-detector/
├── requirements.txt
├── data/
│   ├── raw/                    # put csic2010.csv / owasp_payloads.csv here (§4)
│   └── processed/              # train.csv, test_clean.csv, test_obfuscated.csv
├── models/                     # trained *.joblib pipelines
├── results/                    # metrics.csv, confusion_matrices.txt
├── src/
│   ├── tokenizer.py            # custom tokenizer (preserves ' = < > / -- etc.)
│   ├── obfuscation.py          # 5 evasion techniques (Table 3.1)
│   ├── dataset.py              # dataset builder + train/test/obfuscated split
│   ├── features.py             # TF-IDF vectorizer wrapper
│   ├── models.py               # LR / MNB / SVM pipelines
│   ├── baseline_signature.py   # ModSecurity/Snort-style regex baseline
│   ├── evaluate.py             # metrics + latency/CPU/memory benchmarking
│   └── realtime_sniffer.py     # Scapy live capture -> classify -> log
├── scripts/
│   ├── 01_build_dataset.py
│   ├── 02_train_models.py
│   ├── 03_evaluate_offline.py
│   └── 04_run_realtime.py
├── test_target/app.py          # local Flask app, generates demo traffic only
└── tests/test_pipeline.py      # smoke test for the whole pipeline
```

## 6. What's already verified to work

Every module above was executed end-to-end while building this repo:
tokenizer, obfuscation engine, dataset builder, all 3 classifiers,
signature baseline, offline evaluation (metrics + confusion matrices +
latency/CPU/memory), and the sniffer's packet-parsing logic (tested with
hand-crafted Scapy packets). The only thing that genuinely requires *your*
machine is the live `sniff()` call itself, since that needs a real network
interface and raw-socket privileges.
