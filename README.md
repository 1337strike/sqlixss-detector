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

## 4. Production WAF mode (reverse proxy — blocks traffic, not just logs it)

The Chapter-3 Scapy sniffer (§3 above) is **passive**: it only reads and
logs traffic it can already see. It also fundamentally cannot inspect
HTTPS, because it never has the decryption key — it's just watching
packets fly by on the wire. That's fine for the thesis methodology, but
it's not how a real firewall works today, since almost all web traffic is
TLS-encrypted.

`src/waf_proxy.py` is a proper **inline reverse-proxy WAF**: it sits in
front of your real backend, terminates the connection (including TLS, if
configured — the same architecture Cloudflare/AWS WAF/NGINX+ModSecurity
use), classifies every request, and only forwards it to the backend if
it's clean. Malicious requests get a `403` and never reach your app at
all. It also auto-bans IPs that keep sending malicious requests (like
fail2ban), and writes structured JSON logs of every decision.

```
client --> [ WAF proxy : listen_port ] --> [ your real backend : backend_url ]
                 |
                 classify (ensemble: LR + NB + signature baseline, "any" policy)
                 |
          malicious? --403, log, count offense against source IP
          benign?    --forward to backend, relay its response back
```

### Run it

Terminal 1 — your real backend (or the demo one):
```powershell
python test_target\app.py
```

Terminal 2 — the WAF, listening on port 8443, protecting that backend:
```powershell
python scripts\05_run_waf.py --config config\waf_config.yaml
```

Terminal 3 — send traffic **through the WAF** (not directly to the backend):
```powershell
curl "http://127.0.0.1:8443/search?q=laptop"                          # 200, forwarded
curl "http://127.0.0.1:8443/search?q=%27%20OR%201%3D1%20--"           # 403, blocked
curl "http://127.0.0.1:8443/profile?id=<script>alert(1)</script>"     # 403, blocked
curl -X POST "http://127.0.0.1:8443/login" -d "username=admin'--&password=x"  # 403, blocked
```

Send 5 malicious requests from the same IP in under a minute and the 6th
(even a benign one) gets `429 Too Many Requests` — that IP is auto-banned
for 5 minutes (configurable in `config/waf_config.yaml`).

Check live stats (only answered to `admin_allowed_ips`):
```powershell
curl "http://127.0.0.1:8443/__waf/stats"
curl "http://127.0.0.1:8443/__waf/health"
```

Logs land in `logs/waf.log`, one JSON object per line — ready to ship
into an ELK stack / Splunk / any SIEM.

### Enabling HTTPS

```powershell
python scripts\generate_self_signed_cert.py
```
Then set `tls.enabled: true` in `config/waf_config.yaml` and restart the
WAF. Clients now connect via `https://127.0.0.1:8443/...` (use `curl -k`
to ignore the self-signed cert warning during local testing). For
anything actually exposed to the internet, replace the self-signed cert
with a real one (Let's Encrypt / your org's CA).

### Tuning detection strictness

`config/waf_config.yaml` → `voting_policy`:
- `"any"` (default): block if **any** loaded model/signature flags it —
  most paranoid, fewest false negatives, more false positives.
- `"majority"`: block only if more than half agree — balanced.
- `"all"`: block only if every detector agrees — fewest false positives,
  but an attacker only needs to fool the weakest one detector to slip
  through.

Add/remove entries under `models:` in the config to change which
detectors vote (`logistic_regression`, `naive_bayes`, `svm`,
`signature_baseline`).

### Production deployment (internet-facing)

Everything above is enough for local dev/testing. For anything that will
actually receive real internet traffic, use this topology instead of the
single-process `scripts/05_run_waf.py`:

```
Internet --(HTTPS)--> Caddy --(HTTP, localhost only)--> gunicorn (N WAF workers) --> your backend
                        ^                                      ^
                  auto TLS via                          all workers share state
                  Let's Encrypt                          via Redis (rate limits +
                                                           request counters)
```

**Why this shape, specifically:**
- **Caddy in front, not the WAF's own TLS mode.** Caddy gets and renews a
  real Let's Encrypt certificate automatically and speaks HTTP/2 and
  HTTP/3 — reimplementing that inside the WAF would mean maintaining an
  ACME client for no real benefit. The WAF's `tls.enabled` option still
  exists for standalone/no-Caddy setups.
- **gunicorn with multiple workers, not a single aiohttp process.** One
  process can only use one CPU core and has no supervisor to restart it
  if a worker wedges. `aiohttp.GunicornWebWorker` gives you real
  multi-core concurrency plus gunicorn's process management.
- **Redis for shared state.** With more than one worker, each worker is a
  separate OS process. Without Redis, each one would track rate-limit
  offenses and request counters *independently* — an attacker could
  spread requests across workers and never trip any single worker's
  threshold, and `/__waf/stats` would only show whichever worker happened
  to answer. Set `rate_limit.backend: redis` in the config to fix both at
  once (see below).

**Steps (Arch Linux):**

```bash
# 1. Redis (shared rate-limit + stats state across workers)
sudo pacman -S redis
sudo systemctl enable --now redis

# 2. Caddy (TLS-terminating reverse proxy)
sudo pacman -S caddy
sudo cp deploy/Caddyfile /etc/caddy/Caddyfile
sudo nano /etc/caddy/Caddyfile     # edit your-domain.com to your real domain
sudo systemctl enable --now caddy

# 3. Point config/waf_config.yaml at Redis and trust Caddy's forwarded IP
#    (edit these two sections in config/waf_config.yaml):
#      rate_limit:
#        backend: "redis"
#      trusted_proxies:
#        - "127.0.0.1"     # Caddy runs on the same host

# 4. Install the systemd service for the WAF itself
sudo mkdir -p /opt/sqlixss-detector
sudo cp -r . /opt/sqlixss-detector
sudo useradd --system --no-create-home waf
sudo chown -R waf:waf /opt/sqlixss-detector
cd /opt/sqlixss-detector && python -m venv .venv && .venv/bin/pip install -r requirements.txt
sudo cp deploy/waf.service /etc/systemd/system/waf.service
sudo systemctl daemon-reload
sudo systemctl enable --now waf.service

# 5. Check it's alive
sudo systemctl status waf.service
curl http://127.0.0.1:8443/__waf/health   # from the server itself
curl https://your-domain.com/             # from anywhere -- through Caddy + the WAF
```

`deploy/waf.service` and `deploy/Caddyfile` are both in this repo, fully
commented — read through them before installing, since the paths/domain
inside are examples you need to edit for your actual server.

**Monitoring**: point Prometheus (or Grafana Agent) at
`http://127.0.0.1:8443/__waf/metrics`. Logs are structured JSON at
`logs/waf.log`, rotated automatically at 10 MB (5 backups kept by
default — tune `log_max_bytes`/`log_backup_count` in the config).

### Honest limitations (read before deploying this anywhere real)

- This is a research-grade reverse proxy that has been hardened for real
  deployment, but it has not been through a professional security audit.
  Treat it accordingly for anything high-stakes.
- Doesn't (yet) handle HTTP/2 end-to-end (Caddy-to-WAF hop is HTTP/1.1,
  which is fine — Caddy does HTTP/2 with clients), WebSockets, or exotic
  request-smuggling edge cases at the parser level.
- JSON body inspection classifies the raw body text rather than doing a
  full JSON-aware parse — this still catches SQLi/XSS strings embedded in
  JSON field values (the common case) but a deeply escaped/nested payload
  could theoretically evade it. A JSON-aware extractor is a reasonable
  "future work" item.
- The rate limiter/stats Redis keys have no authentication configured by
  default (`redis://127.0.0.1:6379/0` with no password) — that's fine
  when Redis only listens on localhost (the default, and what
  `deploy/waf.service` assumes), but set a `requirepass` and update
  `redis_url` accordingly if Redis is reachable from anywhere else.
- Treat this the same way you'd treat any single security control: as one
  layer, not the only layer. Keep your backend's own input validation,
  parameterized queries, and output encoding regardless.

---

## 5. Swapping in real data (recommended datasets)

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

## 6. Project structure

```
sqlixss-detector/
├── requirements.txt
├── config/
│   └── waf_config.yaml         # WAF proxy config (backend, TLS, Redis, rate-limit, allow/deny)
├── deploy/
│   ├── waf.service              # systemd unit (gunicorn multi-worker)
│   └── Caddyfile                 # TLS-terminating reverse proxy in front of the WAF
├── data/
│   ├── raw/                    # put real datasets here (§5)
│   └── processed/              # train.csv, test_clean.csv, test_obfuscated.csv
├── models/                     # trained *.joblib pipelines
├── results/                    # metrics.csv, confusion_matrices.txt
├── logs/                       # waf.log (JSON-lines, rotated, generated at runtime)
├── src/
│   ├── tokenizer.py            # custom tokenizer (preserves ' = < > / -- etc.)
│   ├── obfuscation.py          # 5 evasion techniques (Table 3.1)
│   ├── dataset.py              # dataset builder + train/test/obfuscated split
│   ├── features.py             # TF-IDF vectorizer wrapper
│   ├── models.py                # LR / MNB / SVM pipelines
│   ├── baseline_signature.py   # ModSecurity/Snort-style regex baseline
│   ├── evaluate.py             # metrics + latency/CPU/memory benchmarking
│   ├── realtime_sniffer.py     # Scapy live capture -> classify -> log (passive)
│   ├── ensemble.py             # combines all detectors with a voting policy
│   ├── rate_limiter.py         # sliding-window offense counter + auto-ban (memory or Redis)
│   ├── waf_stats.py             # request counters, shared across workers via Redis
│   ├── waf_logging.py          # structured, rotating JSON-lines logging
│   └── waf_proxy.py            # inline reverse-proxy WAF (active blocking, TLS-ready, gunicorn-ready)
├── scripts/
│   ├── 01_build_dataset.py
│   ├── 02_train_models.py
│   ├── 03_evaluate_offline.py
│   ├── 04_run_realtime.py
│   ├── 05_run_waf.py           # entry point for single-process dev/test runs
│   └── generate_self_signed_cert.py
├── test_target/app.py          # local Flask app, generates demo traffic only
└── tests/test_pipeline.py      # smoke test for the whole pipeline
```

## 7. What's already verified to work

Every module above was executed end-to-end while building this repo:
tokenizer, obfuscation engine, dataset builder, all 3 classifiers,
signature baseline, offline evaluation (metrics + confusion matrices +
latency/CPU/memory), the sniffer's packet-parsing logic (tested with
hand-crafted Scapy packets), and the full WAF proxy stack:
- Benign requests forwarded; SQLi/XSS blocked in GET query string, URL
  path, and POST body.
- 429 auto-ban after repeated offenses, admin `/stats`/`/metrics`
  endpoints, HTTPS mode with a self-signed certificate.
- **Redis-backed rate limiting and stats**, verified with two independent
  `RedisRateLimiter`/`RedisStats` instances (simulating separate worker
  processes) correctly sharing ban/counter state.
- **gunicorn multi-worker deployment** (`aiohttp.GunicornWebWorker`, 3
  workers), verified end-to-end: requests load-balanced across workers,
  blocking still works, and `/__waf/stats` shows accurate totals across
  *all* workers rather than just whichever one answered.
- Config validation fails fast with a clear message on missing keys or a
  missing TLS cert file, instead of an obscure crash mid-request.

The only things that genuinely require *your* machine/domain: the live
`sniff()` call in §3 (needs a real network interface + raw-socket
privileges), pointing the WAF at your *actual* application, and the
Caddy/Let's Encrypt step in §4 (needs a real domain name with DNS already
pointed at your server).
