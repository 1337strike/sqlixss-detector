"""
Usage:
    python scripts/01_build_dataset.py [--real-data] [--source kaggle|csic]

Builds data/processed/{train,test_clean,test_obfuscated}.csv
By default uses the synthetic generator (src/dataset.py). Pass --real-data
once you've placed the real CSVs under data/raw/ (see README.md):
  --source kaggle (default): data/raw/kaggle_sqli.csv + kaggle_xss.csv
  --source csic             : data/raw/csic2010.csv + owasp_payloads.csv
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.dataset import build_dataset, save_partitions

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--real-data", action="store_true",
                         help="Use real data from data/raw/ instead of the synthetic generator")
    parser.add_argument("--source", choices=["kaggle", "csic"], default="kaggle",
                         help="Which real dataset to load when --real-data is set (default: kaggle)")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    print(f"[01] Building dataset (use_real_data={args.real_data}, source={args.source}) ...")
    partitions = build_dataset(use_real_data=args.real_data, seed=args.seed, source=args.source)

    for name, df in partitions.items():
        print(f"\n=== {name} ({len(df)} rows) ===")
        print(df["label"].value_counts().to_string())

    save_partitions(partitions)
    print("\n[01] Done. See data/processed/*.csv")
