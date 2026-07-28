"""
Usage:
    python scripts/01_build_dataset.py [--real-data]

Builds data/processed/{train,test_clean,test_obfuscated}.csv
By default uses the synthetic generator (src/dataset.py). Pass --real-data
once you've placed csic2010.csv / owasp_payloads.csv under data/raw/
(see README.md).
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.dataset import build_dataset, save_partitions

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--real-data", action="store_true",
                         help="Use data/raw/csic2010.csv + owasp_payloads.csv instead of the synthetic generator")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    print(f"[01] Building dataset (use_real_data={args.real_data}) ...")
    partitions = build_dataset(use_real_data=args.real_data, seed=args.seed)

    for name, df in partitions.items():
        print(f"\n=== {name} ({len(df)} rows) ===")
        print(df["label"].value_counts().to_string())

    save_partitions(partitions)
    print("\n[01] Done. See data/processed/*.csv")
