"""The reproduction gate must reject missing or malformed statistics."""
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_reference_run.py"
spec = importlib.util.spec_from_file_location("reference_verifier", SCRIPT)
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
export_spec = importlib.util.spec_from_file_location("statistics_exporter", ROOT / "scripts" / "export_statistics.py")
exporter = importlib.util.module_from_spec(export_spec)
export_spec.loader.exec_module(exporter)
SECTIONS = ["comparisons", "pairwise_canonicalized_ml"]


@pytest.fixture
def stats():
    # The historical archive predates the full export schema. Generate a
    # current-format result from its unchanged fold scores, as a fresh run does.
    return exporter.export(verifier.REFERENCE)


def check(tmp_path, stats):
    (tmp_path / "full_statistics.json").write_text(json.dumps(stats))
    return verifier.verify_statistics(tmp_path)


def test_reference_and_reordered_rows_pass(tmp_path, stats):
    assert check(tmp_path, stats) == []
    for section in SECTIONS:
        stats[section].reverse()
    assert check(tmp_path, stats) == []


@pytest.mark.parametrize("section", SECTIONS)
@pytest.mark.parametrize("fault", ["empty", "missing_row", "duplicate", "unknown", "missing_section", "not_list"])
def test_incomplete_labels_rejected(tmp_path, stats, section, fault):
    if fault == "empty":
        stats[section] = []
    elif fault == "missing_row":
        stats[section].pop()
    elif fault == "duplicate":
        stats[section][-1] = stats[section][0]
    elif fault == "unknown":
        stats[section][0]["label"] = "unknown"
    elif fault == "missing_section":
        del stats[section]
    else:
        stats[section] = None
    assert check(tmp_path, stats)


@pytest.mark.parametrize("section", SECTIONS)
@pytest.mark.parametrize("value", [None, float("nan"), float("inf"), "0.1", True])
def test_invalid_numbers_rejected(tmp_path, stats, section, value):
    stats[section][0]["mean_diff"] = value
    assert check(tmp_path, stats)


@pytest.mark.parametrize("section,ci", [("comparisons", "ci95_gain"), ("pairwise_canonicalized_ml", "ci95_diff")])
def test_missing_interval_rejected(tmp_path, stats, section, ci):
    del stats[section][0][ci]
    assert check(tmp_path, stats)


def test_invalid_json_rejected(tmp_path):
    (tmp_path / "full_statistics.json").write_text("{")
    assert verifier.verify_statistics(tmp_path)


def test_empty_statistics_fail_cli(tmp_path, stats):
    for name in ("fold_scores.json", "single_split.json", "per_technique.csv"):
        shutil.copyfile(verifier.REFERENCE / name, tmp_path / name)
    for section in SECTIONS:
        stats[section] = []
    (tmp_path / "full_statistics.json").write_text(json.dumps(stats))
    result = subprocess.run([sys.executable, str(SCRIPT), str(tmp_path)], capture_output=True, text=True)
    assert result.returncode == 1
    assert "[verify] FAIL" in result.stdout
    assert "reproduces the reference run exactly" not in result.stdout
