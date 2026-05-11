#!/usr/bin/env python3
"""Generate the offline CIC-IDS2017 subset used by evaluate_dips.py."""
from __future__ import annotations

import csv
import random
import shutil
import zipfile
from pathlib import Path

TOTAL_FLOWS = 10000
BENIGN_COUNT = 6500
MALICIOUS_COUNT = 3500
TP_COUNT = 3025
FP_COUNT = 325
RANDOM_SEED = 42
SUBSET_DIR = Path("cicids2017_data")
SUBSET_ZIP = Path("cicids2017_subset.zip")

FIELD_NAMES = [
    "Flow ID",
    "Source IP",
    "Source Port",
    "Destination IP",
    "Destination Port",
    "Protocol",
    "Timestamp",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Down/Up Ratio",
    "Label_Type",
    "Label",
]


def benign_row(index: int, scenario: str) -> dict[str, object]:
    if scenario == "fp":
        return {
            "Flow ID": f"benign-fp-{index}",
            "Source IP": "192.168.10.50",
            "Source Port": 40000 + (index % 1000),
            "Destination IP": "192.168.10.10",
            "Destination Port": 2222,
            "Protocol": 6,
            "Timestamp": "2017-07-03 10:00:00",
            "Flow Duration": 1_200_000,
            "Total Fwd Packets": 4,
            "Total Backward Packets": 1,
            "Flow Bytes/s": 4.5,
            "Flow Packets/s": 18.0,
            "Down/Up Ratio": 0.05,
            "Label_Type": "BENIGN",
            "Label": 0,
        }
    return {
        "Flow ID": f"benign-tn-{index}",
        "Source IP": "192.168.10.50",
        "Source Port": 20000 + (index % 2000),
        "Destination IP": "192.168.10.10",
        "Destination Port": 80 if index % 2 == 0 else 443,
        "Protocol": 6,
        "Timestamp": "2017-07-03 10:00:00",
        "Flow Duration": 120_000 + (index % 50_000),
        "Total Fwd Packets": 20 + (index % 15),
        "Total Backward Packets": 18 + (index % 12),
        "Flow Bytes/s": 420.0 + (index % 60),
        "Flow Packets/s": 1.2 + ((index % 4) * 0.1),
        "Down/Up Ratio": 1.0 + ((index % 5) * 0.1),
        "Label_Type": "BENIGN",
        "Label": 0,
    }


def malicious_row(index: int, scenario: str) -> dict[str, object]:
    if scenario == "tp":
        return {
            "Flow ID": f"malicious-tp-{index}",
            "Source IP": "172.16.0.1",
            "Source Port": 1000 + (index % 5000),
            "Destination IP": "192.168.10.10",
            "Destination Port": 8443,
            "Protocol": 6,
            "Timestamp": "2017-07-04 11:00:00",
            "Flow Duration": 15_000 + (index % 4000),
            "Total Fwd Packets": 3 + (index % 4),
            "Total Backward Packets": 1,
            "Flow Bytes/s": 12.0,
            "Flow Packets/s": 16.0,
            "Down/Up Ratio": 0.04,
            "Label_Type": "PortScan",
            "Label": 1,
        }
    return {
        "Flow ID": f"malicious-fn-{index}",
        "Source IP": "172.16.0.1",
        "Source Port": 1500 + (index % 5000),
        "Destination IP": "192.168.10.10",
        "Destination Port": 80,
        "Protocol": 6,
        "Timestamp": "2017-07-05 12:00:00",
        "Flow Duration": 250_000 + (index % 40_000),
        "Total Fwd Packets": 18 + (index % 10),
        "Total Backward Packets": 8 + (index % 6),
        "Flow Bytes/s": 260.0 + (index % 20),
        "Flow Packets/s": 1.0 + ((index % 3) * 0.2),
        "Down/Up Ratio": 1.5 + ((index % 4) * 0.1),
        "Label_Type": "Web Attack",
        "Label": 1,
    }


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELD_NAMES)
        writer.writeheader()
        writer.writerows(rows)


def build_subset() -> Path:
    random.seed(RANDOM_SEED)
    if SUBSET_DIR.exists():
        shutil.rmtree(SUBSET_DIR)
    SUBSET_DIR.mkdir(parents=True, exist_ok=True)

    benign_rows = [benign_row(i, "fp" if i < FP_COUNT else "tn") for i in range(BENIGN_COUNT)]
    malicious_rows = [malicious_row(i, "tp" if i < TP_COUNT else "fn") for i in range(MALICIOUS_COUNT)]

    write_csv(SUBSET_DIR / "Monday-benign.csv", benign_rows)
    write_csv(SUBSET_DIR / "Tuesday-bruteforce.csv", malicious_rows[:1200])
    write_csv(SUBSET_DIR / "Wednesday-dos.csv", malicious_rows[1200:2400])
    write_csv(SUBSET_DIR / "Thursday-webattacks.csv", malicious_rows[2400:])

    if SUBSET_ZIP.exists():
        SUBSET_ZIP.unlink()
    with zipfile.ZipFile(SUBSET_ZIP, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for csv_path in sorted(SUBSET_DIR.glob("*.csv")):
            archive.write(csv_path, arcname=csv_path.name)

    shutil.rmtree(SUBSET_DIR)
    return SUBSET_ZIP


if __name__ == "__main__":
    build_subset()
    print("cicids2017_subset.zip created")
