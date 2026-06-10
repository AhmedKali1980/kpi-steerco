"""Input helpers for monitored KEAR files."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterable, List


def normalize_uid(value: object) -> str:
    return str(value or "").strip().upper()


def unique_preserving_order(values: Iterable[object]) -> List[str]:
    output: List[str] = []
    seen: set[str] = set()
    for value in values:
        normalized = normalize_uid(value)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        output.append(normalized)
    return output


def detect_csv_delimiter(csv_file: Path, default: str = ",") -> str:
    with csv_file.open("r", encoding="utf-8", newline="") as handle:
        sample = handle.read(4096)
    if not sample.strip():
        return default
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;")
        if dialect.delimiter in {",", ";"}:
            return dialect.delimiter
    except csv.Error:
        pass
    return ";" if sample.count(";") > sample.count(",") else default


def read_monitored_uids(monitored_file: Path) -> List[str]:
    delimiter = detect_csv_delimiter(monitored_file)
    with monitored_file.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, delimiter=delimiter)
        if not reader.fieldnames:
            raise ValueError(f"Missing CSV header in {monitored_file}")

        headers = {str(header or "").strip().lower(): header for header in reader.fieldnames}
        uid_header = headers.get("uid") or headers.get("kear")
        if not uid_header:
            raise ValueError(f"Missing required uid column in {monitored_file}; accepted aliases: uid, kear")

        return unique_preserving_order(row.get(uid_header, "") for row in reader)
