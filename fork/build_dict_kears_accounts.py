#!/usr/bin/env python3
"""Create the DictKearsAccounts Excel sheet for the fork first increment."""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path
from typing import Dict, List

import xlsxwriter

FORK_ROOT = Path(__file__).resolve().parent
MODULES_DIR = FORK_ROOT / "modules"
if str(MODULES_DIR) not in sys.path:
    sys.path.insert(0, str(MODULES_DIR))

from config import DICT_KEARS_ACCOUNTS_HEADERS, DICT_KEARS_ACCOUNTS_SHEET  # noqa: E402
from dict_kears_accounts import build_dict_kears_accounts_rows  # noqa: E402

log = logging.getLogger("fork.build_dict_kears_accounts")


def build_headers(rows: List[Dict[str, str]]) -> List[str]:
    headers = list(DICT_KEARS_ACCOUNTS_HEADERS)
    seen = set(headers)
    for row in rows:
        for key in row:
            if key not in seen:
                seen.add(key)
                headers.append(key)
    return headers


def write_dict_kears_accounts_sheet(output_file: Path, rows: List[Dict[str, str]]) -> None:
    headers = build_headers(rows)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with xlsxwriter.Workbook(str(output_file)) as workbook:
        worksheet = workbook.add_worksheet(DICT_KEARS_ACCOUNTS_SHEET)
        header_format = workbook.add_format({"bold": True, "bg_color": "#D9EAF7", "border": 1})
        for col_idx, header in enumerate(headers):
            worksheet.write(0, col_idx, header, header_format)
        for row_idx, row in enumerate(rows, start=1):
            for col_idx, header in enumerate(headers):
                worksheet.write(row_idx, col_idx, row.get(header, ""))
        worksheet.autofilter(0, 0, max(len(rows), 1), max(len(headers) - 1, 0))
        worksheet.freeze_panes(1, 0)
        for col_idx, header in enumerate(headers):
            max_width = max([len(str(header))] + [len(str(row.get(header, ""))) for row in rows[:200]])
            worksheet.set_column(col_idx, col_idx, min(max(max_width + 2, 12), 60))
    log.info("Wrote %s rows to %s", len(rows), output_file)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build the DictKearsAccounts workbook for the fork first increment.")
    parser.add_argument("--monitored-file", default=str(FORK_ROOT / "users_input" / "monitored_kears.csv"))
    parser.add_argument("--output-file", default="")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
    monitored_file = Path(args.monitored_file)
    if not monitored_file.is_file():
        raise FileNotFoundError(f"Missing monitored KEAR input file: {monitored_file}")

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    output_file = Path(args.output_file) if args.output_file else FORK_ROOT / "RUNS" / timestamp / f"dict_kears_accounts_{timestamp}.xlsx"
    rows = build_dict_kears_accounts_rows(monitored_file)
    write_dict_kears_accounts_sheet(output_file, rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
