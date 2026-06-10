#!/usr/bin/env python3
"""Create the W01 Kears/Accounts dictionary Excel sheet."""

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

from config import (  # noqa: E402
    DICT_KEARS_ACCOUNTS_HEADERS,
    DICT_KEARS_ACCOUNTS_SHEET,
    INDEX_HEADERS,
    INDEX_ROWS,
    INDEX_SHEET,
)
from dict_kears_accounts import build_dict_kears_accounts_rows  # noqa: E402

log = logging.getLogger("fork.build_dict_kears_accounts")


def setup_logging(log_file: Path, verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)

    log_file.parent.mkdir(parents=True, exist_ok=True)
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(level)
    stream_handler.setFormatter(formatter)
    root.addHandler(stream_handler)


def _set_column_widths(worksheet, headers: List[str], rows: List[Dict[str, str]]) -> None:
    for col_idx, header in enumerate(headers):
        max_width = max([len(str(header))] + [len(str(row.get(header, ""))) for row in rows[:200]])
        worksheet.set_column(col_idx, col_idx, min(max(max_width + 2, 12), 80))


def write_table_sheet(workbook: xlsxwriter.Workbook, sheet_name: str, headers: List[str], rows: List[Dict[str, str]]) -> None:
    worksheet = workbook.add_worksheet(sheet_name)
    header_format = workbook.add_format({"bold": True, "bg_color": "#D9EAF7", "border": 1})
    for col_idx, header in enumerate(headers):
        worksheet.write(0, col_idx, header, header_format)
    for row_idx, row in enumerate(rows, start=1):
        for col_idx, header in enumerate(headers):
            worksheet.write(row_idx, col_idx, row.get(header, ""))
    worksheet.autofilter(0, 0, max(len(rows), 1), max(len(headers) - 1, 0))
    worksheet.freeze_panes(1, 0)
    _set_column_widths(worksheet, headers, rows)


def write_workbook(output_file: Path, w01_rows: List[Dict[str, str]]) -> None:
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with xlsxwriter.Workbook(str(output_file)) as workbook:
        write_table_sheet(workbook, INDEX_SHEET, list(INDEX_HEADERS), list(INDEX_ROWS))
        write_table_sheet(workbook, DICT_KEARS_ACCOUNTS_SHEET, list(DICT_KEARS_ACCOUNTS_HEADERS), w01_rows)
    log.info("STEP 01 - Build W01 Kears/Accounts dictionary | Wrote %s rows to %s", len(w01_rows), output_file)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build the W01 Kears/Accounts dictionary workbook for the fork first increment.")
    parser.add_argument("--monitored-file", default=str(FORK_ROOT / "users_input" / "monitored_kears.csv"))
    parser.add_argument("--output-file", default="")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    monitored_file = Path(args.monitored_file)
    if not monitored_file.is_file():
        raise FileNotFoundError(f"Missing monitored KEAR input file: {monitored_file}")

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    output_file = Path(args.output_file) if args.output_file else FORK_ROOT / "RUNS" / timestamp / f"dict_kears_accounts_{timestamp}.xlsx"
    execution_log = output_file.parent / "execution.log"
    setup_logging(execution_log, args.verbose)

    log.info("START - DictKearsAccounts increment | monitored_file=%s | output_file=%s", monitored_file, output_file)
    log.info("STEP 01 - Build W01 Kears/Accounts dictionary | Reading monitored KEARs and querying data4sec/platform_accounts")
    rows = build_dict_kears_accounts_rows(monitored_file)
    log.info("STEP 01 - Build W01 Kears/Accounts dictionary | Retrieved %s account rows", len(rows))
    write_workbook(output_file, rows)
    log.info("END - DictKearsAccounts increment | execution_log=%s", execution_log)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
