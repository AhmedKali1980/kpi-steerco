#!/usr/bin/env python3
"""KPI fork orchestrator for W01, W02, W03, W04 and W05 workbook increments."""

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
    DALI,
    APPLICATION_DICTIONARY_HEADERS,
    APPLICATION_DICTIONARY_SHEET,
    DALI_EXTRACT_SHEET,
    DICT_KEARS_ACCOUNTS_HEADERS,
    DICT_KEARS_ACCOUNTS_SHEET,
    INVENTORY_EXTRACT_HEADERS,
    INVENTORY_EXTRACT_SHEET,
    INDEX_HEADERS,
    INDEX_ROWS,
    INDEX_SHEET,
    MARLEY_ORIGINAL_HEADERS,
    MARLEY_ORIGINAL_SHEET,
)
from dali_extract import (  # noqa: E402
    DaliExtractClient,
    build_w02_rows,
    read_headers_mapping,
    read_monitored_rows,
    w02_fieldnames,
    write_json_gz,
)
from dali_application_dictionary import build_w05_rows  # noqa: E402
from dict_kears_accounts import (  # noqa: E402
    append_not_business_accounts_from_w03,
    build_dict_kears_accounts_rows,
    enrich_w01_rows_with_dali_application_attributes,
)
from inventory_extract import build_w03_rows  # noqa: E402
from kear_appli import enrich_w05_rows_with_kear_appli  # noqa: E402
from marley_extract import build_w04_rows  # noqa: E402
from w02_inventory_enrichment import (  # noqa: E402
    W02_INVENTORY_ENRICHMENT_HEADERS,
    enrich_w02_rows_with_inventory,
    w02_headers_with_inventory_enrichment,
)

log = logging.getLogger("fork.kpi_orchestrator")


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
        worksheet.set_column(col_idx, col_idx, min(max(max_width + 2, 12), 100))


def write_table_sheet(
    workbook: xlsxwriter.Workbook,
    sheet_name: str,
    headers: List[str],
    rows: List[Dict[str, str]],
    highlighted_headers: List[str] | None = None,
) -> None:
    worksheet = workbook.add_worksheet(sheet_name)
    header_format = workbook.add_format({"bold": True, "bg_color": "#D9EAF7", "border": 1})
    highlighted_header_format = workbook.add_format({"bold": True, "bg_color": "#E2F0D9", "border": 1})
    highlighted_cell_format = workbook.add_format({"bg_color": "#F4FAF0"})
    highlighted = set(highlighted_headers or [])
    for col_idx, header in enumerate(headers):
        worksheet.write(0, col_idx, header, highlighted_header_format if header in highlighted else header_format)
    for row_idx, row in enumerate(rows, start=1):
        for col_idx, header in enumerate(headers):
            cell_format = highlighted_cell_format if header in highlighted else None
            worksheet.write(row_idx, col_idx, row.get(header, ""), cell_format)
    worksheet.autofilter(0, 0, max(len(rows), 1), max(len(headers) - 1, 0))
    worksheet.freeze_panes(1, 0)
    _set_column_widths(worksheet, headers, rows)


def write_workbook(
    output_file: Path,
    w01_rows: List[Dict[str, str]],
    w02_rows: List[Dict[str, str]],
    w02_headers: List[str],
    w03_rows: List[Dict[str, str]],
    w04_rows: List[Dict[str, str]],
    w05_rows: List[Dict[str, str]],
) -> None:
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with xlsxwriter.Workbook(str(output_file)) as workbook:
        write_table_sheet(workbook, INDEX_SHEET, list(INDEX_HEADERS), list(INDEX_ROWS))
        write_table_sheet(workbook, DICT_KEARS_ACCOUNTS_SHEET, list(DICT_KEARS_ACCOUNTS_HEADERS), w01_rows)
        write_table_sheet(
            workbook,
            DALI_EXTRACT_SHEET,
            w02_headers,
            w02_rows,
            highlighted_headers=list(W02_INVENTORY_ENRICHMENT_HEADERS),
        )
        write_table_sheet(workbook, INVENTORY_EXTRACT_SHEET, list(INVENTORY_EXTRACT_HEADERS), w03_rows)
        write_table_sheet(workbook, MARLEY_ORIGINAL_SHEET, list(MARLEY_ORIGINAL_HEADERS), w04_rows)
        write_table_sheet(workbook, APPLICATION_DICTIONARY_SHEET, list(APPLICATION_DICTIONARY_HEADERS), w05_rows)
    log.info(
        "WRITE - KPI workbook | output_file=%s | W01 rows=%s | W02 rows=%s | W03 rows=%s | W04 rows=%s | W05 rows=%s",
        output_file,
        len(w01_rows),
        len(w02_rows),
        len(w03_rows),
        len(w04_rows),
        len(w05_rows),
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run KPI fork increments W01, W02, W03 and W04 into one workbook.")
    parser.add_argument("--monitored-file", default=str(FORK_ROOT / "users_input" / "monitored_kears.csv"))
    parser.add_argument("--headers-file", default=str(FORK_ROOT / "users_input" / "headers.csv"))
    parser.add_argument("--output-file", default="")
    parser.add_argument("--json-out", default="")
    parser.add_argument("--impact-endpoint", default="")
    parser.add_argument("--search-endpoint", default="")
    parser.add_argument("--depth-until", type=int, default=None)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--sleep-ms", type=int, default=0)
    parser.add_argument(
        "--dry-run-dali",
        action="store_true",
        help="Generate W02 without calling DALI; W01 and W03 still query Data4Sec.",
    )
    parser.add_argument(
        "--dry-run-inventory",
        action="store_true",
        help="Generate W03 structure from W01 accounts without querying Data4Sec/inventory.",
    )
    parser.add_argument(
        "--dry-run-marley",
        action="store_true",
        help="Generate W04 structure without querying Data4Sec/marley_original.",
    )
    parser.add_argument(
        "--dry-run-kear-appli",
        action="store_true",
        help="Generate W05 KEAR_APPLI columns without querying Data4Sec/kear_appli.",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    if args.sleep_ms < 0:
        raise ValueError("--sleep-ms must be >= 0")
    return args


def main() -> int:
    args = parse_args()
    monitored_file = Path(args.monitored_file)
    headers_file = Path(args.headers_file)
    if not monitored_file.is_file():
        raise FileNotFoundError(f"Missing monitored KEAR input file: {monitored_file}")
    if not headers_file.is_file():
        raise FileNotFoundError(f"Missing DALI headers mapping file: {headers_file}")

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    output_file = Path(args.output_file) if args.output_file else FORK_ROOT / "RUNS" / timestamp / f"kpi_steerco_{timestamp}.xlsx"
    execution_log = output_file.parent / "execution.log"
    json_out = Path(args.json_out) if args.json_out else output_file.parent / "dali_extract.json"
    setup_logging(execution_log, args.verbose)

    log.info("START - KPI fork orchestration | monitored_file=%s | headers_file=%s | output_file=%s", monitored_file, headers_file, output_file)

    log.info("STEP 01 - Build W01 Kears/Accounts dictionary | Reading monitored KEARs and querying data4sec/platform_accounts")
    w01_rows = build_dict_kears_accounts_rows(monitored_file)
    log.info("STEP 01 - Build W01 Kears/Accounts dictionary | Retrieved rows=%s", len(w01_rows))

    log.info("STEP 02 - DALI extract W02 | Reading monitored UIDs and DALI header mappings")
    monitored_rows = read_monitored_rows(monitored_file)
    mappings = read_headers_mapping(headers_file)
    log.info("STEP 02 - DALI extract W02 | monitored_uids=%s | mappings=%s", len(monitored_rows), len(mappings))
    dali_client = DaliExtractClient()
    w02_rows, dali_payload = build_w02_rows(
        client=dali_client,
        monitored_rows=monitored_rows,
        mappings=mappings,
        impact_endpoint=args.impact_endpoint or DALI["IMPACT_ENDPOINT"],
        limit=args.limit,
        depth_until=args.depth_until,
        sleep_ms=args.sleep_ms,
        dry_run=args.dry_run_dali,
    )
    log.info("STEP 05 - DALI application dictionary W05 | Querying DALI search by monitored uid values")
    w05_rows, w05_payload = build_w05_rows(
        client=dali_client,
        monitored_rows=monitored_rows,
        search_endpoint=args.search_endpoint or DALI["SEARCH_ENDPOINT"],
        sleep_ms=args.sleep_ms,
        dry_run=args.dry_run_dali,
    )
    kear_appli_payload = enrich_w05_rows_with_kear_appli(
        w05_rows=w05_rows,
        dry_run=args.dry_run_kear_appli,
    )
    w05_payload["kear_appli"] = kear_appli_payload
    dali_payload["application_dictionary"] = w05_payload
    write_json_gz(json_out, dali_payload)
    log.info("STEP 02/05 - DALI traces | JSON trace written to %s", json_out if str(json_out).endswith(".gz") else str(json_out) + ".gz")

    log.info("STEP 03 - Inventory extract W03 | Querying data4sec/inventory by W01 account_name values and appending missing Gen 2 not-business assets")
    w03_rows = build_w03_rows(w01_rows=w01_rows, w02_rows=w02_rows, dry_run=args.dry_run_inventory)
    log.info("STEP 03 - Inventory extract W03 | Retrieved rows=%s", len(w03_rows))

    log.info("STEP 01B - W01 not-business account enrichment | Querying data4sec/platform_accounts from W03 beneficiary values and owner_app_name values absent from beneficiary")
    w01_not_business_appended = append_not_business_accounts_from_w03(
        w01_rows=w01_rows,
        w03_rows=w03_rows,
        dry_run=args.dry_run_inventory,
    )
    log.info("STEP 01B - W01 not-business account enrichment | Appended rows=%s | W01 total rows=%s", w01_not_business_appended, len(w01_rows))

    log.info("STEP 01C - W01 DALI application attributes enrichment | Querying DALI search from distinct W01 KEAR_SG_UID values")
    w01_dali_updated, w01_dali_payload = enrich_w01_rows_with_dali_application_attributes(
        w01_rows=w01_rows,
        client=dali_client,
        search_endpoint=args.search_endpoint or DALI["SEARCH_ENDPOINT"],
        sleep_ms=args.sleep_ms,
        dry_run=args.dry_run_dali,
    )
    dali_payload["w01_application_attributes"] = w01_dali_payload
    write_json_gz(json_out, dali_payload)
    log.info("STEP 01C - W01 DALI application attributes enrichment | Updated rows=%s | W01 total rows=%s", w01_dali_updated, len(w01_rows))

    log.info("STEP 02B - W02 inventory enrichment | Filling W02 inventory columns from completed W01 dictionary and W03 hostid matches")
    w02_rows, w02_inventory_summary = enrich_w02_rows_with_inventory(w02_rows=w02_rows, w03_rows=w03_rows, w01_rows=w01_rows)
    log.info("STEP 02B - W02 inventory enrichment | Summary=%s", w02_inventory_summary)

    log.info("STEP 04 - Marley original extract W04 | Querying data4sec/marley_original by monitored uid values")
    w04_rows = build_w04_rows(
        monitored_file=monitored_file,
        dry_run=args.dry_run_marley,
        w02_rows=w02_rows,
        w03_rows=w03_rows,
    )
    log.info("STEP 04 - Marley original extract W04 | Retrieved rows=%s", len(w04_rows))

    headers = w02_headers_with_inventory_enrichment(w02_fieldnames(mappings))
    write_workbook(
        output_file=output_file,
        w01_rows=w01_rows,
        w02_rows=w02_rows,
        w02_headers=headers,
        w03_rows=w03_rows,
        w04_rows=w04_rows,
        w05_rows=w05_rows,
    )

    log.info("END - KPI fork orchestration | workbook=%s | execution_log=%s", output_file, execution_log)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
