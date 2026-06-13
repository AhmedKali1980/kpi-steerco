"""Build rows for the W03 inventory extract sheet.

W03 is the fork equivalent of the parent project's hidden ``get_inv_by_account``
worksheet. It queries Data4Sec ``inventory`` by beneficiary account, using the
``account_name`` values produced in W01.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List

import xlsxwriter

MODULES_DIR = Path(__file__).resolve().parent
if str(MODULES_DIR) not in sys.path:
    sys.path.insert(0, str(MODULES_DIR))

from config import INVENTORY, INVENTORY_EXTRACT_HEADERS, INVENTORY_EXTRACT_SHEET  # noqa: E402
from data4sec_client import Data4SecClient  # noqa: E402

log = logging.getLogger(__name__)


def normalize_lookup_value(value: Any) -> str:
    """Normalize account lookup keys the same way as the parent inventory flow."""
    return str(value or "").strip().upper()


def normalize_cell_value(value: Any) -> str:
    """Normalize Excel cell values without uppercasing display fields."""
    return str(value or "").strip()


def normalize_status(value: Any) -> str:
    raw = normalize_cell_value(value)
    return raw or "<UNKNOWN STATUS>"


def short_hostname(value: Any) -> str:
    raw = normalize_cell_value(value)
    if not raw:
        return ""
    return raw.split(".", 1)[0].strip()


def normalize_uuid_from_hostid(value: Any) -> str:
    """Extract the trailing UUID from inventory hostid values.

    Parent examples are usually SRN-like values where the server identifier is
    after the last ``:`` token. Keeping this helper permissive makes it safe for
    already-normalized hostids too.
    """
    raw = normalize_cell_value(value)
    if not raw:
        return ""
    uuid = raw.rsplit(":", 1)[-1].strip()
    if uuid.upper().startswith("VM_"):
        uuid = uuid[3:]
    return uuid.lower()


def normalize_uuid_from_srn(value: Any) -> str:
    raw = normalize_cell_value(value)
    if not raw:
        return ""
    marker = ":server:"
    lowered = raw.lower()
    if marker in lowered:
        start = lowered.rfind(marker) + len(marker)
        return raw[start:].split(":", 1)[0].strip().upper()
    return raw.rsplit(":", 1)[-1].strip().upper()


def deduplicate_docs(docs: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    unique_docs: List[Dict[str, Any]] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for doc in docs:
        fingerprint = (
            normalize_lookup_value(doc.get("beneficiary")),
            normalize_lookup_value(doc.get("hostid")),
            normalize_lookup_value(doc.get("srn")),
            normalize_lookup_value(doc.get("ocs_name")),
            normalize_lookup_value(doc.get("hostname")),
        )
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        unique_docs.append(doc)
    return unique_docs


def w03_account_names(w01_rows: Iterable[Dict[str, Any]]) -> List[str]:
    """Return distinct W01 account_name values in stable input order."""
    accounts: List[str] = []
    seen: set[str] = set()
    for row in w01_rows:
        account_name = normalize_cell_value(row.get("account_name"))
        normalized = normalize_lookup_value(account_name)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        accounts.append(account_name)
    return accounts


def build_inventory_beneficiary_query_values(account_names: Iterable[str]) -> List[str]:
    """Return distinct normalized beneficiary values used for the inventory query."""
    values: List[str] = []
    seen: set[str] = set()
    for account_name in account_names:
        normalized = normalize_lookup_value(account_name)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        values.append(normalized)
    return values


def query_inventory_by_beneficiaries(
    client: Data4SecClient,
    beneficiaries: List[str],
) -> Dict[str, List[Dict[str, Any]]]:
    """Fetch Data4Sec inventory documents by beneficiary account.

    This is the clean fork implementation of the parent ``get_inv_by_account``
    query: index ``inventory``, field ``beneficiary``, configured source fields,
    and the same active/unknown status filter.
    """
    lookup_values = build_inventory_beneficiary_query_values(beneficiaries)
    if not lookup_values:
        log.info("W03 inventory extract skipped: no beneficiary account from W01")
        return {}

    log.info(
        "W03 inventory extract query start index=%s beneficiary_field=%s beneficiaries=%s",
        INVENTORY["INDEX"],
        INVENTORY["BENEFICIARY_SEARCH_FIELD"],
        len(lookup_values),
    )
    result_map = client.bulk_search_multi(
        index_name=INVENTORY["INDEX"],
        search_field=INVENTORY["BENEFICIARY_SEARCH_FIELD"],
        values=lookup_values,
        source_fields=INVENTORY["SOURCE_FIELDS"],
        scroll_timeout=INVENTORY["SCROLL_TIMEOUT"],
        size=INVENTORY["BATCH_SIZE"],
        term_filters=INVENTORY["TERM_FILTERS"],
    )

    output: Dict[str, List[Dict[str, Any]]] = {}
    for beneficiary, docs in result_map.items():
        normalized_beneficiary = normalize_lookup_value(beneficiary)
        if not normalized_beneficiary or not docs:
            continue
        output[normalized_beneficiary] = deduplicate_docs(docs)

    log.info(
        "W03 inventory extract query done matched_beneficiaries=%s total_docs=%s",
        len(output),
        sum(len(docs) for docs in output.values()),
    )
    return output


def normalize_dali_server_uid(value: Any) -> str:
    return normalize_uuid_from_hostid(value)


W02_SERVER_UID_COLUMN = "DALI [CI] SERVER UID"


def dali_export_server_uids(w02_rows: Iterable[Dict[str, Any]]) -> set[str]:
    """Collect normalized W02 DALI server UIDs used by lookup_in_raw."""
    server_uids: set[str] = set()
    for row in w02_rows:
        normalized = normalize_dali_server_uid(row.get(W02_SERVER_UID_COLUMN))
        if normalized:
            server_uids.add(normalized)
    return server_uids


def inventory_doc_to_w03_row(input_account: str, doc: Dict[str, Any], dali_server_uids: set[str]) -> Dict[str, str]:
    hostid = normalize_cell_value(doc.get("hostid"))
    srn = normalize_cell_value(doc.get("srn"))
    normalized_hostid_uuid = normalize_uuid_from_hostid(hostid)
    already_exists = (
        "ALREADY IN DALI RAW"
        if normalized_hostid_uuid and normalized_hostid_uuid in dali_server_uids
        else "NEW ASSET"
    )
    return {
        "input_INV_Beneficiary_Account": normalize_lookup_value(input_account),
        "beneficiary": normalize_lookup_value(doc.get("beneficiary")),
        "owner_app_name": normalize_cell_value(doc.get("owner_app_name")),
        "ocs_name": normalize_cell_value(doc.get("ocs_name")),
        "hostname": short_hostname(doc.get("hostname")),
        "status": normalize_status(doc.get("status")),
        "region": normalize_cell_value(doc.get("region")),
        "hostid": hostid,
        "Normalized_uuid_from_hostid": normalized_hostid_uuid,
        "lookup_in_raw": already_exists,
        "srn": srn,
        "Normalized_uuid_from_srn": normalize_uuid_from_srn(srn),
        "ip": normalize_cell_value(doc.get("ip")),
        "service_name": normalize_cell_value(doc.get("service_name")),
        "Asset linked to": "Business Account",
    }


def build_w03_rows(
    w01_rows: List[Dict[str, Any]],
    w02_rows: Iterable[Dict[str, Any]] | None = None,
    client: Data4SecClient | None = None,
    dry_run: bool = False,
) -> List[Dict[str, str]]:
    account_names = w03_account_names(w01_rows)
    if not account_names:
        return []

    if dry_run:
        log.info("W03 inventory extract dry-run enabled: beneficiaries=%s", len(account_names))
        rows: List[Dict[str, str]] = []
        for account_name in account_names:
            row = {header: "" for header in INVENTORY_EXTRACT_HEADERS}
            row.update(
                {
                    "input_INV_Beneficiary_Account": normalize_lookup_value(account_name),
                    "beneficiary": normalize_lookup_value(account_name),
                    "status": "DRY_RUN",
                    "lookup_in_raw": "NEW ASSET",
                    "Asset linked to": "Business Account",
                }
            )
            rows.append(row)
        return rows

    client = client or Data4SecClient()
    inventory_by_beneficiary = query_inventory_by_beneficiaries(client=client, beneficiaries=account_names)
    existing_dali_server_uids = dali_export_server_uids(w02_rows or [])
    log.info("W03 inventory extract DALI existence lookup prepared server_uids=%s", len(existing_dali_server_uids))

    rows: List[Dict[str, str]] = []
    for account_name in account_names:
        normalized_account = normalize_lookup_value(account_name)
        for doc in inventory_by_beneficiary.get(normalized_account, []):
            rows.append(
                inventory_doc_to_w03_row(
                    input_account=normalized_account,
                    doc=doc,
                    dali_server_uids=existing_dali_server_uids,
                )
            )
    return rows


def write_w03_workbook(output_file: Path, rows: List[Dict[str, str]]) -> None:
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with xlsxwriter.Workbook(str(output_file)) as workbook:
        worksheet = workbook.add_worksheet(INVENTORY_EXTRACT_SHEET)
        header_format = workbook.add_format({"bold": True, "bg_color": "#D9EAF7", "border": 1})
        for col_idx, header in enumerate(INVENTORY_EXTRACT_HEADERS):
            worksheet.write(0, col_idx, header, header_format)
        for row_idx, row in enumerate(rows, start=1):
            for col_idx, header in enumerate(INVENTORY_EXTRACT_HEADERS):
                worksheet.write(row_idx, col_idx, row.get(header, ""))
        worksheet.autofilter(0, 0, max(len(rows), 1), len(INVENTORY_EXTRACT_HEADERS) - 1)
        worksheet.freeze_panes(1, 0)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a standalone W03 inventory extract from W01-like account rows.")
    parser.add_argument("--account", action="append", default=[], help="Beneficiary account name to query; repeatable.")
    parser.add_argument("--output-file", default="fork/RUNS/inventory_extract_test.xlsx")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
    w01_rows = [{"account_name": account} for account in args.account]
    rows = build_w03_rows(w01_rows=w01_rows, dry_run=args.dry_run)
    write_w03_workbook(Path(args.output_file), rows)
    log.info("W03 standalone workbook written output_file=%s rows=%s", args.output_file, len(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
