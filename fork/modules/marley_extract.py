"""Build rows for the W04 Marley original extract sheet.

W04 is a direct Data4Sec ``marley_original`` extract keyed by the monitored
KEAR ``uid`` values. It intentionally keeps only documents returned by
Elasticsearch and does not synthesize NOT_FOUND rows or apply enrichment logic.
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

from config import MARLEY_ORIGINAL, MARLEY_ORIGINAL_HEADERS, MARLEY_ORIGINAL_SHEET  # noqa: E402
from data4sec_client import Data4SecClient  # noqa: E402
from input_reader import read_monitored_uids  # noqa: E402

log = logging.getLogger(__name__)


def normalize_lookup_value(value: Any) -> str:
    return str(value or "").strip().upper()


def normalize_cell_value(value: Any) -> str:
    if isinstance(value, list):
        normalized_items = [normalize_cell_value(item) for item in value]
        return ";".join(item for item in normalized_items if item)
    if isinstance(value, dict):
        return str(value)
    return str(value or "").strip()


def nested_values(data: Any, dotted_path: str) -> List[Any]:
    parts = [part for part in str(dotted_path or "").split(".") if part]
    if not parts:
        return [data] if data is not None else []

    def walk(current: Any, remaining: List[str]) -> List[Any]:
        if current is None:
            return []
        if not remaining:
            if isinstance(current, list):
                values: List[Any] = []
                for item in current:
                    values.extend(walk(item, []))
                return values
            return [current]
        if isinstance(current, list):
            values: List[Any] = []
            for item in current:
                values.extend(walk(item, remaining))
            return values
        if not isinstance(current, dict):
            return []
        dotted_remaining = ".".join(remaining)
        if dotted_remaining in current:
            return walk(current.get(dotted_remaining), [])
        return walk(current.get(remaining[0]), remaining[1:])

    if isinstance(data, dict) and dotted_path in data:
        return walk(data.get(dotted_path), [])
    return walk(data, parts)


def nested_get(data: Dict[str, Any], dotted_path: str, default: Any = "") -> Any:
    values = nested_values(data, dotted_path)
    if not values:
        return default
    return values[0]


def normalized_tokens(value: Any) -> set[str]:
    raw_values = value if isinstance(value, list) else [value]
    tokens: set[str] = set()
    for raw_value in raw_values:
        normalized = normalize_lookup_value(raw_value)
        if normalized:
            tokens.add(normalized)
    return tokens


def app_info_candidates(doc: Dict[str, Any], input_uid: str = "") -> List[Dict[str, Any]]:
    app_info = doc.get("app_info")
    if isinstance(app_info, dict):
        candidates = [app_info]
    elif isinstance(app_info, list):
        candidates = [item for item in app_info if isinstance(item, dict)]
    else:
        candidates = []

    normalized_uid = normalize_lookup_value(input_uid)
    if not normalized_uid:
        return candidates

    matching = [
        item
        for item in candidates
        if normalized_uid in normalized_tokens(nested_values(item, "kear_uuid"))
    ]
    return matching or candidates


def normalize_asset_uuid(value: Any) -> str:
    raw = normalize_cell_value(value)
    if not raw:
        return ""
    uuid = raw.rsplit(":", 1)[-1].strip()
    if uuid.upper().startswith("VM_"):
        uuid = uuid[3:]
    return uuid.lower()


def doc_kear_uids(doc: Dict[str, Any]) -> set[str]:
    return normalized_tokens(nested_values(doc, "app_info.kear_uuid"))


def app_info_value(doc: Dict[str, Any], input_uid: str, field_name: str) -> Any:
    values: List[Any] = []
    for app_info in app_info_candidates(doc, input_uid):
        values.extend(nested_values(app_info, field_name))
    if not values:
        values = nested_values(doc, f"app_info.{field_name}")
    return values


def deduplicate_marley_docs(docs: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    unique_docs: List[Dict[str, Any]] = []
    seen: set[tuple[str, str, str, str]] = set()
    for doc in docs:
        fingerprint = (
            normalize_lookup_value(doc.get("uuid")),
            normalize_lookup_value(doc.get("hostname")),
            normalize_lookup_value(doc.get("ocs_name")),
            ";".join(sorted(doc_kear_uids(doc))),
        )
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        unique_docs.append(doc)
    return unique_docs


def query_marley_original_by_uids(
    client: Data4SecClient,
    monitored_uids: List[str],
) -> Dict[str, List[Dict[str, Any]]]:
    lookup_values = [normalize_lookup_value(uid) for uid in monitored_uids if normalize_lookup_value(uid)]
    if not lookup_values:
        log.info("W04 Marley extract skipped: no monitored uid")
        return {}

    log.info(
        "W04 Marley extract query start index=%s uid_field=%s monitored_uids=%s",
        MARLEY_ORIGINAL["INDEX"],
        MARLEY_ORIGINAL["UID_SEARCH_FIELD"],
        len(lookup_values),
    )
    result_map = client.bulk_search_multi(
        index_name=MARLEY_ORIGINAL["INDEX"],
        search_field=MARLEY_ORIGINAL["UID_SEARCH_FIELD"],
        values=lookup_values,
        source_fields=MARLEY_ORIGINAL["SOURCE_FIELDS"],
        scroll_timeout=MARLEY_ORIGINAL["SCROLL_TIMEOUT"],
        size=MARLEY_ORIGINAL["BATCH_SIZE"],
        term_filters=MARLEY_ORIGINAL["TERM_FILTERS"],
    )

    output: Dict[str, List[Dict[str, Any]]] = {}
    for uid, docs in result_map.items():
        normalized_uid = normalize_lookup_value(uid)
        if not normalized_uid or not docs:
            continue
        output[normalized_uid] = deduplicate_marley_docs(docs)

    log.info(
        "W04 Marley extract query done matched_uids=%s total_docs=%s",
        len(output),
        sum(len(docs) for docs in output.values()),
    )
    return output


def marley_doc_to_w04_row(input_uid: str, doc: Dict[str, Any]) -> Dict[str, str]:
    return {
        "input_uid": normalize_lookup_value(input_uid),
        "hostname": normalize_cell_value(doc.get("hostname")),
        "ocs_name": normalize_cell_value(doc.get("ocs_name")),
        "uuid": normalize_cell_value(doc.get("uuid")),
        "lookup_in_dali_inventory": "",
        "app_info.kear_uuid": normalize_cell_value(app_info_value(doc, input_uid, "kear_uuid")),
        "app_info.account_id": normalize_cell_value(app_info_value(doc, input_uid, "account_id")),
        "app_info.app_id": normalize_cell_value(app_info_value(doc, input_uid, "app_id")),
        "app_info.app_name": normalize_cell_value(app_info_value(doc, input_uid, "app_name")),
        "app_info.env": normalize_cell_value(app_info_value(doc, input_uid, "env")),
        "app_info.factor": normalize_cell_value(app_info_value(doc, input_uid, "factor")),
        "app_info.kear_library": normalize_cell_value(app_info_value(doc, input_uid, "kear_library")),
        "app_info.ref_app": normalize_cell_value(app_info_value(doc, input_uid, "ref_app")),
        "app_info.service_line_name": normalize_cell_value(app_info_value(doc, input_uid, "service_line_name")),
        "net_info.net_ipadress": normalize_cell_value(nested_get(doc, "net_info.net_ipadress")),
        "os_name": normalize_cell_value(doc.get("os_name")),
        "os_version": normalize_cell_value(doc.get("os_version")),
        "typologie": normalize_cell_value(doc.get("typologie")),
        "silos": normalize_cell_value(doc.get("silos")),
        "dns": normalize_cell_value(doc.get("dns")),
        "status": normalize_cell_value(doc.get("status")),
        "usage": normalize_cell_value(doc.get("usage")),
    }




def apply_lookup_in_dali_inventory(
    w04_rows: List[Dict[str, str]],
    w02_rows: Iterable[Dict[str, Any]],
    w03_rows: Iterable[Dict[str, Any]],
) -> None:
    dali_uuids = {
        normalized
        for normalized in (normalize_asset_uuid(row.get("DALI [CI] SERVER UID")) for row in w02_rows)
        if normalized
    }
    inventory_uuids = {
        normalized
        for normalized in (normalize_asset_uuid(row.get("Normalized_uuid_from_hostid")) for row in w03_rows)
        if normalized
    }

    already_in_dali = 0
    already_in_inventory = 0
    new_assets = 0
    missing_uuid = 0
    for row in w04_rows:
        normalized_uuid = normalize_asset_uuid(row.get("uuid"))
        if not normalized_uuid:
            row["lookup_in_dali_inventory"] = "NEW ASSET"
            missing_uuid += 1
            new_assets += 1
        elif normalized_uuid in dali_uuids:
            row["lookup_in_dali_inventory"] = "ALREADY IN DALI RAW"
            already_in_dali += 1
        elif normalized_uuid in inventory_uuids:
            row["lookup_in_dali_inventory"] = "ALREADY IN INVENTORY"
            already_in_inventory += 1
        else:
            row["lookup_in_dali_inventory"] = "NEW ASSET"
            new_assets += 1

    log.info(
        "W04 Marley lookup_in_dali_inventory done dali_uids=%s inventory_uids=%s already_in_dali=%s already_in_inventory=%s new_assets=%s missing_uuid=%s",
        len(dali_uuids),
        len(inventory_uuids),
        already_in_dali,
        already_in_inventory,
        new_assets,
        missing_uuid,
    )


def build_w04_rows(
    monitored_file: Path,
    client: Data4SecClient | None = None,
    dry_run: bool = False,
    w02_rows: Iterable[Dict[str, Any]] | None = None,
    w03_rows: Iterable[Dict[str, Any]] | None = None,
) -> List[Dict[str, str]]:
    monitored_uids = read_monitored_uids(monitored_file)
    if not monitored_uids:
        return []

    if dry_run:
        log.info("W04 Marley extract dry-run enabled: monitored_uids=%s", len(monitored_uids))
        return []

    client = client or Data4SecClient()
    marley_docs_by_uid = query_marley_original_by_uids(client=client, monitored_uids=monitored_uids)

    rows: List[Dict[str, str]] = []
    for uid in monitored_uids:
        normalized_uid = normalize_lookup_value(uid)
        for doc in marley_docs_by_uid.get(normalized_uid, []):
            rows.append(marley_doc_to_w04_row(input_uid=normalized_uid, doc=doc))

    if w02_rows is not None and w03_rows is not None:
        apply_lookup_in_dali_inventory(w04_rows=rows, w02_rows=w02_rows, w03_rows=w03_rows)
    return rows


def write_w04_workbook(output_file: Path, rows: List[Dict[str, str]]) -> None:
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with xlsxwriter.Workbook(str(output_file)) as workbook:
        worksheet = workbook.add_worksheet(MARLEY_ORIGINAL_SHEET)
        header_format = workbook.add_format({"bold": True, "bg_color": "#D9EAF7", "border": 1})
        for col_idx, header in enumerate(MARLEY_ORIGINAL_HEADERS):
            worksheet.write(0, col_idx, header, header_format)
        for row_idx, row in enumerate(rows, start=1):
            for col_idx, header in enumerate(MARLEY_ORIGINAL_HEADERS):
                worksheet.write(row_idx, col_idx, row.get(header, ""))
        worksheet.autofilter(0, 0, max(len(rows), 1), len(MARLEY_ORIGINAL_HEADERS) - 1)
        worksheet.freeze_panes(1, 0)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a standalone W04 Marley original extract from monitored KEAR uids.")
    parser.add_argument("--monitored-file", default="fork/users_input/monitored_kears.csv")
    parser.add_argument("--output-file", default="fork/RUNS/marley_extract_test.xlsx")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )
    rows = build_w04_rows(monitored_file=Path(args.monitored_file), dry_run=args.dry_run)
    write_w04_workbook(Path(args.output_file), rows)
    log.info("W04 standalone workbook written output_file=%s rows=%s", args.output_file, len(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
