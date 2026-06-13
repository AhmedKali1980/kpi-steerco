"""Enrich W02 DALI rows with inventory ownership columns from W03.

This module is intentionally fork-local. It adds the inventory-facing columns that
are needed by the fork workbook without modifying the parent project pipeline.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Tuple

from inventory_extract import normalize_lookup_value, normalize_uuid_from_hostid

log = logging.getLogger(__name__)

W02_SERVER_UID_COLUMN = "DALI [CI] SERVER UID"
W02_CLOUD_TYPE_COLUMN = "DALI [CI] CLOUD TYPE"
GEN2_CLOUD_TYPE = "GEN 2"
NOT_GEN2_VALUE = "NOT_GEN2"
NOT_FOUND_IN_INVENTORY_VALUE = "NOT_FOUND_IN_INVENTORY"

W02_INVENTORY_LOOKUP_HEADERS = [
    "INV_owner_account_id",
    "INV_owner_account_name",
    "INV_beneficiary_account_id",
    "INV_beneficiary_account_name",
    "INV_region",
]

W02_INVENTORY_ENRICHMENT_HEADERS = [
    *W02_INVENTORY_LOOKUP_HEADERS,
    "Gen 2 Asset linked to",
]


def _normalize_asset_uid(value: Any) -> str:
    return normalize_uuid_from_hostid(value)


def _account_id_by_name(w01_rows: Iterable[Dict[str, Any]]) -> Dict[str, str]:
    """Build a normalized account-name -> account-id lookup from W01 rows."""
    lookup: Dict[str, str] = {}
    for row in w01_rows:
        account_name_key = normalize_lookup_value(row.get("account_name"))
        account_id = str(row.get("account_id") or "").strip()
        if account_name_key and account_id and account_name_key not in lookup:
            lookup[account_name_key] = account_id
    return lookup


def _inventory_by_hostid(w03_rows: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Build a normalized inventory UUID -> W03 row lookup.

    If W03 contains duplicate assets, the first row wins to keep the enrichment
    stable with the upstream W03 extraction order.
    """
    lookup: Dict[str, Dict[str, Any]] = {}
    for row in w03_rows:
        normalized_uuid = _normalize_asset_uid(row.get("Normalized_uuid_from_hostid"))
        if normalized_uuid and normalized_uuid not in lookup:
            lookup[normalized_uuid] = row
    return lookup


def w02_headers_with_inventory_enrichment(headers: Iterable[str]) -> List[str]:
    """Append the W02 inventory enrichment columns once, preserving order."""
    output = list(headers)
    for header in W02_INVENTORY_ENRICHMENT_HEADERS:
        if header not in output:
            output.append(header)
    return output


def enrich_w02_rows_with_inventory(
    w02_rows: List[Dict[str, Any]],
    w03_rows: Iterable[Dict[str, Any]],
    w01_rows: Iterable[Dict[str, Any]] | None = None,
) -> Tuple[List[Dict[str, str]], Dict[str, int]]:
    """Fill W02 inventory columns from the completed W01/W03 dictionaries.

    All non-Gen2 assets are explicitly marked ``NOT_GEN2``. Gen2 assets are
    matched with W03 using
    ``W03.Normalized_uuid_from_hostid == W02.DALI [CI] SERVER UID`` after the
    same hostid/UUID normalization used by the W03 module. Gen2 assets without
    a W03 match get ``NOT_FOUND_IN_INVENTORY`` in the five inventory lookup
    columns.
    """
    w03_row_list = list(w03_rows)
    inventory_lookup = _inventory_by_hostid(w03_row_list)
    account_lookup = _account_id_by_name(w01_rows or [])
    matched = 0
    not_gen2 = 0
    unmatched_gen2 = 0
    enriched_rows: List[Dict[str, str]] = []

    log.info(
        "STEP 02B - W02 inventory enrichment | Starting | W02 rows=%s | W03 assets=%s | W01 account names=%s",
        len(w02_rows),
        len(inventory_lookup),
        len(account_lookup),
    )

    for row in w02_rows:
        enriched = {str(key): str(value or "") for key, value in row.items()}
        for header in W02_INVENTORY_ENRICHMENT_HEADERS:
            enriched.setdefault(header, "")

        normalized_server_uid = _normalize_asset_uid(enriched.get(W02_SERVER_UID_COLUMN))
        is_gen2 = normalize_lookup_value(enriched.get(W02_CLOUD_TYPE_COLUMN)) == GEN2_CLOUD_TYPE
        inventory_row = inventory_lookup.get(normalized_server_uid) if is_gen2 else None
        if not is_gen2:
            for header in W02_INVENTORY_ENRICHMENT_HEADERS:
                enriched[header] = NOT_GEN2_VALUE
            not_gen2 += 1
        elif inventory_row:
            owner_name = str(inventory_row.get("owner_app_name") or "").strip()
            beneficiary_name = str(inventory_row.get("beneficiary") or "").strip()
            enriched["INV_owner_account_name"] = owner_name
            enriched["INV_beneficiary_account_name"] = beneficiary_name
            enriched["INV_region"] = str(inventory_row.get("region") or "").strip()
            enriched["Gen 2 Asset linked to"] = str(inventory_row.get("Asset linked to") or "").strip()
            enriched["INV_owner_account_id"] = account_lookup.get(normalize_lookup_value(owner_name), "")
            enriched["INV_beneficiary_account_id"] = account_lookup.get(normalize_lookup_value(beneficiary_name), "")
            matched += 1
        else:
            for header in W02_INVENTORY_LOOKUP_HEADERS:
                enriched[header] = NOT_FOUND_IN_INVENTORY_VALUE
            unmatched_gen2 += 1

        enriched_rows.append(enriched)

    summary = {
        "rows": len(enriched_rows),
        "matched_inventory": matched,
        "not_gen2": not_gen2,
        "unmatched_gen2": unmatched_gen2,
        "not_found_in_inventory": unmatched_gen2,
    }
    log.info(
        "STEP 02B - W02 inventory enrichment | Completed | rows=%s | matched_inventory=%s | not_gen2=%s | unmatched_gen2=%s | not_found_in_inventory=%s",
        summary["rows"],
        summary["matched_inventory"],
        summary["not_gen2"],
        summary["unmatched_gen2"],
        summary["not_found_in_inventory"],
    )
    return enriched_rows, summary
