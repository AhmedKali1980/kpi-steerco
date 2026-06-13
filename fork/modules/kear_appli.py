"""Data4Sec kear_appli enrichment for the W05 application dictionary."""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Tuple

from config import KEAR_APPLI
from data4sec_client import Data4SecClient

log = logging.getLogger(__name__)

ORDERED_APPLICATION_LABEL_ATTRIBUTES = ["IRT", "IAPPLI (Trigram)", "IAPPLI"]
KEAR_APPLI_ISSUER_COLUMN = "KEAR_APPLI (identifiers.issuer)"
KEAR_APPLI_IDENTIFIER_COLUMN = "KEAR_APPLI (identifiers.identifier)"
PROPOSED_APPLICATION_LABEL_COLUMN = "proposed application label"
KEAR_APPLI_W05_COLUMNS = [
    KEAR_APPLI_ISSUER_COLUMN,
    KEAR_APPLI_IDENTIFIER_COLUMN,
    PROPOSED_APPLICATION_LABEL_COLUMN,
]


def normalize_lookup_value(value: Any) -> str:
    return str(value or "").strip().upper()


def normalize_cell_value(value: Any) -> str:
    return str(value or "").strip()


def build_apma_value(attr_list: List[str], val_list: List[str], ordered_attributes: List[str]) -> str:
    """Build the ordered APMA suffix from identifier issuers and values."""
    mapping = dict(zip(attr_list, val_list))
    result_values: List[str] = []
    for attribute in ordered_attributes:
        if attribute in mapping:
            value = normalize_cell_value(mapping[attribute])
            if value:
                result_values.append(value)
    return ".".join(result_values)


def build_proposed_application_label(global_id: str, issuers: List[str], identifiers: List[str]) -> str:
    """Return APMA_<global_id>[_<IRT.IAPPLI-trigram.IAPPLI>] using the supplied order."""
    normalized_global_id = normalize_cell_value(global_id)
    concatenated = build_apma_value(issuers, identifiers, ORDERED_APPLICATION_LABEL_ATTRIBUTES)
    return f"APMA_{normalized_global_id}_{concatenated}" if concatenated else f"APMA_{normalized_global_id}"


def _list_values(value: Any) -> List[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _extract_identifier_pairs(doc: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """Extract issuer/identifier pairs while preserving the pair order returned by Elasticsearch."""
    issuers: List[str] = []
    identifiers: List[str] = []

    nested_identifiers = doc.get("identifiers")
    if isinstance(nested_identifiers, list):
        for item in nested_identifiers:
            if not isinstance(item, dict):
                continue
            issuer = normalize_cell_value(item.get("issuer"))
            identifier = normalize_cell_value(item.get("identifier"))
            if issuer or identifier:
                issuers.append(issuer)
                identifiers.append(identifier)
    elif isinstance(nested_identifiers, dict):
        issuer = normalize_cell_value(nested_identifiers.get("issuer"))
        identifier = normalize_cell_value(nested_identifiers.get("identifier"))
        if issuer or identifier:
            issuers.append(issuer)
            identifiers.append(identifier)

    if issuers or identifiers:
        return issuers, identifiers

    dotted_issuers = [normalize_cell_value(value) for value in _list_values(doc.get("identifiers.issuer"))]
    dotted_identifiers = [normalize_cell_value(value) for value in _list_values(doc.get("identifiers.identifier"))]
    max_len = max(len(dotted_issuers), len(dotted_identifiers))
    for idx in range(max_len):
        issuer = dotted_issuers[idx] if idx < len(dotted_issuers) else ""
        identifier = dotted_identifiers[idx] if idx < len(dotted_identifiers) else ""
        if issuer or identifier:
            issuers.append(issuer)
            identifiers.append(identifier)
    return issuers, identifiers


def _first_doc_by_uid(docs_by_uid: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for lookup_uid, docs in docs_by_uid.items():
        if docs:
            out[normalize_lookup_value(lookup_uid)] = docs[0]
    return out


def query_kear_appli_by_global_ids(client: Data4SecClient, uids: Iterable[str]) -> Dict[str, Dict[str, Any]]:
    lookup_values: List[str] = []
    seen: set[str] = set()
    for uid in uids:
        raw_uid = normalize_cell_value(uid)
        normalized = normalize_lookup_value(raw_uid)
        if raw_uid and normalized not in seen:
            seen.add(normalized)
            lookup_values.append(raw_uid)

    if not lookup_values:
        log.info("STEP 05 - KEAR_APPLI enrichment skipped: no W05 uid to query")
        return {}

    log.info(
        "STEP 05 - KEAR_APPLI enrichment query start | index=%s | global_id_count=%s",
        KEAR_APPLI["INDEX"],
        len(lookup_values),
    )
    docs_by_uid = client.bulk_search_multi(
        index_name=KEAR_APPLI["INDEX"],
        search_field=KEAR_APPLI["SEARCH_FIELD"],
        values=lookup_values,
        source_fields=KEAR_APPLI["SOURCE_FIELDS"],
        scroll_timeout=KEAR_APPLI["SCROLL_TIMEOUT"],
        size=KEAR_APPLI["BATCH_SIZE"],
    )
    docs_by_normalized_uid = _first_doc_by_uid(docs_by_uid)
    log.info(
        "STEP 05 - KEAR_APPLI enrichment query done | matched_global_ids=%s/%s",
        len(docs_by_normalized_uid),
        len(lookup_values),
    )
    return docs_by_normalized_uid


def enrich_w05_rows_with_kear_appli(
    w05_rows: List[Dict[str, str]],
    client: Data4SecClient | None = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Append KEAR_APPLI and proposed label columns to W05 rows."""
    for row in w05_rows:
        for column in KEAR_APPLI_W05_COLUMNS:
            row.setdefault(column, "")

    if dry_run:
        log.info("STEP 05 - KEAR_APPLI enrichment skipped by dry-run flag")
        return {"matched_global_ids": 0, "row_count": len(w05_rows), "dry_run": True}

    effective_client = client or Data4SecClient()
    docs_by_uid = query_kear_appli_by_global_ids(effective_client, (row.get("uid", "") for row in w05_rows))

    matched_rows = 0
    for row in w05_rows:
        uid = normalize_cell_value(row.get("uid"))
        doc = docs_by_uid.get(normalize_lookup_value(uid))
        if not doc:
            continue
        global_id = normalize_cell_value(doc.get("global_id")) or uid
        issuers, identifiers = _extract_identifier_pairs(doc)
        row[KEAR_APPLI_ISSUER_COLUMN] = ", ".join(issuers)
        row[KEAR_APPLI_IDENTIFIER_COLUMN] = ", ".join(identifiers)
        row[PROPOSED_APPLICATION_LABEL_COLUMN] = build_proposed_application_label(global_id, issuers, identifiers)
        matched_rows += 1

    log.info(
        "STEP 05 - KEAR_APPLI enrichment done | rows=%s | matched_rows=%s",
        len(w05_rows),
        matched_rows,
    )
    return {"matched_global_ids": matched_rows, "row_count": len(w05_rows), "dry_run": False}
