"""Build the W05 DALI application dictionary sheet for the KPI fork."""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Tuple

from config import APPLICATION_DICTIONARY_HEADERS
log = logging.getLogger(__name__)


def build_application_search_body(uid: str, limit: int = 100) -> Dict[str, Any]:
    """Return the DALI search request body used to retrieve one application."""
    return {
        "filters": [
            {
                "attributeName": "uid",
                "attributeValue": uid,
                "matchType": "equals",
            }
        ],
        "includeCount": True,
        "label": "Application",
        "limit": limit,
        "orderBy": [
            {
                "direction": "asc",
                "labelProperty": "string",
            }
        ],
        "skip": 0,
    }


def extract_application_properties(response: Dict[str, Any]) -> Dict[str, Any]:
    """Extract ``result[0].leading_node.properties`` from a DALI search response."""
    result = response.get("result") if isinstance(response, dict) else None
    if not isinstance(result, list) or not result:
        return {}
    first = result[0]
    if not isinstance(first, dict):
        return {}
    leading_node = first.get("leading_node")
    if not isinstance(leading_node, dict):
        return {}
    properties = leading_node.get("properties")
    return properties if isinstance(properties, dict) else {}


def _uid_for_w05(row: Dict[str, str]) -> str:
    """Return the original monitored UID casing for DALI search equality matching."""
    return str(row.get("input_uid") or row.get("uid") or "").strip()


def _unique_preserving_original_uids(monitored_rows: List[Dict[str, str]]) -> List[str]:
    output: List[str] = []
    seen: set[str] = set()
    for row in monitored_rows:
        uid = _uid_for_w05(row)
        if not uid or uid in seen:
            continue
        seen.add(uid)
        output.append(uid)
    return output


def build_w05_rows(
    client: Any,
    monitored_rows: List[Dict[str, str]],
    search_endpoint: str,
    sleep_ms: int = 0,
    dry_run: bool = False,
    limit: int = 100,
) -> Tuple[List[Dict[str, str]], Dict[str, Any]]:
    """Query DALI search for distinct monitored UIDs and return W05 rows + trace."""
    uids = _unique_preserving_original_uids(monitored_rows)
    rows: List[Dict[str, str]] = []
    items: List[Dict[str, Any]] = []
    errors: List[Dict[str, str]] = []
    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    log.info("STEP 05 - DALI application dictionary W05 | Preparing batch | uid_count=%s | dry_run=%s", len(uids), dry_run)
    for idx, uid in enumerate(uids, start=1):
        log.info("STEP 05 - DALI application dictionary W05 | uid=%s | progress=%s/%s", uid, idx, len(uids))
        request_body = build_application_search_body(uid=uid, limit=limit)
        err_text = ""
        if dry_run:
            response: Dict[str, Any] = {"count": 0, "result": []}
        else:
            try:
                response = client.post_json(endpoint=search_endpoint, payload=request_body)
            except Exception as exc:
                err_text = str(exc)
                response = {}
                errors.append({"uid": uid, "error": err_text})
                log.warning("STEP 05 - DALI application dictionary W05 | uid=%s | error=%s", uid, err_text)

        properties = extract_application_properties(response)
        row = {header: str(properties.get(header, "") or "") for header in APPLICATION_DICTIONARY_HEADERS}
        row["uid"] = row.get("uid") or uid
        rows.append(row)
        items.append({"uid": uid, "request": request_body, "response": response, "error": err_text})
        if sleep_ms > 0:
            time.sleep(sleep_ms / 1000.0)

    ended_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    found_uid_count = sum(
        1
        for item in items
        if isinstance(item.get("response"), dict) and int(item.get("response", {}).get("count", 0) or 0) > 0
    )
    payload = {
        "meta": {
            "generated_at": ended_at,
            "job_started_at": started_at,
            "job_end_at": ended_at,
            "endpoint": search_endpoint,
            "uid_count": len(uids),
            "success_count": len(uids) - len(errors),
            "found_uid_count": found_uid_count,
            "error_count": len(errors),
            "row_count": len(rows),
            "limit": limit,
            "dry_run": dry_run,
        },
        "items": items,
        "errors": errors,
    }
    log.info(
        "STEP 05 - DALI application dictionary W05 | Completed | uid_count=%s | rows=%s | errors=%s",
        len(uids),
        len(rows),
        len(errors),
    )
    return rows, payload
