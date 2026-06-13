"""Build rows for the DictKearsAccounts Excel sheet."""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from config import PLATFORM_ACCOUNTS
from dali_application_dictionary import build_application_search_body, extract_application_properties
from data4sec_client import Data4SecClient
from input_reader import read_monitored_uids


log = logging.getLogger(__name__)


def split_tags(tags_value: Any) -> List[str]:
    """Return individual tags from the Data4Sec tags field."""
    if isinstance(tags_value, list):
        return [str(item or "").strip() for item in tags_value if str(item or "").strip()]

    text = str(tags_value or "").strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    return [part.strip() for part in text.split(",") if part.strip()]


def _tag_column_name(key: str, value_part: str) -> str:
    if key.lower() == "is" and "=" in value_part:
        attribute, _value = value_part.split("=", 1)
        return f"is_{attribute.strip()}"
    return key


def parse_tags_attributes(tags_value: Any) -> Dict[str, str]:
    """Parse tags into one Excel column per tag attribute.

    Supported formats:
    - ``KEY:VALUE`` (example: ``ENV:PRD``)
    - ``is:attribute=value`` (example: ``is:env=PRD`` -> column ``is_env``)
    """
    attributes: Dict[str, str] = {}
    for tag in split_tags(tags_value):
        if ":" not in tag:
            continue
        key, value_part = tag.split(":", 1)
        key = key.strip()
        value_part = value_part.strip()
        if not key or not value_part:
            continue

        column = _tag_column_name(key, value_part)
        value = value_part.split("=", 1)[1].strip() if key.lower() == "is" and "=" in value_part else value_part
        if not column or not value:
            continue

        existing = attributes.get(column)
        if existing and value not in {part.strip() for part in existing.split("|")}:
            attributes[column] = f"{existing} | {value}"
        elif not existing:
            attributes[column] = value
    return attributes


def extract_env_from_tags(tags_value: Any) -> str:
    attributes = parse_tags_attributes(tags_value)
    return attributes.get("ENV") or attributes.get("is_env") or ""


def _first_kear_sg_uid(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return text.split("|", 1)[0].strip()


def _distinct_w01_kear_sg_uids(w01_rows: Iterable[Dict[str, str]]) -> List[str]:
    output: List[str] = []
    seen: set[str] = set()
    for row in w01_rows:
        uid = _first_kear_sg_uid(row.get("KEAR_SG_UID"))
        if uid and uid not in seen:
            seen.add(uid)
            output.append(uid)
    return output


def _row_from_platform_account(account: Dict[str, Any], account_linked_to: str) -> Dict[str, str]:
    tag_attributes = parse_tags_attributes(account.get("tags"))
    return {
        "account_id": str(account.get("id") or "").strip(),
        "account_name": str(account.get("name") or "").strip(),
        "env_account": tag_attributes.get("ENV") or tag_attributes.get("is_env") or "",
        "appName": "",
        "dsi": "",
        "KEAR_SG_UID": tag_attributes.get("KEAR_SG_UID", ""),
        "Account linked to": account_linked_to,
    }


def _account_row_key(row: Dict[str, str]) -> tuple[str, str]:
    return (str(row.get("account_id") or "").strip().upper(), str(row.get("account_name") or "").strip().upper())


def _w01_append_account_names_from_w03(w03_rows: Iterable[Dict[str, str]]) -> List[Tuple[str, str]]:
    """Return W03 account names to append to W01 with their linkage label.

    Beneficiary accounts keep the historical Not Business App label.
    owner_app_name values are appended only when they are not already present
    in beneficiary values and are labelled as infra owners.
    """
    beneficiary_names: List[str] = []
    owner_names: List[str] = []
    beneficiary_seen: set[str] = set()
    owner_seen: set[str] = set()

    for row in w03_rows:
        if str(row.get("Asset linked to") or "").strip() != "Not Business Account":
            continue

        beneficiary = str(row.get("beneficiary") or "").strip()
        normalized_beneficiary = beneficiary.upper()
        if beneficiary and normalized_beneficiary not in beneficiary_seen:
            beneficiary_seen.add(normalized_beneficiary)
            beneficiary_names.append(beneficiary)

        owner = str(row.get("owner_app_name") or "").strip()
        normalized_owner = owner.upper()
        if owner and normalized_owner not in owner_seen:
            owner_seen.add(normalized_owner)
            owner_names.append(owner)

    output: List[Tuple[str, str]] = [(name, "Not Business App") for name in beneficiary_names]
    output.extend(
        (name, "Infra Owner of Business App")
        for name in owner_names
        if name.upper() not in beneficiary_seen
    )
    return output


def append_not_business_accounts_from_w03(
    w01_rows: List[Dict[str, str]],
    w03_rows: List[Dict[str, str]],
    client: Data4SecClient | None = None,
    dry_run: bool = False,
) -> int:
    """Append W01 rows for W03 not-business beneficiaries and infra owners."""
    account_name_links = _w01_append_account_names_from_w03(w03_rows)
    account_names = [name for name, _link in account_name_links]
    infra_owner_candidates = sum(1 for _name, link in account_name_links if link == "Infra Owner of Business App")
    log.info(
        "W01 not-business account enrichment start candidate_account_names=%s infra_owner_candidates=%s dry_run=%s",
        len(account_names),
        infra_owner_candidates,
        dry_run,
    )
    if not account_names or dry_run:
        log.info(
            "W01 not-business account enrichment skipped candidate_account_names=%s infra_owner_candidates=%s dry_run=%s",
            len(account_names),
            infra_owner_candidates,
            dry_run,
        )
        return 0

    client = client or Data4SecClient()
    accounts_by_name = client.bulk_search_multi(
        index_name=PLATFORM_ACCOUNTS["INDEX"],
        search_field="name",
        values=account_names,
        source_fields=PLATFORM_ACCOUNTS["SOURCE_FIELDS"],
        scroll_timeout=PLATFORM_ACCOUNTS["SCROLL_TIMEOUT"],
        size=PLATFORM_ACCOUNTS["BATCH_SIZE"],
    )

    seen = {_account_row_key(row) for row in w01_rows}
    appended = 0
    appended_infra_owners = 0
    for account_name, account_linked_to in account_name_links:
        for account in accounts_by_name.get(account_name.upper(), []):
            row = _row_from_platform_account(account, account_linked_to)
            key = _account_row_key(row)
            if key in seen:
                continue
            seen.add(key)
            w01_rows.append(row)
            appended += 1
            if account_linked_to == "Infra Owner of Business App":
                appended_infra_owners += 1
    log.info(
        "W01 not-business account enrichment completed candidate_account_names=%s appended_rows=%s appended_infra_owner_rows=%s",
        len(account_names),
        appended,
        appended_infra_owners,
    )
    return appended


def enrich_w01_rows_with_dali_application_attributes(
    w01_rows: List[Dict[str, str]],
    client: Any,
    search_endpoint: str,
    sleep_ms: int = 0,
    dry_run: bool = False,
    limit: int = 100,
) -> Tuple[int, Dict[str, Any]]:
    """Fill W01 appName and dsi from DALI search using distinct W01 KEAR_SG_UID values."""
    uids = _distinct_w01_kear_sg_uids(w01_rows)
    log.info("W01 DALI application attributes enrichment start uid_count=%s dry_run=%s", len(uids), dry_run)
    attributes_by_uid: Dict[str, Dict[str, str]] = {}
    items: List[Dict[str, Any]] = []
    errors: List[Dict[str, str]] = []
    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    for idx, uid in enumerate(uids, start=1):
        log.info("W01 DALI application attributes enrichment | uid=%s | progress=%s/%s", uid, idx, len(uids))
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
                log.warning("W01 DALI application attributes enrichment | uid=%s | error=%s", uid, err_text)

        properties = extract_application_properties(response)
        attributes_by_uid[uid] = {
            "appName": str(properties.get("name") or "").strip(),
            "dsi": str(properties.get("dsi") or "").strip(),
        }
        items.append({"uid": uid, "request": request_body, "response": response, "error": err_text})
        if sleep_ms > 0:
            time.sleep(sleep_ms / 1000.0)

    updated = 0
    for row in w01_rows:
        uid = _first_kear_sg_uid(row.get("KEAR_SG_UID"))
        attrs = attributes_by_uid.get(uid)
        if not attrs:
            row.setdefault("appName", "")
            row.setdefault("dsi", "")
            continue
        previous_app_name = row.get("appName", "")
        previous_dsi = row.get("dsi", "")
        row["appName"] = attrs.get("appName", "")
        row["dsi"] = attrs.get("dsi", "")
        if row.get("appName") != previous_app_name or row.get("dsi") != previous_dsi:
            updated += 1

    ended_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    payload = {
        "meta": {
            "generated_at": ended_at,
            "job_started_at": started_at,
            "job_end_at": ended_at,
            "endpoint": search_endpoint,
            "uid_count": len(uids),
            "success_count": len(uids) - len(errors),
            "error_count": len(errors),
            "updated_row_count": updated,
            "limit": limit,
            "dry_run": dry_run,
        },
        "items": items,
        "errors": errors,
    }
    log.info(
        "W01 DALI application attributes enrichment completed uid_count=%s updated_rows=%s errors=%s",
        len(uids),
        updated,
        len(errors),
    )
    return updated, payload


def build_dict_kears_accounts_rows(monitored_file: Path, client: Data4SecClient | None = None) -> List[Dict[str, str]]:
    uids = read_monitored_uids(monitored_file)
    if not uids:
        return []

    client = client or Data4SecClient()
    accounts_by_uid = client.search_platform_accounts_by_kear_tag(
        index_name=PLATFORM_ACCOUNTS["INDEX"],
        kear_uids=uids,
        source_fields=PLATFORM_ACCOUNTS["SOURCE_FIELDS"],
        scroll_timeout=PLATFORM_ACCOUNTS["SCROLL_TIMEOUT"],
        size=PLATFORM_ACCOUNTS["BATCH_SIZE"],
        tags_field=PLATFORM_ACCOUNTS["TAGS_FIELD"],
        tag_key=PLATFORM_ACCOUNTS["KEAR_TAG_KEY"],
    )

    rows: List[Dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for uid in uids:
        for account in accounts_by_uid.get(uid, []):
            account_id = str(account.get("id") or "").strip()
            account_name = str(account.get("name") or "").strip()
            key = (account_id.upper(), account_name.upper())
            if key in seen:
                continue
            seen.add(key)

            rows.append(_row_from_platform_account(account, "Business App"))
    return rows
