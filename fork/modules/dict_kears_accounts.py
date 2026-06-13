"""Build rows for the DictKearsAccounts Excel sheet."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Iterable, List

from config import PLATFORM_ACCOUNTS
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


def extract_app_name_from_tags(tags_value: Any) -> str:
    attributes = parse_tags_attributes(tags_value)
    return attributes.get("appName") or attributes.get("is_appName") or attributes.get("APP_NAME") or ""


def _row_from_platform_account(account: Dict[str, Any], account_linked_to: str) -> Dict[str, str]:
    tag_attributes = parse_tags_attributes(account.get("tags"))
    return {
        "account_id": str(account.get("id") or "").strip(),
        "account_name": str(account.get("name") or "").strip(),
        "env_account": tag_attributes.get("ENV") or tag_attributes.get("is_env") or "",
        "appName": tag_attributes.get("appName") or tag_attributes.get("is_appName") or tag_attributes.get("APP_NAME") or "",
        "KEAR_SG_UID": tag_attributes.get("KEAR_SG_UID", ""),
        "Account linked to": account_linked_to,
    }


def _account_row_key(row: Dict[str, str]) -> tuple[str, str]:
    return (str(row.get("account_id") or "").strip().upper(), str(row.get("account_name") or "").strip().upper())


def _distinct_not_business_account_names(w03_rows: Iterable[Dict[str, str]]) -> List[str]:
    output: List[str] = []
    seen: set[str] = set()
    for row in w03_rows:
        if str(row.get("Asset linked to") or "").strip() != "Not Business Account":
            continue
        for column in ("beneficiary", "owner_app_name"):
            value = str(row.get(column) or "").strip()
            normalized = value.upper()
            if value and normalized not in seen:
                seen.add(normalized)
                output.append(value)
    return output


def append_not_business_accounts_from_w03(
    w01_rows: List[Dict[str, str]],
    w03_rows: List[Dict[str, str]],
    client: Data4SecClient | None = None,
    dry_run: bool = False,
) -> int:
    """Append W01 rows for accounts found on W03 Not Business Account assets."""
    account_names = _distinct_not_business_account_names(w03_rows)
    log.info(
        "W01 not-business account enrichment start candidate_account_names=%s dry_run=%s",
        len(account_names),
        dry_run,
    )
    if not account_names or dry_run:
        log.info("W01 not-business account enrichment skipped candidate_account_names=%s dry_run=%s", len(account_names), dry_run)
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
    for account_name in account_names:
        for account in accounts_by_name.get(account_name.upper(), []):
            row = _row_from_platform_account(account, "Not Business App")
            key = _account_row_key(row)
            if key in seen:
                continue
            seen.add(key)
            w01_rows.append(row)
            appended += 1
    log.info(
        "W01 not-business account enrichment completed candidate_account_names=%s appended_rows=%s",
        len(account_names),
        appended,
    )
    return appended


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
