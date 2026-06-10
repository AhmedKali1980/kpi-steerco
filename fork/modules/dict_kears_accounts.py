"""Build rows for the DictKearsAccounts Excel sheet."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from config import PLATFORM_ACCOUNTS
from data4sec_client import Data4SecClient
from input_reader import read_monitored_uids


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

            tag_attributes = parse_tags_attributes(account.get("tags"))
            rows.append(
                {
                    "account_id": account_id,
                    "account_name": account_name,
                    "env_account": tag_attributes.get("ENV") or tag_attributes.get("is_env") or "",
                    **tag_attributes,
                }
            )
    return rows
