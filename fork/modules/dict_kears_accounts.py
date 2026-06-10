"""Build rows for the DictKearsAccounts Excel sheet."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from config import PLATFORM_ACCOUNTS
from data4sec_client import Data4SecClient
from input_reader import read_monitored_uids


def extract_env_from_tags(tags_value: Any) -> str:
    if isinstance(tags_value, list):
        items = [str(item or "").strip() for item in tags_value if str(item or "").strip()]
    else:
        text = str(tags_value or "").strip()
        if text.startswith("[") and text.endswith("]"):
            text = text[1:-1]
        items = [part.strip() for part in text.split(",") if part.strip()]

    for item in items:
        if ":" not in item:
            continue
        key, value = item.split(":", 1)
        if key.strip().upper() == "ENV":
            return value.strip()
    return ""


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
            rows.append(
                {
                    "account_id": account_id,
                    "account_name": account_name,
                    "env_account": extract_env_from_tags(account.get("tags")),
                }
            )
    return rows
