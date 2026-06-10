"""Configuration for the first fork increment: DictKearsAccounts only."""

from __future__ import annotations

import os
from pathlib import Path
from dotenv import load_dotenv

FORK_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(FORK_ROOT / ".env")
load_dotenv(Path.cwd() / ".env")


def _env(name: str, default: str = "") -> str:
    return (os.getenv(name) or default).strip().strip("'").strip('"')


ELASTICSEARCH = {
    "HOST": _env("ELASTICSEARCH_WRITE_HOST"),
    "PORT": _env("ELASTICSEARCH_WRITE_PORT", "443"),
    "USERNAME": _env("ELASTICSEARCH_WRITE_LOGIN"),
    "PASSWORD": _env("ELASTICSEARCH_WRITE_PASS"),
}

PLATFORM_ACCOUNTS = {
    "INDEX": _env("PLATFORM_ACCOUNTS_INDEX", "platform_accounts"),
    "TAGS_FIELD": _env("PLATFORM_ACCOUNTS_TAGS_FIELD", "tags"),
    "KEAR_TAG_KEY": _env("PLATFORM_ACCOUNTS_KEAR_TAG_KEY", "KEAR_SG_UID"),
    "SOURCE_FIELDS": ["id", "name", "tags"],
    "SCROLL_TIMEOUT": _env("PLATFORM_ACCOUNTS_SCROLL_TIMEOUT", "10m"),
    "BATCH_SIZE": int(_env("PLATFORM_ACCOUNTS_BATCH_SIZE", "500")),
}

INDEX_SHEET = "Index"
INDEX_HEADERS = ["worksheet", "feature", "description"]
INDEX_ROWS = [
    {
        "worksheet": "W01",
        "feature": "Kears/Accounts dictionary",
        "description": "Retrieves all business accounts related to the listed KEARs, including the account environment resolved from data4sec/platform_accounts.",
    }
]

DICT_KEARS_ACCOUNTS_SHEET = "W01"
DICT_KEARS_ACCOUNTS_HEADERS = ["account_id", "account_name", "env_account", "KEAR_SG_UID"]
