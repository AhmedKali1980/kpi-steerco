"""Configuration for the KPI fork increments."""

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
    },
    {
        "worksheet": "W02",
        "feature": "DALI impactAnalysis extract",
        "description": "Contains the raw DALI data extracted from impactAnalysis for every distinct uid read from monitored_kears.csv. This sheet is an extract-only step and does not include Data4Sec inventory, PCE, scope, exclusion, PPTX or email enrichment.",
    },
]

DICT_KEARS_ACCOUNTS_SHEET = "W01"
DICT_KEARS_ACCOUNTS_HEADERS = ["account_id", "account_name", "env_account", "KEAR_SG_UID"]

DALI_EXTRACT_SHEET = "W02"
DALI_EXTRACT_HEADERS = ["uid", "kear", "program", "network", "taken", "short_label", "slide", "Server UID", "lookup_status", "count", "error"]
DALI = {
    "BASE_URL": _env("DALI_BASE_URL"),
    "TOKEN_URL": _env("SGMARKET_TOKEN_URL"),
    "SGCONNECT_CLIENT_ID": _env("SGCONNECT_CLIENT_ID"),
    "SGCONNECT_CLIENT_SECRET": _env("SGCONNECT_CLIENT_SECRET"),
    "SGCONNECT_SCOPES": _env("SGCONNECT_SCOPES"),
    "DALI_CLIENT_ID": _env("DALI_CLIENT_ID"),
    "DALI_CLIENT_ID_HEADER": _env("DALI_CLIENT_ID_HEADER", "x-client-id"),
    "IMPACT_ENDPOINT": _env("DALI_IMPACT_ENDPOINT", "/api/v1/impactAnalysis"),
    "DEPTH_UNTIL": int(_env("DALI_DEPTH_UNTIL", "8")),
    "LIMIT": int(_env("DALI_LIMIT", "10000")),
    "IMPACT_DEFAULT_PARAMS": {
        "attributeType": _env("DALI_ATTRIBUTE_TYPE", "uid"),
        "impactType": _env("DALI_IMPACT_TYPE", "Applicative"),
    },
}
