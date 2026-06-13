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

INVENTORY = {
    "INDEX": _env("INVENTORY_INDEX", "inventory"),
    "BENEFICIARY_SEARCH_FIELD": _env("INVENTORY_BENEFICIARY_SEARCH_FIELD", "beneficiary"),
    "SOURCE_FIELDS": [
        "hostid",
        "srn",
        "ocs_name",
        "hostname",
        "beneficiary",
        "owner_app_name",
        "status",
        "region",
        "ip",
        "service_name",
    ],
    "TERM_FILTERS": {
        "status.keyword": [
            "ACTIVE",
            "Active",
            "active",
            "<UNKNOWN STATUS>",
            "<unknown status>",
            "<Unknown Status>",
            "UNKNOWN",
            "Unknown",
            "unknown",
        ]
    },
    "SCROLL_TIMEOUT": _env("INVENTORY_SCROLL_TIMEOUT", "10m"),
    "BATCH_SIZE": int(_env("INVENTORY_BATCH_SIZE", "500")),
}

KEAR_APPLI = {
    "INDEX": _env("KEAR_APPLI_INDEX", "kear_appli"),
    "SEARCH_FIELD": _env("KEAR_APPLI_SEARCH_FIELD", "global_id"),
    "SOURCE_FIELDS": ["global_id", "identifiers", "identifiers.issuer", "identifiers.identifier"],
    "SCROLL_TIMEOUT": _env("KEAR_APPLI_SCROLL_TIMEOUT", "10m"),
    "BATCH_SIZE": int(_env("KEAR_APPLI_BATCH_SIZE", "500")),
}

MARLEY_ORIGINAL = {
    "INDEX": _env("MARLEY_ORIGINAL_INDEX", "marley_original"),
    "UID_SEARCH_FIELD": _env("MARLEY_ORIGINAL_UID_SEARCH_FIELD", "app_info.kear_uuid"),
    "SOURCE_FIELDS": [
        "hostname",
        "ocs_name",
        "app_info",
        "app_info.iapplicode",
        "app_info.kear_library",
        "uuid",
        "brand",
        "country",
        "geo_zone",
        "model",
        "type",
        "net_info",
        "os_name",
        "os_version",
        "typologie",
        "silos",
        "dns",
        "status",
        "usage",
    ],
    "TERM_FILTERS": {
        "status.keyword": [
            "ACTIVE",
            "Active",
            "active",
            "<UNKNOWN STATUS>",
            "<unknown status>",
            "<Unknown Status>",
            "UNKNOWN",
            "Unknown",
            "unknown",
        ]
    },
    "SCROLL_TIMEOUT": _env("MARLEY_ORIGINAL_SCROLL_TIMEOUT", "10m"),
    "BATCH_SIZE": int(_env("MARLEY_ORIGINAL_BATCH_SIZE", "500")),
}

INDEX_SHEET = "Index"
INDEX_HEADERS = ["worksheet", "feature", "description"]
INDEX_ROWS = [
    {
        "worksheet": "W01",
        "feature": "Kears/Accounts dictionary",
        "description": "Retrieves all business accounts related to the listed KEARs, including the account environment and appName resolved from data4sec/platform_accounts.",
    },
    {
        "worksheet": "W02",
        "feature": "DALI impactAnalysis extract",
        "description": "Contains the DALI data extracted from impactAnalysis for every distinct uid read from monitored_kears.csv, plus fork-only inventory owner/beneficiary/region columns filled from W03.",
    },
    {
        "worksheet": "W03",
        "feature": "Inventory extract by beneficiary account",
        "description": "Fork equivalent of parent get_inv_by_account: queries data4sec/inventory with W01 account_name values as beneficiary accounts, then appends not-business Gen 2 W02 assets missing from W03 by searching inventory srn with hostid fallback.",
    },
    {
        "worksheet": "W04",
        "feature": "Marley original assets by monitored UID",
        "description": "Direct extract from data4sec/marley_original using monitored_kears.csv uid values against app_info.kear_uuid; keeps only assets retrieved from Elasticsearch.",
    },
    {
        "worksheet": "W05",
        "feature": "DALI application dictionary",
        "description": "Queries DALI search for each distinct monitored application uid, enriches with data4sec/kear_appli identifiers, and proposes an APMA application label from IRT, IAPPLI (Trigram), and IAPPLI values.",
    },
]

DICT_KEARS_ACCOUNTS_SHEET = "W01"
DICT_KEARS_ACCOUNTS_HEADERS = ["account_id", "account_name", "env_account", "appName", "KEAR_SG_UID", "Account linked to"]

INVENTORY_EXTRACT_SHEET = "W03"
INVENTORY_EXTRACT_HEADERS = [
    "input_INV_Beneficiary_Account",
    "beneficiary",
    "owner_app_name",
    "ocs_name",
    "hostname",
    "status",
    "region",
    "hostid",
    "Normalized_uuid_from_hostid",
    "lookup_in_raw",
    "srn",
    "Normalized_uuid_from_srn",
    "ip",
    "service_name",
    "Asset linked to",
]

MARLEY_ORIGINAL_SHEET = "W04"
MARLEY_ORIGINAL_HEADERS = [
    "input_uid",
    "hostname",
    "ocs_name",
    "uuid",
    "lookup_in_dali_inventory",
    "app_info.kear_uuid",
    "app_info.account_id",
    "app_info.app_id",
    "app_info.app_name",
    "app_info.env",
    "app_info.factor",
    "app_info.kear_library",
    "app_info.iapplicode",
    "app_info.ref_app",
    "app_info.service_line_name",
    "net_info.net_ipadress",
    "brand",
    "country",
    "geo_zone",
    "model",
    "type",
    "os_name",
    "os_version",
    "typologie",
    "silos",
    "dns",
    "status",
    "usage",
]

DALI_EXTRACT_SHEET = "W02"
DALI_IMPACT_RELATIONSHIPS = [
    "CHANGES",
    "IS_ASSIGNED_TO",
    "IS_CONTAINED_BY",
    "IS_GRANTED_TO",
    "IS_HOSTED_BY",
    "IS_LOCATED_BY",
    "IS_MANAGED_BY",
    "IS_MEMBER_OF",
    "IS_USED_BY",
    "USE",
    "USE_STORAGE",
    "MANAGE_RESOURCE",
    "IS_PROVIDED_BY",
    "IS_CONNECTED_TO",
    "COMPOSED_BY",
    "CLUSTER_CONTAINS",
]
DALI = {
    "BASE_URL": _env("DALI_BASE_URL"),
    "TOKEN_URL": _env("SGMARKET_TOKEN_URL"),
    "SGCONNECT_CLIENT_ID": _env("SGCONNECT_CLIENT_ID"),
    "SGCONNECT_CLIENT_SECRET": _env("SGCONNECT_CLIENT_SECRET"),
    "SGCONNECT_SCOPES": _env("SGCONNECT_SCOPES"),
    "DALI_CLIENT_ID": _env("DALI_CLIENT_ID"),
    "DALI_CLIENT_ID_HEADER": _env("DALI_CLIENT_ID_HEADER", "x-client-id"),
    "IMPACT_ENDPOINT": _env("DALI_IMPACT_ENDPOINT", "/api/v1/impactAnalysis"),
    "SEARCH_ENDPOINT": _env("DALI_SEARCH_ENDPOINT", "/api/v1/search"),
    "DEPTH_UNTIL": int(_env("DALI_DEPTH_UNTIL", "8")),
    "LIMIT": int(_env("DALI_LIMIT", "10000")),
    "IMPACT_DEFAULT_PARAMS": {
        "ciLabel": "Application",
        "attributeName": "uid",
        "matchType": "equals",
        "direction": "to",
        "relationship": DALI_IMPACT_RELATIONSHIPS,
        "impactedCis": "Server",
        "status": "In use",
        "reliability": "false",
        "criticality": ["Critical", "High", "Medium", "Low", "Unknown"],
        "includeLiveSources": "true",
        "zones": ["EUR", "ASIA", "AMER", "BCO", "UK", "Unknown"],
        "environments": ["Production", "Not in production"],
        "excludeDuplicates": "true",
        "boost": "false",
        "includeGTSInfra": "true",
        "includeCount": "true",
        "skip": "0",
    },
}

APPLICATION_DICTIONARY_SHEET = "W05"
APPLICATION_DICTIONARY_HEADERS = [
    "uid",
    "name",
    "short_label",
    "irt_code",
    "iappli_code",
    "trigram",
    "dsi",
    "application_management_rc",
    "application_development_manager",
    "asa",
    "status",
    "KEAR_APPLI (identifiers.issuer)",
    "KEAR_APPLI (identifiers.identifier)",
    "proposed application label",
]
