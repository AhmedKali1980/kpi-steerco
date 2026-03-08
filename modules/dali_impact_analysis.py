"""DALI impact analysis and Data4Sec inventory enrichment pipeline.

This module orchestrates monitored-UID extraction from DALI, inventory enrichment
for Gen2 servers, beneficiary-based discovery, and report artifact generation.
"""

import argparse
import base64
import csv
import gzip
import json
import logging
import os
import random
import time
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin
from xml.sax.saxutils import escape

from config import QUERY_CONFIG
from d4s_client import Data4secClient

log = logging.getLogger(__name__)

HEADER_ALIASES = {
    "kear": "kear",
    "kear_id": "kear",
    "kearid": "kear",
    "uid": "uid",
    "program": "program",
    "programme": "program",
    "network": "network",
    "net": "network",
    "taken": "taken",
    "is_taken": "taken",
}


IMPACT_DEFAULT_PARAMS = {
    "ciLabel": "Application",
    "attributeName": "uid",
    "matchType": "equals",
    "direction": "to",
    "relationship": [
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
    ],
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
}


RETRY_STATUSES = {429, 500, 502, 503, 504}


def _response_error_details(status_code: int, body: str, max_len: int = 500) -> str:
    compact = " ".join(str(body or "").split())
    if len(compact) > max_len:
        compact = compact[:max_len] + "..."
    return f"HTTP {status_code} | response={compact or '<empty>'}"


def normalize_header_name(name: Optional[str]) -> str:
    if name is None:
        return ""
    normalized = str(name).replace("\ufeff", "").strip().lower()
    normalized = normalized.replace(" ", "_").replace("-", "_")
    while "__" in normalized:
        normalized = normalized.replace("__", "_")
    return HEADER_ALIASES.get(normalized, normalized)


def load_env_file(env_file: str = ".env") -> None:
    path = Path(env_file)
    if not path.is_file():
        return
    with open(path, "r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


def resolve_verify_ca() -> Any:
    """Resolve TLS verification strategy: VERIFY_CA > sg_cacert_file > default True."""
    value = os.getenv("VERIFY_CA")
    if value is not None and str(value).strip() != "":
        lowered = str(value).strip().lower()
        if lowered in {"true", "1", "yes", "on"}:
            return True
        if lowered in {"false", "0", "no", "off"}:
            return False
        return str(value).strip()

    try:
        from sg_cacert_file import get_cacert_path

        ca_path = get_cacert_path()
        log.info("Using CA bundle from sg_cacert_file: %s", ca_path)
        return ca_path
    except Exception:
        return True


def parse_positive_int(name: str, value: Optional[str]) -> Optional[int]:
    if value is None or str(value).strip() == "":
        return None
    parsed = int(value)
    if parsed <= 0:
        raise ValueError(f"{name} must be > 0")
    return parsed


def detect_csv_delimiter(csv_file: str, default: str = ",") -> str:
    with open(csv_file, "r", encoding="utf-8", newline="") as handle:
        sample = handle.read(4096)
    if not sample.strip():
        return default
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;")
        if dialect.delimiter in {",", ";"}:
            return dialect.delimiter
    except csv.Error:
        pass
    return ";" if sample.count(";") > sample.count(",") else default


class DaliImpactAnalysisClient:
    def __init__(self) -> None:
        self.base_url = (os.getenv("DALI_BASE_URL") or "").rstrip("/")
        self.token_url = (os.getenv("SGMARKET_TOKEN_URL") or "").strip()
        self.client_id = (os.getenv("SGCONNECT_CLIENT_ID") or "").strip()
        self.client_secret = (os.getenv("SGCONNECT_CLIENT_SECRET") or "").strip()
        self.scopes = (os.getenv("SGCONNECT_SCOPES") or "").strip()
        self.dali_client_id = (os.getenv("DALI_CLIENT_ID") or "").strip()
        self.dali_client_id_header = (os.getenv("DALI_CLIENT_ID_HEADER") or "x-client-id").strip()
        self.verify = resolve_verify_ca()
        self._token: Optional[str] = None
        self._token_expiry_epoch: float = 0.0

    def _validate_settings(self) -> None:
        missing = []
        for key, value in {
            "DALI_BASE_URL": self.base_url,
            "SGMARKET_TOKEN_URL": self.token_url,
            "SGCONNECT_CLIENT_ID": self.client_id,
            "SGCONNECT_CLIENT_SECRET": self.client_secret,
            "SGCONNECT_SCOPES": self.scopes,
        }.items():
            if not value:
                missing.append(key)
        if missing:
            raise ValueError(f"Missing DALI settings in .env: {', '.join(missing)}")

    def _basic_auth_header(self) -> str:
        raw = f"{self.client_id}:{self.client_secret}".encode("utf-8")
        return "Basic " + base64.b64encode(raw).decode("ascii")

    def fetch_sg_token(self) -> Tuple[str, int]:
        self._validate_settings()
        import requests

        headers = {
            "Authorization": self._basic_auth_header(),
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        payload = {
            "grant_type": "client_credentials",
            "scope": self.scopes,
        }
        response = requests.post(self.token_url, data=payload, headers=headers, timeout=30, verify=self.verify)
        response.raise_for_status()
        body = response.json()
        token = body.get("access_token")
        expires_in = int(body.get("expires_in", 3600))
        if not token:
            raise RuntimeError("No access_token found in OAuth2 response")
        return token, expires_in

    def get_bearer_token(self, force_refresh: bool = False) -> str:
        now = time.time()
        if not force_refresh and self._token and now < (self._token_expiry_epoch - 30):
            return self._token
        token, expires_in = self.fetch_sg_token()
        self._token = token
        self._token_expiry_epoch = now + max(60, expires_in)
        return token

    def dali_headers(self, force_refresh: bool = False) -> Dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.get_bearer_token(force_refresh=force_refresh)}",
        }
        if self.dali_client_id:
            headers[self.dali_client_id_header] = self.dali_client_id
        return headers

    def get_json(self, endpoint: str, params: Dict[str, Any], timeout_s: int = 60, retries: int = 4) -> Dict[str, Any]:
        import requests

        url = urljoin(f"{self.base_url}/", endpoint.lstrip("/"))
        last_exc: Optional[Exception] = None
        uid = params.get("attributeValue")

        for attempt in range(retries + 1):
            force_refresh = attempt > 0
            try:
                log.info(
                    "DALI GET request attempt=%s/%s url=%s params=%s",
                    attempt + 1,
                    retries + 1,
                    url,
                    params,
                )
                response = requests.get(
                    url,
                    params=params,
                    headers=self.dali_headers(force_refresh=force_refresh),
                    timeout=timeout_s,
                    verify=self.verify,
                )
                status_code = int(response.status_code)

                if status_code in {401, 403}:
                    self._token = None
                    self._token_expiry_epoch = 0
                    if attempt < retries:
                        continue

                if status_code in RETRY_STATUSES and attempt < retries:
                    delay = (2**attempt) + random.uniform(0, 0.5)
                    log.warning("DALI transient status=%s for uid=%s, retry in %.2fs", status_code, uid, delay)
                    time.sleep(delay)
                    continue

                if status_code >= 400:
                    details = _response_error_details(status_code=status_code, body=response.text)
                    raise RuntimeError(f"DALI request failed for uid={params.get('attributeValue')}: {details}")

                response.raise_for_status()
                payload = response.json()
                result_count = 0
                if isinstance(payload, dict):
                    result = payload.get("result")
                    if isinstance(result, list):
                        result_count = len(result)
                log.info(
                    "DALI GET response status=%s url=%s result_edges=%s count=%s",
                    status_code,
                    url,
                    result_count,
                    payload.get("count") if isinstance(payload, dict) else "n/a",
                )
                return payload
            except requests.HTTPError as exc:
                status_code = int(exc.response.status_code) if exc.response is not None else -1
                details = _response_error_details(
                    status_code=status_code,
                    body=exc.response.text if exc.response is not None else str(exc),
                )
                raise RuntimeError(f"DALI request failed for uid={uid}: {details}") from exc
            except requests.RequestException as exc:
                last_exc = exc
                if attempt < retries:
                    delay = (2**attempt) + random.uniform(0, 0.5)
                    log.warning(
                        "DALI request error for uid=%s on attempt %s/%s: %s; retry in %.2fs",
                        uid,
                        attempt + 1,
                        retries + 1,
                        exc,
                        delay,
                    )
                    time.sleep(delay)
                    continue
                break

        raise RuntimeError(f"DALI request failed after retries for uid={uid}: {last_exc}")


def read_headers_mapping(headers_file: str) -> List[Tuple[str, str]]:
    mappings: List[Tuple[str, str]] = []
    delimiter = detect_csv_delimiter(headers_file)
    log.info("Detected headers delimiter '%s' for %s", delimiter, headers_file)
    with open(headers_file, "r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle, delimiter=delimiter)
        for row in reader:
            display_name = str(row[0]).strip() if len(row) > 0 and row[0] else ""
            dali_attr = str(row[1]).strip() if len(row) > 1 and row[1] else ""
            if display_name and dali_attr:
                mappings.append((display_name, dali_attr))
    if not mappings:
        raise ValueError(f"No valid mappings found in {headers_file}")
    return mappings


def read_monitored_kears(monitored_file: str) -> List[Dict[str, str]]:
    delimiter = detect_csv_delimiter(monitored_file)
    log.info("Detected monitored_kears delimiter '%s' for %s", delimiter, monitored_file)
    with open(monitored_file, "r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, delimiter=delimiter)
        raw_headers = reader.fieldnames or []
        headers = [normalize_header_name(h) for h in raw_headers]
        required = ["program", "network", "taken"]
        missing = [col for col in required if col not in headers]
        if "kear" not in headers and "uid" not in headers:
            missing = ["kear_or_uid"] + missing
        if missing:
            raise ValueError(
                f"Missing required columns in {monitored_file}: {', '.join(missing)} | detected_headers={headers}"
            )

        rows: List[Dict[str, str]] = []
        for raw in reader:
            normalized: Dict[str, str] = {}
            for key, value in raw.items():
                normalized_key = normalize_header_name(key)
                normalized[normalized_key] = str(value).strip() if value is not None else ""
            uid = normalized.get("uid") or normalized.get("kear")
            if not uid:
                continue
            rows.append(
                {
                    "uid": uid,
                    "kear": normalized.get("kear", uid),
                    "program": normalized.get("program", ""),
                    "network": normalized.get("network", ""),
                    "taken": normalized.get("taken", ""),
                }
            )
    if not rows:
        raise ValueError(f"No monitored KEAR rows found in {monitored_file}")
    return rows


def read_filters_conf(filters_file: str) -> Dict[str, str]:
    filters: Dict[str, str] = {}
    with open(filters_file, "r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            if "=" in line:
                key, value = line.split("=", 1)
            elif "," in line:
                key, value = line.split(",", 1)
            else:
                log.warning("Ignoring invalid filter line (expected key=value or key,value): %s", line)
                continue

            key = key.strip()
            value = value.strip()
            if key:
                filters[key] = value
    return filters


def node_properties_to_dict(node: Any) -> Dict[str, Any]:
    if not isinstance(node, dict):
        return {}
    props = node.get("properties")
    if isinstance(props, dict):
        return props
    if not isinstance(props, list):
        return {}
    out: Dict[str, Any] = {}
    for p in props:
        if not isinstance(p, dict):
            continue
        name = p.get("name")
        if not name:
            continue
        out[str(name)] = p.get("value")
    return out


def _extract_server_uid_from_edge(edge: Dict[str, Any]) -> str:
    """Extract Server UID from nodes labeled `Server` in a DALI edge."""
    for node_key in ("leading_node", "trailing_node"):
        node = edge.get(node_key)
        if not isinstance(node, dict):
            continue
        labels = node.get("labels")
        normalized_labels = {str(label).strip().lower() for label in labels} if isinstance(labels, list) else set()
        if "server" not in normalized_labels:
            continue
        props = node_properties_to_dict(node)
        uid = props.get("uid")
        if uid is None:
            continue
        value = str(uid).strip()
        if value:
            return value
    return ""


def _normalize_cell_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(str(x) for x in value if str(x).strip())
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def _parse_filter_tokens(filters: Optional[Dict[str, str]], key: str) -> List[str]:
    if not filters:
        return []
    raw = filters.get(key)
    if raw is None:
        raw = filters.get(key.lower())
    if not raw:
        return []
    return [chunk.strip().upper() for chunk in raw.split(",") if chunk.strip()]


def _property_value_from_nodes(lead: Dict[str, Any], trail: Dict[str, Any], property_name: str) -> str:
    value = lead.get(property_name)
    if value is None or (isinstance(value, str) and not value.strip()):
        value = trail.get(property_name)
    return _normalize_cell_value(value)


def _contains_any_token(value: str, tokens: List[str]) -> bool:
    if not tokens:
        return False
    normalized = str(value or "").upper()
    return any(token in normalized for token in tokens)


def _matches_exact_token(value: str, tokens: List[str]) -> bool:
    if not tokens:
        return False
    normalized = str(value or "").upper().strip()
    if normalized in tokens:
        return True
    parts = [part.strip() for part in normalized.split(",") if part.strip()]
    return any(part in tokens for part in parts)

    os_tokens = _parse_filter_tokens(filters, "FILTER_OS_NAME")
    if os_tokens:
        os_name = _property_value_from_nodes(lead, trail, "os_name")
        if not _contains_any_token(os_name, os_tokens):
            return False

def _edge_matches_filters(lead: Dict[str, Any], trail: Dict[str, Any], filters: Optional[Dict[str, str]]) -> bool:
    env_tokens = _parse_filter_tokens(filters, "FILTER_PRD_ENV")
    if env_tokens:
        environment = _property_value_from_nodes(lead, trail, "environment")
        if not _contains_any_token(environment, env_tokens):
            return False

    os_tokens = _parse_filter_tokens(filters, "FILTER_OS_NAME")
    if os_tokens:
        os_name = _property_value_from_nodes(lead, trail, "os_name")
        if not _matches_exact_token(os_name, os_tokens):
            return False

    cloud_type_not_taken = _parse_filter_tokens(filters, "FILTER_CLOUD_TYPE_NOT_TAKEN")
    if cloud_type_not_taken:
        cloud_type = _property_value_from_nodes(lead, trail, "cloud_type")
        if _contains_any_token(cloud_type, cloud_type_not_taken):
            return False

    main_app_not_taken = _parse_filter_tokens(filters, "FILTER_MAIN_APP_NOT_TAKEN")
    if main_app_not_taken:
        main_application = _property_value_from_nodes(lead, trail, "main_application")
        if _contains_any_token(main_application, main_app_not_taken):
            return False

    typology_not_taken = _parse_filter_tokens(filters, "FILTER_TYPOLOGY_NOT_TAKEN")
    if typology_not_taken:
        typology = _property_value_from_nodes(lead, trail, "typology")
        if _contains_any_token(typology, typology_not_taken):
            return False

    return True


INVENTORY_HEADERS = [
    "INV_ocs_name",
    "INV_status",
    "INV_hostname",
    "Retrived from",
    "INV_Owner_Account",
    "INV_Beneficiary_Account",
]


def _normalize_lookup_value(value: Any) -> str:
    return str(value or "").strip().upper()


def _short_hostname(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    return raw.split(".", 1)[0].strip()


def _normalize_status(value: Any) -> str:
    return str(value or "").strip().upper()


def _inventory_hostid_from_server_uid(server_uid: Any) -> str:
    """Build inventory hostid key as VM_<SERVER_UID>."""
    normalized_uid = _normalize_lookup_value(server_uid)
    if not normalized_uid:
        return ""
    return f"VM_{normalized_uid}"


def _inventory_srn_from_server_uid(server_uid: Any) -> str:
    """Build canonical SRN prefix pattern from Server UID."""
    normalized_uid = _normalize_lookup_value(server_uid)
    if not normalized_uid:
        return ""
    return f"SRN:SGCP:VCS.EU-FR-PARIS:SERVER:{normalized_uid}"


def _normalize_column_key(value: str) -> str:
    return "".join(ch for ch in str(value or "").lower() if ch.isalnum())


def _get_row_value_by_candidates(row: Dict[str, Any], candidates: List[str]) -> str:
    normalized_candidates = {_normalize_column_key(name) for name in candidates}
    for key, value in row.items():
        if _normalize_column_key(key) in normalized_candidates:
            return str(value or "")
    return ""




def _lookup_variants(value: str) -> List[str]:
    raw = str(value or "").strip()
    if not raw:
        return []
    variants: List[str] = []
    short_raw = _short_hostname(raw)
    for candidate in (raw, short_raw, raw.upper(), raw.lower(), short_raw.upper(), short_raw.lower()):
        if candidate and candidate not in variants:
            variants.append(candidate)
    return variants

def _pick_inventory_row(docs: List[Dict[str, Any]], retrieved_from: str) -> Dict[str, str]:
    if not docs:
        return {}
    first = docs[0]
    return {
        "INV_ocs_name": _normalize_cell_value(first.get("ocs_name")),
        "INV_status": _normalize_status(first.get("status")),
        "INV_hostname": _short_hostname(_normalize_cell_value(first.get("hostname"))),
        "Retrived from": retrieved_from,
        "INV_Owner_Account": _normalize_cell_value(first.get("owner_app_name")),
        "INV_Beneficiary_Account": _normalize_cell_value(first.get("beneficiary")),
    }


def _deduplicate_docs(docs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    unique_docs: List[Dict[str, Any]] = []
    fingerprints = set()
    for doc in docs:
        fingerprint = json.dumps(doc, sort_keys=True, ensure_ascii=False)
        if fingerprint in fingerprints:
            continue
        fingerprints.add(fingerprint)
        unique_docs.append(doc)
    return unique_docs


def _inventory_search_by_field(client: Data4secClient, search_field: str, values: List[str]) -> Dict[str, List[Dict[str, Any]]]:
    """Centralized inventory search wrapper with consistent logging/filters."""
    cfg = QUERY_CONFIG["inventory"]
    log.info(
        "Inventory lookup start field=%s lookup_values=%s index=%s",
        search_field,
        len(values),
        cfg["index"],
    )
    result = client.bulk_search_multi(
        index_name=cfg["index"],
        search_field=search_field,
        values=values,
        source_fields=cfg["source_fields"],
        scroll_timeout=QUERY_CONFIG.get("scroll_timeout", "10m"),
        size=QUERY_CONFIG.get("batch_size", 500),
        term_filters=cfg.get("term_filters", {}),
    )
    non_empty = sum(1 for docs in result.values() if docs)
    total_docs = sum(len(docs) for docs in result.values())
    log.info(
        "Inventory lookup done field=%s matched_values=%s total_docs=%s",
        search_field,
        non_empty,
        total_docs,
    )
    return result


def query_inventory_for_server_uids(client: Data4secClient, server_uids: List[str]) -> Dict[str, Dict[str, str]]:
    """Resolve inventory rows from Server UID with hostid->srn fallback strategy."""
    uid_to_hostid: Dict[str, str] = {}
    uid_to_srn: Dict[str, str] = {}
    for server_uid in server_uids:
        normalized_uid = _normalize_lookup_value(server_uid)
        if not normalized_uid:
            continue
        uid_to_hostid[normalized_uid] = _inventory_hostid_from_server_uid(normalized_uid)
        uid_to_srn[normalized_uid] = _inventory_srn_from_server_uid(normalized_uid)

    if not uid_to_hostid:
        log.info("Inventory enrichment skipped: no Server UID values to query")
        return {}

    hostid_lookup_values = sorted(set(uid_to_hostid.values()))
    srn_lookup_values = sorted(set(uid_to_srn.values()))
    log.info(
        "Inventory Server UID enrichment prepared server_uids=%s hostid_lookup_values=%s srn_lookup_values=%s",
        len(uid_to_hostid),
        len(hostid_lookup_values),
        len(srn_lookup_values),
    )

    aggregated: Dict[str, List[Dict[str, Any]]] = {uid: [] for uid in uid_to_hostid.keys()}

    hostid_results = _inventory_search_by_field(client=client, search_field="hostid", values=hostid_lookup_values)
    for input_value, docs in hostid_results.items():
        normalized_value = _normalize_lookup_value(input_value)
        if not normalized_value or not docs:
            continue
        for uid, expected_hostid in uid_to_hostid.items():
            if normalized_value == _normalize_lookup_value(expected_hostid):
                aggregated[uid].extend(docs)

    missing_uids = [uid for uid, docs in aggregated.items() if not docs]
    if missing_uids:
        log.info("Inventory Server UID hostid retry without status filter missing_uids=%s", len(missing_uids))
        cfg = QUERY_CONFIG["inventory"]
        hostid_values_for_missing = [uid_to_hostid[uid] for uid in missing_uids if uid in uid_to_hostid]
        hostid_no_status_results = client.bulk_search_multi(
            index_name=cfg["index"],
            search_field="hostid",
            values=hostid_values_for_missing,
            source_fields=cfg["source_fields"],
            scroll_timeout=QUERY_CONFIG.get("scroll_timeout", "10m"),
            size=QUERY_CONFIG.get("batch_size", 500),
            term_filters={},
        )
        for input_value, docs in hostid_no_status_results.items():
            normalized_value = _normalize_lookup_value(input_value)
            if not normalized_value or not docs:
                continue
            for uid in missing_uids:
                expected_hostid = uid_to_hostid.get(uid, "")
                if normalized_value == _normalize_lookup_value(expected_hostid):
                    aggregated[uid].extend(docs)

    missing_uids = [uid for uid, docs in aggregated.items() if not docs]
    if missing_uids:
        log.info("Inventory Server UID enrichment fallback on srn missing_uids=%s", len(missing_uids))
        cfg = QUERY_CONFIG["inventory"]
        for uid in missing_uids:
            uid_token = _normalize_lookup_value(uid)
            if not uid_token:
                continue
            wildcard_value = f"*server:{uid_token}*"
            docs = client.search_by_wildcard(
                index_name=cfg["index"],
                search_field="srn",
                wildcard_value=wildcard_value,
                source_fields=cfg["source_fields"],
                scroll_timeout=QUERY_CONFIG.get("scroll_timeout", "10m"),
                size=QUERY_CONFIG.get("batch_size", 500),
                term_filters=cfg.get("term_filters", {}),
            )
            if not docs:
                log.info(
                    "SRN wildcard with status filter returned 0 for uid=%s, retrying without status filter",
                    uid,
                )
                docs = client.search_by_wildcard(
                    index_name=cfg["index"],
                    search_field="srn",
                    wildcard_value=wildcard_value,
                    source_fields=cfg["source_fields"],
                    scroll_timeout=QUERY_CONFIG.get("scroll_timeout", "10m"),
                    size=QUERY_CONFIG.get("batch_size", 500),
                    term_filters={},
                )
            if docs:
                aggregated[uid].extend(docs)

    output: Dict[str, Dict[str, str]] = {}
    matched = 0
    for uid, docs in aggregated.items():
        dedup_docs = _deduplicate_docs(docs)
        if dedup_docs:
            matched += 1
        output[uid] = _pick_inventory_row(dedup_docs, retrieved_from="Dali Export")
    log.info(
        "Inventory Server UID enrichment done matched_server_uids=%s total_server_uids=%s",
        matched,
        len(uid_to_hostid),
    )
    return output


def query_inventory_for_beneficiaries(client: Data4secClient, beneficiaries: List[str]) -> Dict[str, List[Dict[str, Any]]]:
    """Fetch inventory documents by beneficiary account list."""
    cfg = QUERY_CONFIG["inventory"]
    search_field = cfg.get("beneficiary_search_field", "beneficiary")
    lookup_values = [_normalize_lookup_value(value) for value in beneficiaries if _normalize_lookup_value(value)]
    if not lookup_values:
        log.info("Inventory beneficiary discovery skipped: no beneficiaries")
        return {}
    log.info("Inventory beneficiary discovery prepared beneficiaries=%s", len(lookup_values))

    result_map = _inventory_search_by_field(client=client, search_field=search_field, values=lookup_values)
    out: Dict[str, List[Dict[str, Any]]] = {}
    for key, docs in result_map.items():
        normalized_key = _normalize_lookup_value(key)
        if not normalized_key or not docs:
            continue
        out.setdefault(normalized_key, []).extend(docs)

    deduped = {key: _deduplicate_docs(value) for key, value in out.items()}
    log.info(
        "Inventory beneficiary discovery done matched_beneficiaries=%s total_docs=%s",
        len(deduped),
        sum(len(v) for v in deduped.values()),
    )
    return deduped


def _extract_monitored_app_links_from_dali(response: Dict[str, Any], monitored_uids: set[str]) -> List[Dict[str, Any]]:
    """Keep DALI edges whose trailing application UID is in monitored scope."""
    rows: List[Dict[str, Any]] = []
    result = response.get("result") if isinstance(response, dict) else None
    edges = [edge for edge in (result or []) if isinstance(edge, dict)] if isinstance(result, list) else []

    log.info("DALI application-link extraction from additional lookup edges=%s", len(edges))
    for edge in edges:
        leading_props = node_properties_to_dict(edge.get("leading_node"))
        trailing_props = node_properties_to_dict(edge.get("trailing_node"))

        app_uid = str(trailing_props.get("uid") or "").strip()
        if not app_uid or app_uid not in monitored_uids:
            continue

        server_hostname = _normalize_cell_value(leading_props.get("hostname")) or _normalize_cell_value(trailing_props.get("hostname"))
        server_cloud_type = _normalize_cell_value(leading_props.get("cloud_type")) or _normalize_cell_value(trailing_props.get("cloud_type"))

        rows.append(
            {
                "uid": app_uid,
                "hostname": server_hostname,
                "cloud_type": server_cloud_type,
            }
        )

    log.info("DALI application-link extraction kept_rows=%s (monitored application uids)", len(rows))
    return rows


def discover_additional_servers_from_inventory_accounts(
    # Beneficiary-driven expansion: inventory -> DALI -> monitored UID filtering
    client: DaliImpactAnalysisClient,
    d4s_client: Data4secClient,
    filtered_rows: List[Dict[str, Any]],
    monitored_uids: set[str],
    impact_endpoint: str,
    limit: Optional[int],
    depth_until: Optional[int],
    inventory_by_account_rows: Optional[List[Dict[str, Any]]] = None,
    dali_by_ocsname_rows: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    beneficiary_values = {
        _normalize_lookup_value(row.get("INV_Beneficiary_Account", ""))
        for row in filtered_rows
        if str(row.get("INV_Beneficiary_Account", "")).strip() not in {"", "NOT_FOUND", "NOT_GEN2"}
    }
    if not beneficiary_values:
        log.info("Additional inventory-account discovery skipped: no beneficiary account available")
        return []
    log.info("Additional inventory-account discovery start distinct_beneficiaries=%s", len(beneficiary_values))

    inventory_by_beneficiary = query_inventory_for_beneficiaries(d4s_client, sorted(beneficiary_values))
    inventory_docs: List[Dict[str, Any]] = []
    for beneficiary, docs in inventory_by_beneficiary.items():
        for doc in docs:
            if inventory_by_account_rows is not None:
                inventory_by_account_rows.append(
                    {
                        "beneficiary": beneficiary,
                        "ocs_name": _normalize_cell_value(doc.get("ocs_name")),
                        "hostname": _short_hostname(_normalize_cell_value(doc.get("hostname"))),
                        "status": _normalize_status(doc.get("status")),
                        "owner_app_name": _normalize_cell_value(doc.get("owner_app_name")),
                    }
                )
        inventory_docs.extend(docs)
    inventory_docs = _deduplicate_docs(inventory_docs)
    log.info("Additional inventory-account discovery inventory_docs=%s", len(inventory_docs))

    discovered_rows: List[Dict[str, Any]] = []
    seen_uids = {str(row.get("uid", "")).strip() for row in filtered_rows}

    for idx, doc in enumerate(inventory_docs, start=1):
        ocs_name = str(doc.get("ocs_name") or "").strip()
        log.info("Additional DALI lookup %s/%s ocs_name=%s", idx, len(inventory_docs), ocs_name)
        if not ocs_name:
            continue

        params = build_impact_params(uid=ocs_name, limit=limit, depth_until=depth_until)
        params["ciLabel"] = "Server"
        params["attributeName"] = "hostname"
        params["attributeValue"] = ocs_name
        params["direction"] = "from"
        params["impactedCis"] = "Application"
        params["reliability"] = "true"
        params["boost"] = "true"
        params["relationship"] = IMPACT_DEFAULT_PARAMS["relationship"] + [
            "ORG_CONTAINED_BY",
            "BELONG_TO_NETWORK",
            "CONTAINS",
        ]

        try:
            response = client.get_json(endpoint=impact_endpoint, params=params)
        except Exception as exc:
            if dali_by_ocsname_rows is not None:
                dali_by_ocsname_rows.append(
                    {
                        "ocs_name": ocs_name,
                        "edge_index": "",
                        "node_type": "ERROR",
                        "node_uid": "",
                        "node_hostname": "",
                        "node_cloud_type": "",
                        "uid_in_monitored_list": "",
                        "response_count": "",
                        "error": str(exc),
                    }
                )
            log.warning("Additional DALI lookup failed for hostname=%s: %s", ocs_name, exc)
            continue

        result_edges = response.get("result") if isinstance(response, dict) else []
        if not isinstance(result_edges, list):
            result_edges = []
        for edge_idx, edge in enumerate(result_edges, start=1):
            if not isinstance(edge, dict):
                continue
            leading_props = node_properties_to_dict(edge.get("leading_node"))
            trailing_props = node_properties_to_dict(edge.get("trailing_node"))
            trailing_uid = str(trailing_props.get("uid") or "").strip()
            if dali_by_ocsname_rows is not None:
                dali_by_ocsname_rows.append(
                    {
                        "ocs_name": ocs_name,
                        "edge_index": edge_idx,
                        "server_hostname": _normalize_cell_value(leading_props.get("hostname")) or _normalize_cell_value(trailing_props.get("hostname")),
                        "server_cloud_type": _normalize_cell_value(leading_props.get("cloud_type")) or _normalize_cell_value(trailing_props.get("cloud_type")),
                        "trailing_application_uid": trailing_uid,
                        "trailing_uid_in_monitored_list": "YES" if trailing_uid in monitored_uids else "NO",
                        "response_count": response.get("count", 0),
                    }
                )

        dali_servers = _extract_monitored_app_links_from_dali(response=response, monitored_uids=monitored_uids)
        log.info("Additional DALI lookup ocs_name=%s matching_application_links=%s", ocs_name, len(dali_servers))
        for server in dali_servers:
            uid = server.get("uid", "")
            if not uid or uid in seen_uids:
                continue

            discovered_rows.append(
                {
                    "uid": uid,
                    "program": "",
                    "network": "",
                    "taken": "",
                    "lookup_status": "FOUND",
                    "count": response.get("count", 0),
                    "error": "",
                    "hostname": server.get("hostname", ""),
                    "cloud_type": server.get("cloud_type", ""),
                    "INV_ocs_name": _normalize_cell_value(doc.get("ocs_name")),
                    "INV_status": _normalize_status(doc.get("status")),
                    "INV_hostname": _short_hostname(_normalize_cell_value(doc.get("hostname"))),
                    "Retrived from": "From inventory account",
                    "INV_Owner_Account": _normalize_cell_value(doc.get("owner_app_name")),
                    "INV_Beneficiary_Account": _normalize_cell_value(doc.get("beneficiary")),
                }
            )
            seen_uids.add(uid)

    log.info("Additional inventory-account discovery done appended_rows=%s", len(discovered_rows))
    return discovered_rows


def enrich_filtered_rows_with_inventory(
    # Main enrichment path for FILTRED: Gen2 inventory + optional discovered rows
    filtered_rows: List[Dict[str, Any]],
    client: DaliImpactAnalysisClient,
    impact_endpoint: str,
    limit: Optional[int],
    depth_until: Optional[int],
    monitored_uids: set[str],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    server_uids_to_query: List[str] = []
    row_contexts: List[Tuple[Dict[str, Any], str, str]] = []
    d4s_client = Data4secClient()
    log.info("Inventory enrichment start filtered_rows=%s monitored_uids=%s", len(filtered_rows), len(monitored_uids))

    for row in filtered_rows:
        cloud_type = _get_row_value_by_candidates(row, ["cloud_type", "server_cloud_type"])
        server_uid = _get_row_value_by_candidates(row, ["server_uid", "server uid", "Server UID"])
        row_contexts.append((row, cloud_type, server_uid))

        is_gen2 = _normalize_lookup_value(cloud_type) == "GEN 2"
        if is_gen2 and _normalize_lookup_value(server_uid):
            server_uids_to_query.append(server_uid)

    inventory_map = query_inventory_for_server_uids(client=d4s_client, server_uids=server_uids_to_query)

    for row, cloud_type, server_uid in row_contexts:
        is_gen2 = _normalize_lookup_value(cloud_type) == "GEN 2"
        if not is_gen2:
            for column in INVENTORY_HEADERS:
                row[column] = "NOT_GEN2"
            continue

        normalized_server_uid = _normalize_lookup_value(server_uid)
        inventory_row = inventory_map.get(normalized_server_uid, {}) if normalized_server_uid else {}

        if not inventory_row:
            row["INV_ocs_name"] = "NOT_FOUND"
            row["INV_status"] = "NOT_FOUND"
            row["INV_hostname"] = "NOT_FOUND"
            row["Retrived from"] = "NOT_FOUND"
            row["INV_Owner_Account"] = "NOT_FOUND"
            row["INV_Beneficiary_Account"] = "NOT_FOUND"
            continue

        for column in INVENTORY_HEADERS:
            row[column] = inventory_row.get(column, "")

    inventory_by_account_rows: List[Dict[str, Any]] = []
    dali_by_ocsname_rows: List[Dict[str, Any]] = []

    discovered_rows = discover_additional_servers_from_inventory_accounts(
        client=client,
        d4s_client=d4s_client,
        filtered_rows=filtered_rows,
        monitored_uids=monitored_uids,
        impact_endpoint=impact_endpoint,
        limit=limit,
        depth_until=depth_until,
        inventory_by_account_rows=inventory_by_account_rows,
        dali_by_ocsname_rows=dali_by_ocsname_rows,
    )
    filtered_rows.extend(discovered_rows)
    log.info(
        "Inventory enrichment done base_rows=%s discovered_rows=%s total_rows=%s",
        len(row_contexts),
        len(discovered_rows),
        len(filtered_rows),
    )
    return filtered_rows, inventory_by_account_rows, dali_by_ocsname_rows


def extract_rows_from_response(
    response: Dict[str, Any],
    base_row: Dict[str, Any],
    mappings: List[Tuple[str, str]],
    err_text: str,
    filters: Optional[Dict[str, str]] = None,
    apply_filters: bool = True,
) -> List[Dict[str, Any]]:
    if err_text:
        row = dict(base_row)
        row.update({
            "lookup_status": "ERROR",
            "count": 0,
            "error": err_text,
        })
        for display_name, _ in mappings:
            row[display_name] = ""
        return [row]

    result = response.get("result") if isinstance(response, dict) else None
    edges = [edge for edge in (result or []) if isinstance(edge, dict)] if isinstance(result, list) else []
    count_value = response.get("count", 0) if isinstance(response, dict) else 0

    if not edges:
        row = dict(base_row)
        row.update({
            "lookup_status": "NOT_FOUND",
            "count": count_value,
            "error": "",
        })
        for display_name, _ in mappings:
            row[display_name] = ""
        return [row]

    out_rows: List[Dict[str, Any]] = []
    for edge in edges:
        lead = node_properties_to_dict(edge.get("leading_node"))
        trail = node_properties_to_dict(edge.get("trailing_node"))
        row = dict(base_row)
        row["Server UID"] = _extract_server_uid_from_edge(edge)
        row.update({
            "lookup_status": "FOUND",
            "count": count_value,
            "error": "",
        })
        for display_name, dali_attr in mappings:
            raw_value = lead.get(dali_attr)
            if raw_value is None or (isinstance(raw_value, str) and not raw_value.strip()):
                raw_value = trail.get(dali_attr)
            if raw_value is None and dali_attr.lower() in {"uid", "application_uid", "app_uid"}:
                raw_value = base_row.get("uid", "")
            row[display_name] = _normalize_cell_value(raw_value)
        if (not apply_filters) or _edge_matches_filters(lead=lead, trail=trail, filters=filters):
            out_rows.append(row)
    return out_rows


def write_output_csv(
    output_file: str,
    rows: List[Dict[str, Any]],
    mappings: List[Tuple[str, str]],
    extra_fieldnames: Optional[List[str]] = None,
) -> None:
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["uid", "program", "network", "taken", "Server UID"] + [display for display, _ in mappings] + (extra_fieldnames or [])
    with open(output_file, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _xlsx_col_ref(index: int) -> str:
    ref = ""
    idx = index + 1
    while idx > 0:
        idx, rem = divmod(idx - 1, 26)
        ref = chr(65 + rem) + ref
    return ref


def _compute_col_widths(rows: List[List[str]], min_width: float = 10.0, max_width: float = 60.0) -> List[float]:
    if not rows:
        return []
    max_cols = max(len(row) for row in rows)
    widths: List[float] = []
    for col_idx in range(max_cols):
        max_len = 0
        for row in rows:
            value = row[col_idx] if col_idx < len(row) else ""
            max_len = max(max_len, len(str(value or "")))
        widths.append(min(max_width, max(min_width, float(max_len + 2))))
    return widths


def _xlsx_cols_xml(widths: List[float]) -> str:
    if not widths:
        return ""
    cols = []
    for idx, width in enumerate(widths, start=1):
        cols.append(f'<col min="{idx}" max="{idx}" width="{width:.2f}" customWidth="1"/>')
    return '<cols>' + ''.join(cols) + '</cols>'


def _xlsx_autofilter_xml(row_count: int, col_count: int) -> str:
    if col_count <= 0:
        return ""
    start_ref = "A1"
    end_ref = f"{_xlsx_col_ref(col_count - 1)}{max(1, row_count + 1)}"
    return f'<autoFilter ref="{start_ref}:{end_ref}"/>'


def _xlsx_sheet_xml_table(rows: List[Dict[str, Any]], fieldnames: List[str]) -> str:
    matrix: List[List[str]] = [fieldnames]
    for row in rows:
        matrix.append([str(row.get(field, "") or "") for field in fieldnames])

    sheet_rows: List[str] = []
    for row_idx, row_values in enumerate(matrix, start=1):
        cells: List[str] = []
        style_id = "1" if row_idx == 1 else "0"
        for col_idx, value in enumerate(row_values):
            col_ref = _xlsx_col_ref(col_idx)
            escaped_value = escape(value)
            cells.append(f'<c r="{col_ref}{row_idx}" s="{style_id}" t="inlineStr"><is><t>{escaped_value}</t></is></c>')
        sheet_rows.append(f'<row r="{row_idx}">' + ''.join(cells) + '</row>')

    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        + _xlsx_cols_xml(_compute_col_widths(matrix))
        + '<sheetData>' + ''.join(sheet_rows) + '</sheetData>'
        + _xlsx_autofilter_xml(row_count=len(rows), col_count=len(fieldnames))
        + '</worksheet>'
    )


def _xlsx_sheet_xml_summary(summary_rows: List[Tuple[str, str]]) -> str:
    matrix = [[left, right] for left, right in summary_rows]
    sheet_rows: List[str] = []
    for row_idx, (left, right) in enumerate(matrix, start=1):
        is_section = str(left).strip().startswith("Section ")
        style_id = "2" if is_section else "0"
        cells = [
            f'<c r="A{row_idx}" s="{style_id}" t="inlineStr"><is><t>{escape(str(left or ""))}</t></is></c>',
            f'<c r="B{row_idx}" s="{style_id}" t="inlineStr"><is><t>{escape(str(right or ""))}</t></is></c>',
        ]
        sheet_rows.append(f'<row r="{row_idx}">' + ''.join(cells) + '</row>')

    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        + _xlsx_cols_xml(_compute_col_widths(matrix))
        + '<sheetData>' + ''.join(sheet_rows) + '</sheetData>'
        + '</worksheet>'
    )


def _fieldnames_for_rows(rows: List[Dict[str, Any]]) -> List[str]:
    ordered: List[str] = []
    seen = set()
    for row in rows:
        for key in row.keys():
            if key not in seen:
                seen.add(key)
                ordered.append(key)
    return ordered


def write_output_xlsx(
    # Dynamic XLSX writer supporting optional diagnostic sheets
    output_file: str,
    raw_rows: List[Dict[str, Any]],
    filtered_rows: List[Dict[str, Any]],
    mappings: List[Tuple[str, str]],
    summary_rows: List[Tuple[str, str]],
    filtered_extra_fieldnames: Optional[List[str]] = None,
    extra_sheets: Optional[List[Tuple[str, List[Dict[str, Any]], Optional[List[str]]]]] = None,
) -> None:
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    raw_fieldnames = ["uid", "program", "network", "taken", "Server UID"] + [display for display, _ in mappings]
    filtered_fieldnames = raw_fieldnames + (filtered_extra_fieldnames or [])

    sheets: List[Tuple[str, str, Optional[List[Dict[str, Any]]], Optional[List[str]]]] = [
        ("Summary", "summary", None, None),
        ("RAW", "table", raw_rows, raw_fieldnames),
        ("FILTRED", "table", filtered_rows, filtered_fieldnames),
    ]
    for name, rows, fieldnames in (extra_sheets or []):
        effective_fields = fieldnames or _fieldnames_for_rows(rows)
        sheets.append((name, "table", rows, effective_fields))

    content_types_parts = [
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">',
        '  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>',
        '  <Default Extension="xml" ContentType="application/xml"/>',
        '  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>',
        '  <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>',
    ]
    for idx in range(1, len(sheets) + 1):
        content_types_parts.append(
            f'  <Override PartName="/xl/worksheets/sheet{idx}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        )
    content_types_parts.append('</Types>')
    content_types = "\n".join(content_types_parts)

    rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>'''

    workbook_parts = [
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">',
        '  <sheets>',
    ]
    for idx, (sheet_name, _, _, _) in enumerate(sheets, start=1):
        workbook_parts.append(f'    <sheet name="{escape(sheet_name)}" sheetId="{idx}" r:id="rId{idx}"/>')
    workbook_parts.extend(['  </sheets>', '</workbook>'])
    workbook = "\n".join(workbook_parts)

    workbook_rels_parts = [
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">',
    ]
    for idx in range(1, len(sheets) + 1):
        workbook_rels_parts.append(
            f'  <Relationship Id="rId{idx}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{idx}.xml"/>'
        )
    workbook_rels_parts.append(
        f'  <Relationship Id="rId{len(sheets) + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>'
    )
    workbook_rels_parts.append('</Relationships>')
    workbook_rels = "\n".join(workbook_rels_parts)

    styles = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <fonts count="2">
    <font><sz val="11"/><name val="Calibri"/></font>
    <font><b/><sz val="11"/><name val="Calibri"/></font>
  </fonts>
  <fills count="3">
    <fill><patternFill patternType="none"/></fill>
    <fill><patternFill patternType="gray125"/></fill>
    <fill><patternFill patternType="solid"><fgColor rgb="FFD9E1F2"/><bgColor indexed="64"/></patternFill></fill>
  </fills>
  <borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>
  <cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
  <cellXfs count="3">
    <xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
    <xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/>
    <xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/>
  </cellXfs>
  <cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
</styleSheet>'''

    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", rels)
        zf.writestr("xl/workbook.xml", workbook)
        zf.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
        zf.writestr("xl/styles.xml", styles)

        for idx, (_, sheet_kind, rows, fieldnames) in enumerate(sheets, start=1):
            if sheet_kind == "summary":
                xml = _xlsx_sheet_xml_summary(summary_rows)
            else:
                xml = _xlsx_sheet_xml_table(rows or [], fieldnames or [])
            zf.writestr(f"xl/worksheets/sheet{idx}.xml", xml)


def write_output_json(output_file: str, payload: Dict[str, Any]) -> str:
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    json_text = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"

    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(json_text)

    gz_path = output_path if output_path.suffix == ".gz" else output_path.with_suffix(output_path.suffix + ".gz")
    with gzip.open(gz_path, "wt", encoding="utf-8") as handle:
        handle.write(json_text)

    output_path.unlink(missing_ok=True)
    return str(gz_path)


def build_impact_params(uid: str, limit: Optional[int], depth_until: Optional[int]) -> Dict[str, Any]:
    params = dict(IMPACT_DEFAULT_PARAMS)
    params["attributeValue"] = uid
    params["limit"] = str(limit if limit is not None else 10000)
    params["depthUntil"] = str(depth_until if depth_until is not None else 8)
    return params


def run_impact_analysis(
    # Batch DALI extraction for monitored application UIDs/KEARs
    client: DaliImpactAnalysisClient,
    monitored_rows: List[Dict[str, str]],
    mappings: List[Tuple[str, str]],
    impact_endpoint: str,
    limit: Optional[int],
    depth_until: Optional[int],
    sleep_ms: int,
    dry_run: bool,
    filters: Optional[Dict[str, str]] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    errors: List[Dict[str, str]] = []
    raw_rows: List[Dict[str, Any]] = []
    filtered_rows: List[Dict[str, Any]] = []

    total = len(monitored_rows)
    job_started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    for idx, row in enumerate(monitored_rows, start=1):
        uid = row["uid"]
        log.info("[%s/%s] uid=%s", idx, total, uid)
        response: Dict[str, Any] = {}
        err_text = ""

        if dry_run:
            response = {"count": 0, "result": []}
        else:
            try:
                params = build_impact_params(uid=uid, limit=limit, depth_until=depth_until)
                response = client.get_json(endpoint=impact_endpoint, params=params)
            except Exception as exc:  # continue batch on error
                err_text = str(exc)
                log.warning("Impact analysis failed for uid=%s: %s", uid, err_text)
                errors.append({"uid": uid, "error": err_text})
                response = {}

        items.append({"uid": uid, "response": response})

        base_row = {
            "uid": uid,
            "kear": row.get("kear", uid),
            "program": row.get("program", ""),
            "network": row.get("network", ""),
            "taken": row.get("taken", ""),
            "Server UID": "",
        }
        raw_rows.extend(
            extract_rows_from_response(response=response, base_row=base_row, mappings=mappings, err_text=err_text, filters=filters, apply_filters=False)
        )
        filtered_rows.extend(
            extract_rows_from_response(response=response, base_row=base_row, mappings=mappings, err_text=err_text, filters=filters, apply_filters=True)
        )

        if sleep_ms > 0:
            time.sleep(sleep_ms / 1000.0)

    success_count = len(monitored_rows) - len(errors)
    found_count = sum(1 for item in items if isinstance(item.get("response"), dict) and int(item.get("response", {}).get("count", 0) or 0) > 0)
    job_end_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    payload = {
        "meta": {
            "generated_at": job_end_at,
            "job_started_at": job_started_at,
            "job_end_at": job_end_at,
            "dali_base_url": client.base_url,
            "endpoint": impact_endpoint,
            "uid_count": len(monitored_rows),
            "success_count": success_count,
            "found_count": found_count,
            "error_count": len(errors),
            "depth_until": depth_until,
            "limit": limit,
            "dry_run": dry_run,
        },
        "items": items,
        "errors": errors,
    }
    return raw_rows, filtered_rows, payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Batch DALI impact analysis for monitored UIDs/KEARs.")
    parser.add_argument("--monitored-file", default="user_inputs/monitored_kears.csv", help="Path to monitored_kears.csv")
    parser.add_argument("--input", dest="monitored_file", help="Compatibility alias for --monitored-file")
    parser.add_argument("--headers-file", default="user_inputs/headers.csv", help="Path to headers.csv")
    parser.add_argument("--headers-xlsx", dest="headers_file", help="Compatibility alias for --headers-file")
    parser.add_argument("--headers-sheet", help="Compatibility option for legacy command (ignored in CSV mode)")
    parser.add_argument("--excel", action="store_true", help="Compatibility option for legacy command (ignored in CSV mode)")
    parser.add_argument("--filters-file", default="user_inputs/filters.conf", help="Path to filters.conf (key,value)")
    parser.add_argument("--output", default="RUNS/dali_impact_analysis.xlsx", help="Output XLSX path (sheets RAW and FILTRED)")
    parser.add_argument("--json-out", default="RUNS/dali_impact_analysis.json", help="Output JSON path")
    parser.add_argument(
        "--impact-endpoint",
        default=os.getenv("DALI_IMPACT_ENDPOINT") or "/api/v1/impactAnalysis",
        help="DALI impact analysis endpoint path",
    )
    parser.add_argument("--depth-until", type=int, default=parse_positive_int("DALI_DEPTH_UNTIL", os.getenv("DALI_DEPTH_UNTIL")))
    parser.add_argument("--limit", type=int, default=parse_positive_int("DALI_LIMIT", os.getenv("DALI_LIMIT")))
    parser.add_argument("--sleep-ms", type=int, default=0, help="Sleep between UID calls in milliseconds")
    parser.add_argument("--dry-run", action="store_true", help="Do not call DALI API; generate empty responses")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")

    args = parser.parse_args()
    args.depth_until = parse_positive_int("--depth-until", str(args.depth_until) if args.depth_until is not None else None)
    args.limit = parse_positive_int("--limit", str(args.limit) if args.limit is not None else None)
    if args.sleep_ms < 0:
        raise ValueError("--sleep-ms must be >= 0")
    return args


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")


def main() -> None:
    """CLI entrypoint: extract, enrich, then write CSV/XLSX/JSON outputs."""
    load_env_file()
    args = parse_args()
    setup_logging(args.verbose)

    if args.excel:
        log.info("--excel compatibility flag detected (CSV mode used).")
    if args.headers_sheet:
        log.info("--headers-sheet=%s ignored in CSV mode.", args.headers_sheet)

    mappings = read_headers_mapping(args.headers_file)
    monitored_rows = read_monitored_kears(args.monitored_file)
    filters = read_filters_conf(args.filters_file) if Path(args.filters_file).is_file() else {}

    client = DaliImpactAnalysisClient()
    raw_rows, filtered_rows, json_payload = run_impact_analysis(
        client=client,
        monitored_rows=monitored_rows,
        mappings=mappings,
        impact_endpoint=args.impact_endpoint,
        limit=args.limit,
        depth_until=args.depth_until,
        sleep_ms=args.sleep_ms,
        dry_run=args.dry_run,
        filters=filters,
    )

    monitored_uids = {str(row.get("uid", "")).strip() for row in monitored_rows if str(row.get("uid", "")).strip()}
    filtered_rows, inv_by_account_rows, dali_by_ocsname_rows = enrich_filtered_rows_with_inventory(
        filtered_rows=filtered_rows,
        client=client,
        impact_endpoint=args.impact_endpoint,
        limit=args.limit,
        depth_until=args.depth_until,
        monitored_uids=monitored_uids,
    )

    output_xlsx = Path(args.output)
    raw_csv_path = output_xlsx.with_name(output_xlsx.stem + "_RAW.csv")
    filtered_csv_path = output_xlsx.with_name(output_xlsx.stem + "_FILTRED.csv")
    write_output_csv(str(raw_csv_path), raw_rows, mappings)
    write_output_csv(str(filtered_csv_path), filtered_rows, mappings, extra_fieldnames=INVENTORY_HEADERS)

    now_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    started_at = json_payload.get("meta", {}).get("job_started_at", now_utc)
    ended_at = json_payload.get("meta", {}).get("job_end_at", now_utc)
    error_count = int(json_payload.get("meta", {}).get("error_count", 0) or 0)
    execution_status = "SUCCESS" if error_count == 0 else "FAIL"
    summary_rows: List[Tuple[str, str]] = [
        ("Section 1 : Execution Report", ""),
        ("Report date", now_utc),
        ("Job Started at", started_at),
        ("Job End at", ended_at),
        ("Execution Report", execution_status),
        ("", ""),
        ("Section 2 : Applied filters", ""),
    ]
    if filters:
        for key, value in sorted(filters.items()):
            summary_rows.append((key, value))
    else:
        summary_rows.append(("No filter", "<none>"))

    gen2_rows = [row for row in filtered_rows if _normalize_lookup_value(_get_row_value_by_candidates(row, ["cloud_type", "server_cloud_type"])) == "GEN 2"]
    inventory_found_rows = [
        row
        for row in gen2_rows
        if str(row.get("INV_ocs_name", "")).strip() not in {"", "NOT_FOUND", "NOT_GEN2"}
    ]

    summary_rows.extend(
        [
            ("", ""),
            ("Section 3 : Dali Report", ""),
            ("Number of processed kears", str(len(monitored_rows))),
            ("Total assets get from Dali", str(len(raw_rows))),
            ("Total assets after filtering", str(len(filtered_rows))),
            ("", ""),
            ("Section 4 : Data4sec/inventory report", ""),
            ("Number of processed GEN 2 servers", str(len(gen2_rows))),
            ("Number of assets found in inventory", str(len(inventory_found_rows))),
        ]
    )

    write_output_xlsx(
        str(output_xlsx),
        raw_rows,
        filtered_rows,
        mappings,
        summary_rows,
        filtered_extra_fieldnames=INVENTORY_HEADERS,
        extra_sheets=[
            ("get_inv_by_account", inv_by_account_rows, None),
            ("get_dali_by_ocsname", dali_by_ocsname_rows, None),
        ],
    )
    json_gz_path = write_output_json(args.json_out, json_payload)

    print(f"Monitored rows: {len(monitored_rows)}")
    print(f"Header mappings: {len(mappings)}")
    print(f"Custom filters loaded: {len(filters)}")
    print(f"Impact endpoint: {args.impact_endpoint}")
    print(f"Depth until: {args.depth_until}")
    print(f"Limit: {args.limit}")
    print(f"Errors: {len(json_payload.get('errors', []))}")
    print(f"RAW CSV written to: {raw_csv_path}")
    print(f"FILTRED CSV written to: {filtered_csv_path}")
    print(f"XLSX written to: {output_xlsx}")
    print(f"JSON.GZ written to: {json_gz_path}")


if __name__ == "__main__":
    main()
