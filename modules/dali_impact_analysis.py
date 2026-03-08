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
                return response.json()
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


INVENTORY_HEADERS = ["INV_ocs_name", "INV_hostname", "INV_Beneficiary_Account"]


def _normalize_lookup_value(value: Any) -> str:
    return str(value or "").strip().upper()


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
    for candidate in (raw, raw.upper(), raw.lower()):
        if candidate and candidate not in variants:
            variants.append(candidate)
    return variants

def _pick_inventory_row(docs: List[Dict[str, Any]]) -> Dict[str, str]:
    if not docs:
        return {}
    first = docs[0]
    return {
        "INV_ocs_name": _normalize_cell_value(first.get("ocs_name")),
        "INV_hostname": _normalize_cell_value(first.get("hostname")),
        "INV_Beneficiary_Account": _normalize_cell_value(first.get("beneficiary")),
    }


def query_inventory_for_hostnames(hostnames: List[str]) -> Dict[str, Dict[str, str]]:
    canonical_hostnames: List[str] = []
    seen_canonical = set()
    variant_to_canonical: Dict[str, str] = {}

    for hostname in hostnames:
        canonical = _normalize_lookup_value(hostname)
        if not canonical:
            continue
        if canonical not in seen_canonical:
            seen_canonical.add(canonical)
            canonical_hostnames.append(canonical)

        for variant in _lookup_variants(hostname):
            variant_to_canonical[variant] = canonical

    if not canonical_hostnames:
        return {}

    lookup_values = list(variant_to_canonical.keys())

    cfg = QUERY_CONFIG["inventory"]
    client = Data4secClient()
    aggregated: Dict[str, List[Dict[str, Any]]] = {value: [] for value in canonical_hostnames}

    for search_field in cfg["search_fields"]:
        result_map = client.bulk_search_multi(
            index_name=cfg["index"],
            search_field=search_field,
            values=lookup_values,
            source_fields=cfg["source_fields"],
            scroll_timeout=QUERY_CONFIG.get("scroll_timeout", "10m"),
            size=QUERY_CONFIG.get("batch_size", 500),
            term_filters=cfg.get("term_filters", {}),
        )
        for input_value, docs in result_map.items():
            if not docs:
                continue
            canonical = variant_to_canonical.get(input_value, _normalize_lookup_value(input_value))
            aggregated.setdefault(canonical, []).extend(docs)

    output: Dict[str, Dict[str, str]] = {}
    for hostname, docs in aggregated.items():
        unique_docs = []
        fingerprints = set()
        for doc in docs:
            fingerprint = json.dumps(doc, sort_keys=True, ensure_ascii=False)
            if fingerprint in fingerprints:
                continue
            fingerprints.add(fingerprint)
            unique_docs.append(doc)
        output[hostname] = _pick_inventory_row(unique_docs)
    return output


def enrich_filtered_rows_with_inventory(filtered_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    hostnames_to_lookup: List[str] = []
    row_contexts: List[Tuple[Dict[str, Any], str, str]] = []

    for row in filtered_rows:
        cloud_type = _get_row_value_by_candidates(row, ["cloud_type", "server_cloud_type"])
        hostname = _get_row_value_by_candidates(row, ["hostname", "server_hostname", "host_name"])
        row_contexts.append((row, cloud_type, hostname))

        is_gen2 = _normalize_lookup_value(cloud_type) == "GEN 2"
        if is_gen2 and _normalize_lookup_value(hostname):
            hostnames_to_lookup.append(hostname)

    inventory_map = query_inventory_for_hostnames(hostnames_to_lookup)

    for row, cloud_type, hostname in row_contexts:
        is_gen2 = _normalize_lookup_value(cloud_type) == "GEN 2"
        if not is_gen2:
            for column in INVENTORY_HEADERS:
                row[column] = "NOT_GEN2"
            continue

        inventory_row = inventory_map.get(_normalize_lookup_value(hostname), {})
        if not inventory_row:
            row["INV_ocs_name"] = "NOT_FOUND"
            row["INV_hostname"] = "NOT_FOUND"
            row["INV_Beneficiary_Account"] = "NOT_FOUND"
            continue

        for column in INVENTORY_HEADERS:
            row[column] = inventory_row.get(column, "")

    return filtered_rows


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
    fieldnames = ["uid", "program", "network", "taken"] + [display for display, _ in mappings] + (extra_fieldnames or [])
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


def write_output_xlsx(
    output_file: str,
    raw_rows: List[Dict[str, Any]],
    filtered_rows: List[Dict[str, Any]],
    mappings: List[Tuple[str, str]],
    summary_rows: List[Tuple[str, str]],
    filtered_extra_fieldnames: Optional[List[str]] = None,
) -> None:
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    raw_fieldnames = ["uid", "program", "network", "taken"] + [display for display, _ in mappings]
    filtered_fieldnames = raw_fieldnames + (filtered_extra_fieldnames or [])

    content_types = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/worksheets/sheet3.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>'''
    rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>'''
    workbook = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="Summary" sheetId="1" r:id="rId1"/>
    <sheet name="RAW" sheetId="2" r:id="rId2"/>
    <sheet name="FILTRED" sheetId="3" r:id="rId3"/>
  </sheets>
</workbook>'''
    workbook_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet3.xml"/>
  <Relationship Id="rId4" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>'''
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
        zf.writestr("xl/worksheets/sheet1.xml", _xlsx_sheet_xml_summary(summary_rows))
        zf.writestr("xl/worksheets/sheet2.xml", _xlsx_sheet_xml_table(raw_rows, raw_fieldnames))
        zf.writestr("xl/worksheets/sheet3.xml", _xlsx_sheet_xml_table(filtered_rows, filtered_fieldnames))


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

    filtered_rows = enrich_filtered_rows_with_inventory(filtered_rows)

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

    summary_rows.extend(
        [
            ("", ""),
            ("Section 3 : Dali Report", ""),
            ("Number of processed kears", str(len(monitored_rows))),
            ("Total assets get from Dali", str(len(raw_rows))),
            ("Total assets after filtering", str(len(filtered_rows))),
        ]
    )

    write_output_xlsx(
        str(output_xlsx),
        raw_rows,
        filtered_rows,
        mappings,
        summary_rows,
        filtered_extra_fieldnames=INVENTORY_HEADERS,
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
