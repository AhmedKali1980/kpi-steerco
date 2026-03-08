import argparse
import base64
import csv
import json
import logging
import os
import random
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

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
    "impactedCis": "Server",
    "status": "In use",
    "includeLiveSources": "true",
    "zones": "EUR",
    "environments": ["Production", "Not in production"],
    "excludeDuplicates": "true",
    "includeGTSInfra": "true",
    "includeCount": "true",
    "skip": 0,
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
                    log.warning("DALI transient status=%s, retry in %.2fs", status_code, delay)
                    time.sleep(delay)
                    continue

                if status_code >= 400:
                    details = _response_error_details(status_code=status_code, body=response.text)
                    raise RuntimeError(f"DALI request failed for uid={params.get('attributeValue')}: {details}")

                response.raise_for_status()
                return response.json()
            except requests.RequestException as exc:
                last_exc = exc
                if attempt < retries:
                    delay = (2**attempt) + random.uniform(0, 0.5)
                    log.warning("DALI request error on attempt %s/%s: %s; retry in %.2fs", attempt + 1, retries + 1, exc, delay)
                    time.sleep(delay)
                    continue
                break

        raise RuntimeError(f"DALI request failed after retries: {last_exc}")


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
            if "," not in line:
                log.warning("Ignoring invalid filter line (expected key,value): %s", line)
                continue
            key, value = line.split(",", 1)
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


def first_non_empty(values: List[Any]) -> Any:
    for v in values:
        if v is None:
            continue
        if isinstance(v, str) and not v.strip():
            continue
        return v
    return ""


def extract_mapped_fields(response: Dict[str, Any], mappings: List[Tuple[str, str]]) -> Dict[str, Any]:
    result = response.get("result") if isinstance(response, dict) else None
    entries = result if isinstance(result, list) else []

    aggregated: Dict[str, List[Any]] = {}
    for edge in entries:
        if not isinstance(edge, dict):
            continue
        lead = node_properties_to_dict(edge.get("leading_node"))
        trail = node_properties_to_dict(edge.get("trailing_node"))
        for key, value in {**lead, **trail}.items():
            aggregated.setdefault(key, []).append(value)

    mapped: Dict[str, Any] = {}
    for display_name, dali_attr in mappings:
        values = aggregated.get(dali_attr, [])
        value = first_non_empty(values)
        if isinstance(value, list):
            value = ", ".join(str(x) for x in value if str(x).strip())
        mapped[display_name] = value
    return mapped


def write_output_csv(output_file: str, rows: List[Dict[str, Any]], mappings: List[Tuple[str, str]]) -> None:
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["uid", "kear", "program", "network", "taken", "lookup_status", "count", "error"] + [
        display for display, _ in mappings
    ]
    with open(output_file, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_output_json(output_file: str, payload: Dict[str, Any]) -> None:
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)


def build_impact_params(uid: str, limit: Optional[int], depth_until: Optional[int]) -> Dict[str, Any]:
    params = dict(IMPACT_DEFAULT_PARAMS)
    params["attributeValue"] = uid
    params["limit"] = limit if limit is not None else 10000
    params["depthUntil"] = depth_until if depth_until is not None else 8
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
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    errors: List[Dict[str, str]] = []
    csv_rows: List[Dict[str, Any]] = []

    for row in monitored_rows:
        uid = row["uid"]
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
                errors.append({"uid": uid, "error": err_text})
                response = {}

        items.append({"uid": uid, "response": response})

        mapped = extract_mapped_fields(response, mappings)
        count_value = response.get("count", 0) if isinstance(response, dict) else 0
        csv_rows.append(
            {
                "uid": uid,
                "kear": row.get("kear", uid),
                "program": row.get("program", ""),
                "network": row.get("network", ""),
                "taken": row.get("taken", ""),
                "lookup_status": ("ERROR" if err_text else ("FOUND" if int(count_value or 0) > 0 else "NOT_FOUND")),
                "count": count_value,
                "error": err_text,
                **mapped,
            }
        )

        if sleep_ms > 0:
            time.sleep(sleep_ms / 1000.0)

    success_count = sum(1 for row in csv_rows if row.get("lookup_status") != "ERROR")
    found_count = sum(1 for row in csv_rows if row.get("lookup_status") == "FOUND")
    payload = {
        "meta": {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
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
    return csv_rows, payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Batch DALI impact analysis for monitored UIDs/KEARs.")
    parser.add_argument("--monitored-file", default="user_inputs/monitored_kears.csv", help="Path to monitored_kears.csv")
    parser.add_argument("--input", dest="monitored_file", help="Compatibility alias for --monitored-file")
    parser.add_argument("--headers-file", default="user_inputs/headers.csv", help="Path to headers.csv")
    parser.add_argument("--headers-xlsx", dest="headers_file", help="Compatibility alias for --headers-file")
    parser.add_argument("--headers-sheet", help="Compatibility option for legacy command (ignored in CSV mode)")
    parser.add_argument("--excel", action="store_true", help="Compatibility option for legacy command (ignored in CSV mode)")
    parser.add_argument("--filters-file", default="user_inputs/filters.conf", help="Path to filters.conf (key,value)")
    parser.add_argument("--output", default="RUNS/dali_impact_analysis.csv", help="Output CSV path")
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
    csv_rows, json_payload = run_impact_analysis(
        client=client,
        monitored_rows=monitored_rows,
        mappings=mappings,
        impact_endpoint=args.impact_endpoint,
        limit=args.limit,
        depth_until=args.depth_until,
        sleep_ms=args.sleep_ms,
        dry_run=args.dry_run,
    )

    write_output_csv(args.output, csv_rows, mappings)
    write_output_json(args.json_out, json_payload)

    print(f"Monitored rows: {len(monitored_rows)}")
    print(f"Header mappings: {len(mappings)}")
    print(f"Custom filters loaded: {len(filters)}")
    print(f"Impact endpoint: {args.impact_endpoint}")
    print(f"Depth until: {args.depth_until}")
    print(f"Limit: {args.limit}")
    print(f"Errors: {len(json_payload.get('errors', []))}")
    print(f"CSV written to: {args.output}")
    print(f"JSON written to: {args.json_out}")


if __name__ == "__main__":
    main()
