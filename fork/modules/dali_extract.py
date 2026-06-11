"""DALI-only extraction for the KPI fork second increment.

This module intentionally stops at the DALI extraction boundary:
- read monitored KEAR/UID values,
- call DALI impactAnalysis once per distinct UID,
- flatten the DALI edges into W02 rows,
- optionally write a W02-only workbook and a compressed JSON trace.

No Data4Sec inventory, PCE, Marley, filtering, scope, exclusion, PPTX or email logic is
implemented here. Those steps belong to later increments.
"""

from __future__ import annotations

import argparse
import base64
import csv
import gzip
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urljoin

import requests
import xlsxwriter

from config import DALI, DALI_EXTRACT_HEADERS, DALI_EXTRACT_SHEET, FORK_ROOT
from input_reader import detect_csv_delimiter, normalize_uid, unique_preserving_order

log = logging.getLogger(__name__)


def _env(name: str, default: str = "") -> str:
    return (os.getenv(name) or default).strip().strip("'").strip('"')


def _basic_auth_header(client_id: str, client_secret: str) -> str:
    raw = f"{client_id}:{client_secret}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def _request_verify_setting() -> Any:
    value = _env("VERIFY_CA")
    if value:
        lowered = value.lower()
        if lowered in {"true", "1", "yes", "on"}:
            return True
        if lowered in {"false", "0", "no", "off"}:
            return False
        return value

    for candidate in (_env("REQUESTS_CA_BUNDLE"), _env("SSL_CERT_FILE")):
        if candidate and Path(candidate).is_file():
            return candidate
    return True


def read_headers_mapping(headers_file: Path) -> List[Tuple[str, str]]:
    """Read display-name/DALI-attribute mappings from headers.csv."""
    delimiter = detect_csv_delimiter(headers_file)
    mappings: List[Tuple[str, str]] = []
    with headers_file.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle, delimiter=delimiter)
        for row in reader:
            display_name = str(row[0]).strip() if len(row) > 0 and row[0] else ""
            dali_attr = str(row[1]).strip() if len(row) > 1 and row[1] else ""
            if display_name and dali_attr:
                mappings.append((display_name, dali_attr))
    if not mappings:
        raise ValueError(f"No valid DALI header mapping found in {headers_file}")
    return mappings


def read_monitored_rows(monitored_file: Path) -> List[Dict[str, str]]:
    """Read monitored KEAR rows and preserve useful context columns for W02."""
    delimiter = detect_csv_delimiter(monitored_file)
    with monitored_file.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, delimiter=delimiter)
        if not reader.fieldnames:
            raise ValueError(f"Missing CSV header in {monitored_file}")

        headers = {str(header or "").strip().lower(): header for header in reader.fieldnames}
        uid_header = headers.get("uid") or headers.get("kear")
        if not uid_header:
            raise ValueError(f"Missing required uid column in {monitored_file}; accepted aliases: uid, kear")

        rows: List[Dict[str, str]] = []
        seen: set[str] = set()
        for raw in reader:
            uid = normalize_uid(raw.get(uid_header, ""))
            if not uid or uid in seen:
                continue
            seen.add(uid)
            rows.append(
                {
                    "uid": uid,
                    "kear": normalize_uid(raw.get(headers.get("kear", uid_header), uid)),
                    "program": str(raw.get(headers.get("program", ""), "") or "").strip(),
                    "network": str(raw.get(headers.get("network", ""), "") or "").strip(),
                    "taken": str(raw.get(headers.get("taken", ""), "") or "").strip(),
                    "short_label": str(raw.get(headers.get("short_label", ""), "") or "").strip(),
                    "slide": str(raw.get(headers.get("slide", ""), "") or "").strip(),
                }
            )
    if not rows:
        raise ValueError(f"No monitored UID found in {monitored_file}")
    return rows


class DaliExtractClient:
    """Minimal DALI impactAnalysis client for W02 extraction."""

    def __init__(self) -> None:
        self.base_url = DALI["BASE_URL"].rstrip("/")
        self.token_url = DALI["TOKEN_URL"]
        self.client_id = DALI["SGCONNECT_CLIENT_ID"]
        self.client_secret = DALI["SGCONNECT_CLIENT_SECRET"]
        self.scopes = DALI["SGCONNECT_SCOPES"]
        self.dali_client_id = DALI["DALI_CLIENT_ID"]
        self.dali_client_id_header = DALI["DALI_CLIENT_ID_HEADER"] or "x-client-id"
        self.verify = _request_verify_setting()
        self._token = ""
        self._token_expiry_epoch = 0.0

    def _validate_settings(self) -> None:
        missing = [
            name
            for name, value in {
                "DALI_BASE_URL": self.base_url,
                "SGMARKET_TOKEN_URL": self.token_url,
                "SGCONNECT_CLIENT_ID": self.client_id,
                "SGCONNECT_CLIENT_SECRET": self.client_secret,
                "SGCONNECT_SCOPES": self.scopes,
            }.items()
            if not value
        ]
        if missing:
            raise ValueError(f"Missing DALI settings. Check fork/.env or the project .env: {', '.join(missing)}")

    def fetch_sg_token(self) -> Tuple[str, int]:
        self._validate_settings()
        headers = {
            "Authorization": _basic_auth_header(self.client_id, self.client_secret),
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        payload = {"grant_type": "client_credentials", "scope": self.scopes}
        log.info("DALI token request | url=%s", self.token_url)
        response = requests.post(self.token_url, data=payload, headers=headers, timeout=30, verify=self.verify)
        response.raise_for_status()
        body = response.json()
        token = body.get("access_token")
        expires_in = int(body.get("expires_in", 3600) or 3600)
        if not token:
            raise RuntimeError("No access_token found in OAuth2 response")
        return str(token), expires_in

    def get_bearer_token(self, force_refresh: bool = False) -> str:
        now = time.time()
        if not force_refresh and self._token and now < self._token_expiry_epoch - 30:
            return self._token
        token, expires_in = self.fetch_sg_token()
        self._token = token
        self._token_expiry_epoch = now + max(60, expires_in)
        return self._token

    def dali_headers(self, force_refresh: bool = False) -> Dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.get_bearer_token(force_refresh=force_refresh)}",
        }
        if self.dali_client_id:
            headers[self.dali_client_id_header] = self.dali_client_id
        return headers

    def get_json(self, endpoint: str, params: Dict[str, Any], timeout_s: int = 60, retries: int = 3) -> Dict[str, Any]:
        self._validate_settings()
        url = urljoin(f"{self.base_url}/", endpoint.lstrip("/"))
        uid = params.get("attributeValue")
        last_error: Optional[Exception] = None
        for attempt in range(retries + 1):
            try:
                log.info("DALI impactAnalysis request | uid=%s | attempt=%s/%s", uid, attempt + 1, retries + 1)
                response = requests.get(
                    url,
                    params=params,
                    headers=self.dali_headers(force_refresh=attempt > 0),
                    timeout=timeout_s,
                    verify=self.verify,
                )
                if response.status_code in {401, 403} and attempt < retries:
                    self._token = ""
                    self._token_expiry_epoch = 0.0
                    continue
                if response.status_code >= 400:
                    raise RuntimeError(f"HTTP {response.status_code}: {response.text[:1000]}")
                payload = response.json()
                count = payload.get("count") if isinstance(payload, dict) else "n/a"
                result = payload.get("result") if isinstance(payload, dict) else None
                edge_count = len(result) if isinstance(result, list) else 0
                log.info("DALI impactAnalysis response | uid=%s | count=%s | edges=%s", uid, count, edge_count)
                return payload
            except requests.RequestException as exc:
                last_error = exc
            except RuntimeError as exc:
                last_error = exc
                if "HTTP 401" not in str(exc) and "HTTP 403" not in str(exc):
                    raise
            if attempt < retries:
                time.sleep(2**attempt)
        raise RuntimeError(f"DALI request failed for uid={uid}: {last_error}")


def build_impact_params(uid: str, limit: Optional[int], depth_until: Optional[int]) -> Dict[str, Any]:
    params = dict(DALI["IMPACT_DEFAULT_PARAMS"])
    params["attributeValue"] = uid
    params["limit"] = str(limit if limit is not None else DALI["LIMIT"])
    params["depthUntil"] = str(depth_until if depth_until is not None else DALI["DEPTH_UNTIL"])
    return params


def node_properties_to_dict(node: Any) -> Dict[str, Any]:
    if not isinstance(node, dict):
        return {}
    props = node.get("properties")
    if isinstance(props, dict):
        return props
    if not isinstance(props, list):
        return {}
    output: Dict[str, Any] = {}
    for prop in props:
        if not isinstance(prop, dict):
            continue
        name = prop.get("name")
        if name:
            output[str(name)] = prop.get("value")
    return output


def _node_has_label(node: Any, expected_label: str) -> bool:
    labels = node.get("labels") if isinstance(node, dict) else None
    normalized = {str(label).strip().lower() for label in labels} if isinstance(labels, list) else set()
    return expected_label.strip().lower() in normalized


def _extract_server_uid_from_edge(edge: Dict[str, Any]) -> str:
    for node_key in ("leading_node", "trailing_node"):
        node = edge.get(node_key)
        if not _node_has_label(node, "server"):
            continue
        uid = node_properties_to_dict(node).get("uid")
        value = str(uid or "").strip()
        if value:
            return value
    return ""


def _resolve_edge_mapping_value(edge: Dict[str, Any], dali_attr: str, base_row: Dict[str, Any]) -> Any:
    attr = str(dali_attr or "").strip()
    if not attr:
        return ""

    leading_node = edge.get("leading_node")
    trailing_node = edge.get("trailing_node")
    lead = node_properties_to_dict(leading_node)
    trail = node_properties_to_dict(trailing_node)
    scoped_attr = attr
    lower_attr = attr.lower()

    if "." in attr:
        scope, scoped_attr = attr.split(".", 1)
        scope = scope.strip().lower()
        scoped_attr = scoped_attr.strip()
        scoped_value: Any = None
        if scope == "leading":
            scoped_value = lead.get(scoped_attr)
        elif scope == "trailing":
            scoped_value = trail.get(scoped_attr)
        elif scope in {"server", "application"}:
            for node, props in ((leading_node, lead), (trailing_node, trail)):
                if _node_has_label(node, scope):
                    scoped_value = props.get(scoped_attr)
                    if scoped_value is not None and (not isinstance(scoped_value, str) or scoped_value.strip()):
                        break
        if scoped_value is not None:
            return scoped_value
        lower_attr = scoped_attr.lower()

    raw_value = lead.get(scoped_attr)
    if raw_value is None or (isinstance(raw_value, str) and not raw_value.strip()):
        raw_value = trail.get(scoped_attr)
    if raw_value is None and lower_attr in {"uid", "application_uid", "app_uid"}:
        raw_value = base_row.get("uid", "")
    return raw_value


def _normalize_cell_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(str(item) for item in value if str(item).strip())
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def flatten_dali_response(
    response: Dict[str, Any],
    base_row: Dict[str, Any],
    mappings: List[Tuple[str, str]],
    err_text: str = "",
) -> List[Dict[str, str]]:
    """Flatten one DALI response into W02 rows."""
    if err_text:
        row = {header: str(base_row.get(header, "")) for header in DALI_EXTRACT_HEADERS}
        row.update({"lookup_status": "ERROR", "count": "0", "error": err_text})
        for display_name, _dali_attr in mappings:
            row[display_name] = ""
        return [row]

    result = response.get("result") if isinstance(response, dict) else None
    edges = [edge for edge in (result or []) if isinstance(edge, dict)] if isinstance(result, list) else []
    count_value = response.get("count", len(edges)) if isinstance(response, dict) else len(edges)

    if not edges:
        row = {header: str(base_row.get(header, "")) for header in DALI_EXTRACT_HEADERS}
        row.update({"lookup_status": "NOT_FOUND", "count": str(count_value or 0), "error": ""})
        for display_name, _dali_attr in mappings:
            row[display_name] = ""
        return [row]

    rows: List[Dict[str, str]] = []
    for edge in edges:
        row = {header: str(base_row.get(header, "")) for header in DALI_EXTRACT_HEADERS}
        row.update(
            {
                "Server UID": _extract_server_uid_from_edge(edge),
                "lookup_status": "FOUND",
                "count": str(count_value or len(edges)),
                "error": "",
            }
        )
        for display_name, dali_attr in mappings:
            row[display_name] = _normalize_cell_value(_resolve_edge_mapping_value(edge, dali_attr, base_row))
        rows.append(row)
    return rows


def build_w02_rows(
    client: DaliExtractClient,
    monitored_rows: List[Dict[str, str]],
    mappings: List[Tuple[str, str]],
    impact_endpoint: str,
    limit: Optional[int] = None,
    depth_until: Optional[int] = None,
    sleep_ms: int = 0,
    dry_run: bool = False,
) -> Tuple[List[Dict[str, str]], Dict[str, Any]]:
    """Run the DALI-only batch extraction and return W02 rows plus JSON trace."""
    w02_rows: List[Dict[str, str]] = []
    items: List[Dict[str, Any]] = []
    errors: List[Dict[str, str]] = []
    uids = unique_preserving_order(row.get("uid", "") for row in monitored_rows)
    rows_by_uid = {row["uid"]: row for row in monitored_rows if row.get("uid")}
    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    log.info("STEP 02 - DALI extract W02 | Preparing batch | uid_count=%s | dry_run=%s", len(uids), dry_run)
    for idx, uid in enumerate(uids, start=1):
        source_row = rows_by_uid[uid]
        base_row = {header: source_row.get(header, "") for header in DALI_EXTRACT_HEADERS}
        log.info("STEP 02 - DALI extract W02 | uid=%s | progress=%s/%s", uid, idx, len(uids))
        err_text = ""
        if dry_run:
            response: Dict[str, Any] = {"count": 0, "result": []}
        else:
            try:
                params = build_impact_params(uid=uid, limit=limit, depth_until=depth_until)
                response = client.get_json(endpoint=impact_endpoint, params=params)
            except Exception as exc:
                err_text = str(exc)
                response = {}
                errors.append({"uid": uid, "error": err_text})
                log.warning("STEP 02 - DALI extract W02 | uid=%s | error=%s", uid, err_text)

        items.append({"uid": uid, "response": response, "error": err_text})
        rows_for_uid = flatten_dali_response(response=response, base_row=base_row, mappings=mappings, err_text=err_text)
        w02_rows.extend(rows_for_uid)
        log.info("STEP 02 - DALI extract W02 | uid=%s | rows=%s", uid, len(rows_for_uid))
        if sleep_ms > 0:
            time.sleep(sleep_ms / 1000.0)

    ended_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    found_uid_count = sum(
        1
        for item in items
        if isinstance(item.get("response"), dict) and int(item.get("response", {}).get("count", 0) or 0) > 0
    )
    payload = {
        "meta": {
            "generated_at": ended_at,
            "job_started_at": started_at,
            "job_end_at": ended_at,
            "dali_base_url": client.base_url,
            "endpoint": impact_endpoint,
            "uid_count": len(uids),
            "success_count": len(uids) - len(errors),
            "found_uid_count": found_uid_count,
            "error_count": len(errors),
            "row_count": len(w02_rows),
            "depth_until": depth_until if depth_until is not None else DALI["DEPTH_UNTIL"],
            "limit": limit if limit is not None else DALI["LIMIT"],
            "dry_run": dry_run,
        },
        "items": items,
        "errors": errors,
    }
    log.info(
        "STEP 02 - DALI extract W02 | Completed | uid_count=%s | rows=%s | errors=%s",
        len(uids),
        len(w02_rows),
        len(errors),
    )
    return w02_rows, payload


def w02_fieldnames(mappings: List[Tuple[str, str]]) -> List[str]:
    return list(DALI_EXTRACT_HEADERS) + [display_name for display_name, _dali_attr in mappings]


def _set_column_widths(worksheet, headers: List[str], rows: List[Dict[str, str]]) -> None:
    for col_idx, header in enumerate(headers):
        max_width = max([len(str(header))] + [len(str(row.get(header, ""))) for row in rows[:200]])
        worksheet.set_column(col_idx, col_idx, min(max(max_width + 2, 12), 80))


def write_table_sheet(workbook: xlsxwriter.Workbook, sheet_name: str, headers: List[str], rows: List[Dict[str, str]]) -> None:
    worksheet = workbook.add_worksheet(sheet_name)
    header_format = workbook.add_format({"bold": True, "bg_color": "#D9EAF7", "border": 1})
    for col_idx, header in enumerate(headers):
        worksheet.write(0, col_idx, header, header_format)
    for row_idx, row in enumerate(rows, start=1):
        for col_idx, header in enumerate(headers):
            worksheet.write(row_idx, col_idx, row.get(header, ""))
    worksheet.autofilter(0, 0, max(len(rows), 1), max(len(headers) - 1, 0))
    worksheet.freeze_panes(1, 0)
    _set_column_widths(worksheet, headers, rows)


def write_w02_workbook(output_file: Path, rows: List[Dict[str, str]], headers: List[str], sheet_name: str = DALI_EXTRACT_SHEET) -> None:
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with xlsxwriter.Workbook(str(output_file)) as workbook:
        write_table_sheet(workbook, sheet_name, headers, rows)
    log.info("STEP 02 - DALI extract W02 | Wrote workbook=%s | rows=%s", output_file, len(rows))


def write_json_gz(output_file: Path, payload: Dict[str, Any]) -> Path:
    output_file.parent.mkdir(parents=True, exist_ok=True)
    gz_path = output_file if output_file.suffix == ".gz" else Path(str(output_file) + ".gz")
    with gzip.open(gz_path, "wt", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
    log.info("STEP 02 - DALI extract W02 | Wrote JSON trace=%s", gz_path)
    return gz_path


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")


def parse_positive_int(name: str, value: Optional[str]) -> Optional[int]:
    if value is None or str(value).strip() == "":
        return None
    parsed = int(value)
    if parsed <= 0:
        raise ValueError(f"{name} must be > 0")
    return parsed


def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the KPI fork second increment: DALI-only extract into W02.")
    parser.add_argument("--monitored-file", default=str(FORK_ROOT / "users_input" / "monitored_kears.csv"))
    parser.add_argument("--headers-file", default=str(FORK_ROOT / "users_input" / "headers.csv"))
    parser.add_argument("--output-file", default="")
    parser.add_argument("--json-out", default="")
    parser.add_argument("--sheet-name", default=DALI_EXTRACT_SHEET)
    parser.add_argument("--impact-endpoint", default=DALI["IMPACT_ENDPOINT"])
    parser.add_argument("--depth-until", type=int, default=parse_positive_int("DALI_DEPTH_UNTIL", _env("DALI_DEPTH_UNTIL")))
    parser.add_argument("--limit", type=int, default=parse_positive_int("DALI_LIMIT", _env("DALI_LIMIT")))
    parser.add_argument("--sleep-ms", type=int, default=0)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.sleep_ms < 0:
        raise ValueError("--sleep-ms must be >= 0")
    return args


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = parse_args(argv)
    setup_logging(args.verbose)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    output_file = Path(args.output_file) if args.output_file else FORK_ROOT / "RUNS" / timestamp / f"dali_extract_{timestamp}.xlsx"
    json_out = Path(args.json_out) if args.json_out else output_file.with_name("dali_extract.json")

    monitored_rows = read_monitored_rows(Path(args.monitored_file))
    mappings = read_headers_mapping(Path(args.headers_file))
    rows, payload = build_w02_rows(
        client=DaliExtractClient(),
        monitored_rows=monitored_rows,
        mappings=mappings,
        impact_endpoint=args.impact_endpoint,
        limit=args.limit,
        depth_until=args.depth_until,
        sleep_ms=args.sleep_ms,
        dry_run=args.dry_run,
    )
    write_w02_workbook(output_file=output_file, rows=rows, headers=w02_fieldnames(mappings), sheet_name=args.sheet_name)
    write_json_gz(json_out, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
