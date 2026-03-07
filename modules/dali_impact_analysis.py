#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import os
import sys
import csv
import json
import time
import base64
import random
import logging
import argparse
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, List

import requests

# NEW: Excel
import openpyxl


# -----------------------------
# Logging
# -----------------------------
logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("dali")


# -----------------------------
# Load .env robustly
# -----------------------------
def load_env_robust() -> Optional[Path]:
    """
    Tries:
      1) python-dotenv find_dotenv(usecwd=True): search from current working dir upward
      2) script dir / parent / grand-parent .env
    """
    try:
        from dotenv import load_dotenv, find_dotenv
    except Exception:
        log.warning("python-dotenv not installed in this venv. Run: pip install python-dotenv")
        return None

    found = find_dotenv(usecwd=True)
    if found:
        load_dotenv(found, override=True)
        return Path(found)

    here = Path(__file__).resolve().parent
    for p in (here / ".env", here.parent / ".env", here.parent.parent / ".env"):
        if p.exists():
            load_dotenv(p, override=True)
            return p

    return None


loaded_env = load_env_robust()
if loaded_env:
    log.info("Loaded .env: %s", loaded_env)
else:
    log.warning("No .env loaded. Using process environment only.")


# -----------------------------
# Corporate CA bundle (SG)
# -----------------------------
def resolve_verify_ca() -> bool | str:
    """
    Priority:
      1) VERIFY_CA env var (true/false OR path)
      2) sg_cacert_file.load_sg_certs() if available
      3) default True
    """
    v = (os.getenv("VERIFY_CA", "") or "").strip()
    if v:
        if v.lower() in ("1", "true", "yes", "on"):
            return True
        if v.lower() in ("0", "false", "no", "off"):
            return False
        return v  # file path

    try:
        from sg_cacert_file import load_sg_certs  # type: ignore
        cacert = load_sg_certs()
        if cacert:
            log.info("SG CA bundle loaded via sg_cacert_file: %s", cacert)
            return cacert
    except Exception as e:
        log.info("sg_cacert_file not usable: %s", e)

    return True


VERIFY_CA = resolve_verify_ca()


# -----------------------------
# Config
# -----------------------------
DALI_BASE_URL = (os.getenv("DALI_BASE_URL", "https://dali-uat.fr.world.socgen") or "").rstrip("/")
DALI_CLIENT_ID = (os.getenv("DALI_CLIENT_ID", "") or "").strip()
DALI_CLIENT_ID_HEADER = (os.getenv("DALI_CLIENT_ID_HEADER", "x-client-id") or "").strip()

SGMARKET_TOKEN_URL = (
    os.getenv("SGMARKET_TOKEN_URL", "https://sso.sgmarkets.com/sgconnect/oauth2/access_token") or ""
).strip()
SGCONNECT_CLIENT_ID = (os.getenv("SGCONNECT_CLIENT_ID", "") or "").strip()
SGCONNECT_CLIENT_SECRET = (os.getenv("SGCONNECT_CLIENT_SECRET", "") or "").strip()
SGCONNECT_SCOPES = (os.getenv("SGCONNECT_SCOPES", "") or "").strip()

required = {
    "SGCONNECT_CLIENT_ID": SGCONNECT_CLIENT_ID,
    "SGCONNECT_CLIENT_SECRET": SGCONNECT_CLIENT_SECRET,
    "SGCONNECT_SCOPES": SGCONNECT_SCOPES,
}
missing = [k for k, v in required.items() if not v]
if missing:
    log.error("Missing config vars: %s", ", ".join(missing))
    log.error("Debug: cwd=%s", os.getcwd())
    log.error("Debug: script=%s", Path(__file__).resolve())
    log.error("Debug: loaded_env=%s", loaded_env)
    raise SystemExit(
        "Config manquante. Vérifie que le bon .env est chargé et contient: "
        "SGCONNECT_CLIENT_ID, SGCONNECT_CLIENT_SECRET, SGCONNECT_SCOPES."
    )


# -----------------------------
# Token handling (SGMarket / SGConnect)
# -----------------------------
_token_cache: Dict[str, Any] = {"token": None, "expires_at": 0.0}


def _basic_auth_header(client_id: str, client_secret: str) -> str:
    raw = f"{client_id}:{client_secret}".encode("utf-8")
    b64 = base64.b64encode(raw).decode("ascii")
    return f"Basic {b64}"


def fetch_sg_token(timeout: int = 30) -> Tuple[str, int]:
    """
    OAuth2 client_credentials via POST x-www-form-urlencoded
    """
    headers = {
        "Accept": "application/json",
        "Authorization": _basic_auth_header(SGCONNECT_CLIENT_ID, SGCONNECT_CLIENT_SECRET),
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = {
        "grant_type": "client_credentials",
        "scope": SGCONNECT_SCOPES,
    }

    r = requests.post(SGMARKET_TOKEN_URL, headers=headers, data=data, verify=VERIFY_CA, timeout=timeout)
    if r.status_code >= 400:
        raise SystemExit(f"Token fetch failed HTTP {r.status_code}: {r.text[:2000]}")

    payload = r.json()
    token = payload.get("access_token")
    expires_in = int(payload.get("expires_in", 600))
    if not token:
        raise SystemExit(f"Token fetch: access_token missing. Payload: {json.dumps(payload)[:2000]}")
    return token, expires_in


def get_bearer_token(timeout: int = 30) -> str:
    now = time.time()
    if _token_cache["token"] and now < (_token_cache["expires_at"] - 30):
        return _token_cache["token"]

    token, expires_in = fetch_sg_token(timeout=timeout)
    _token_cache["token"] = token
    _token_cache["expires_at"] = now + expires_in
    log.info("Obtained SG token (expires_in=%ss)", expires_in)
    return token


def dali_headers(token_timeout: int = 30) -> Dict[str, str]:
    h = {
        "Accept": "application/json",
        "Authorization": f"Bearer {get_bearer_token(timeout=token_timeout)}",
    }
    if DALI_CLIENT_ID:
        h[DALI_CLIENT_ID_HEADER] = DALI_CLIENT_ID
    return h


# -----------------------------
# HTTP helper
# -----------------------------
def get_json(
    url: str,
    params: Dict[str, Any],
    timeout: int = 300,          # default 5 minutes
    token_timeout: int = 30,     # token endpoint timeout
    max_retries: int = 5
) -> Any:
    sleep_s = 1.0
    last_text: Optional[str] = None

    for attempt in range(max_retries):
        try:
            r = requests.get(
                url,
                headers=dali_headers(token_timeout=token_timeout),
                params=params,
                verify=VERIFY_CA,
                timeout=timeout,
            )
            last_text = r.text

            # token expired / wrong scopes: refresh token once
            if r.status_code in (401, 403) and attempt < max_retries - 1:
                log.warning("HTTP %s -> clearing token cache & retrying", r.status_code)
                _token_cache["token"] = None
                _token_cache["expires_at"] = 0.0
                continue

            # transient errors
            if r.status_code in (429, 500, 502, 503, 504) and attempt < max_retries - 1:
                jitter = random.uniform(0, sleep_s)
                log.warning("HTTP %s retry #%d in %.1fs", r.status_code, attempt + 1, sleep_s + jitter)
                time.sleep(sleep_s + jitter)
                sleep_s = min(20.0, sleep_s * 2.0)
                continue

            if r.status_code >= 400:
                log.error("HTTP %s error body: %s", r.status_code, (r.text or "")[:2000])
            r.raise_for_status()
            return r.json()

        except requests.exceptions.SSLError as e:
            raise SystemExit("SSL error. Vérifie VERIFY_CA ou sg_cacert_file / bundle PEM.") from e
        except requests.exceptions.RequestException as e:
            if attempt < max_retries - 1:
                jitter = random.uniform(0, sleep_s)
                log.warning("Request error (%s) retry #%d in %.1fs", e, attempt + 1, sleep_s + jitter)
                time.sleep(sleep_s + jitter)
                sleep_s = min(20.0, sleep_s * 2.0)
                continue
            raise SystemExit(f"Request failed: {e}\nLast body:\n{(last_text or '')[:2000]}") from e


# -----------------------------
# CSV reading
# -----------------------------
def read_uids_from_csv(csv_path: Path, uid_column: str = "uid") -> List[str]:
    if not csv_path.exists():
        raise SystemExit(f"Input CSV not found: {csv_path}")

    uids: List[str] = []
    with csv_path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise SystemExit("CSV has no header row (DictReader needs a header).")

        # match column case-insensitively
        field_map = {name.lower(): name for name in reader.fieldnames}
        if uid_column.lower() not in field_map:
            raise SystemExit(f"CSV missing column '{uid_column}'. Found columns: {reader.fieldnames}")

        real_col = field_map[uid_column.lower()]
        for row in reader:
            v = (row.get(real_col) or "").strip()
            if v:
                uids.append(v)

    # de-dup preserving order
    seen = set()
    out: List[str] = []
    for u in uids:
        if u not in seen:
            out.append(u)
            seen.add(u)
    return out


# -----------------------------
# Output directory / file
# -----------------------------
def make_timestamped_output(base_dir: Path) -> Tuple[Path, str, Path]:
    ts = time.strftime("%Y%m%d-%H%M%S")
    out_dir = base_dir / ts
    out_dir.mkdir(parents=True, exist_ok=True)
    out_json = out_dir / f"impactAnalysis_{ts}.json"
    return out_dir, ts, out_json


# -----------------------------
# NEW: Excel mapping helpers
# -----------------------------
def read_headers_mapping(headers_xlsx: Path, sheet_name: Optional[str] = None) -> List[Tuple[str, str]]:
    """
    Reads mapping from headers.xlsx:
      Col A = Excel header
      Col B = JSON key to fetch (or 'EMPTY')
    """
    wb = openpyxl.load_workbook(headers_xlsx, data_only=True)
    ws = wb[sheet_name] if sheet_name else wb[wb.sheetnames[0]]

    mapping: List[Tuple[str, str]] = []
    for row in range(1, ws.max_row + 1):
        a = ws.cell(row, 1).value
        b = ws.cell(row, 2).value
        if a is None and b is None:
            continue
        header = str(a).strip() if a is not None else ""
        key = str(b).strip() if b is not None else "EMPTY"
        if header:
            mapping.append((header, key))
    return mapping


def _safe_json_str(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        return json.dumps(v, ensure_ascii=False)
    return str(v)


def pick_value_from_result_edge(key: str, uid: str, edge: Dict[str, Any]) -> str:
    """
    Minimal + robust:
    - key == 'EMPTY' => empty cell
    - try leading_node.properties[key]
    - else try trailing_node.properties[key]
    - else empty
    - Special: if key == 'uid' and not found, return the input uid (useful if mapping uses uid)
    """
    if key == "EMPTY":
        return ""

    leading_props = (((edge.get("leading_node") or {}).get("properties")) or {})
    trailing_props = (((edge.get("trailing_node") or {}).get("properties")) or {})

    if key in leading_props:
        return _safe_json_str(leading_props.get(key))
    if key in trailing_props:
        return _safe_json_str(trailing_props.get(key))

    # fallback for common columns
    if key.lower() in ("uid", "application_uid", "app_uid"):
        return uid

    return ""


def write_excel_from_consolidated(
    consolidated: Dict[str, Any],
    mapping: List[Tuple[str, str]],
    out_xlsx: Path
) -> int:
    """
    Writes one row per edge in response.result[].
    If result[] is empty/missing or response is an error, writes one row with uid + empty values.
    Returns number of rows written (excluding header).
    """
    headers = [h for h, _ in mapping]

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "impactAnalysis"

    ws.append(headers)
    ws.freeze_panes = "A2"

    row_count = 0

    for item in consolidated.get("items", []):
        uid = (item.get("uid") or "")
        resp = item.get("response")

        # If response is not a dict or contains error info, still write a row
        if not isinstance(resp, dict):
            ws.append([uid if k.lower() in ("uid", "application_uid", "app_uid") else "" for _, k in mapping])
            row_count += 1
            continue

        if resp.get("error") is True:
            ws.append([uid if k.lower() in ("uid", "application_uid", "app_uid") else "" for _, k in mapping])
            row_count += 1
            continue

        edges = resp.get("result")
        if not isinstance(edges, list) or len(edges) == 0:
            ws.append([uid if k.lower() in ("uid", "application_uid", "app_uid") else "" for _, k in mapping])
            row_count += 1
            continue

        for edge in edges:
            row = []
            for _, k in mapping:
                row.append(pick_value_from_result_edge(k, uid, edge if isinstance(edge, dict) else {}))
            ws.append(row)
            row_count += 1

    wb.save(out_xlsx)
    return row_count


# -----------------------------
# Main
# -----------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Batch DALI impactAnalysis for a list of Application UIDs (CSV input) and consolidate into one JSON."
    )
    parser.add_argument("--input", "-i", required=True, help="Input CSV file containing a uid column")
    parser.add_argument("--uid-column", default="uid", help="CSV column name that contains the UID (default: uid)")
    parser.add_argument("--output-base-dir", default="out", help="Base output directory (default: ./out)")
    parser.add_argument("--sleep-ms", type=int, default=0, help="Optional sleep between calls (ms) to be gentle")
    parser.add_argument("--limit", type=int, default=10, help="DALI limit param (default: 10)")
    parser.add_argument("--depth-until", type=int, default=10, help="DALI depthUntil param (default: 10)")

    # NEW: timeouts
    parser.add_argument("--timeout-seconds", type=int, default=300, help="HTTP timeout seconds for DALI calls (default: 300)")
    parser.add_argument("--token-timeout-seconds", type=int, default=30, help="HTTP timeout seconds for token call (default: 30)")

    # NEW: Excel mapping options
    parser.add_argument("--headers-xlsx", help="Excel mapping file (col A=header, col B=json key or EMPTY)")
    parser.add_argument("--headers-sheet", default=None, help="Optional sheet name (default: first sheet)")
    parser.add_argument("--excel", action="store_true", help="Generate Excel output using headers mapping (requires --headers-xlsx)")

    args = parser.parse_args()

    input_csv = Path(args.input).expanduser().resolve()
    uids = read_uids_from_csv(input_csv, uid_column=args.uid_column)

    if not uids:
        raise SystemExit("No UID found in input CSV.")

    base_out = Path(args.output_base_dir).expanduser().resolve()
    out_dir, ts, out_json = make_timestamped_output(base_out)
    out_xlsx = out_dir / f"impactAnalysis_{ts}.xlsx"

    endpoint = f"{DALI_BASE_URL}/api/v1/impactAnalysis"
    log.info("Input CSV: %s (uids=%d)", input_csv, len(uids))
    log.info("Output dir: %s", out_dir)
    log.info("Endpoint: %s", endpoint)

    consolidated: Dict[str, Any] = {
        "meta": {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "dali_base_url": DALI_BASE_URL,
            "endpoint": "/api/v1/impactAnalysis",
            "input_csv": str(input_csv),
            "uid_column": args.uid_column,
            "count_uids": len(uids),
        },
        "items": [],
        "errors": [],
    }

    for idx, uid in enumerate(uids, start=1):
        params: Dict[str, Any] = {
            "ciLabel": "Application",
            "attributeName": "uid",
            "matchType": "equals",
            "attributeValue": uid,
            "direction": "to",
            "relationship": ['CHANGES', 'IS_ASSIGNED_TO', 'IS_CONTAINED_BY', 'IS_GRANTED_TO', 'IS_HOSTED_BY', 'IS_LOCATED_BY', 'IS_MANAGED_BY', 'IS_MEMBER_OF', 'IS_USED_BY', 'USE', 'USE_STORAGE', 'MANAGE_RESOURCE', 'IS_PROVIDED_BY', 'IS_CONNECTED_TO', 'COMPOSED_BY', 'CLUSTER_CONTAINS'],
            "impactedCis": "Server",
            "status": "In use",
            "reliability": "false",
            "criticality": ['Critical', 'High', 'Medium', 'Low', 'Unknown'],
            "includeLiveSources": "true",
            "zones": ['EUR', 'ASIA', 'AMER', 'BCO', 'UK', 'Unknown'],
            "environments": ["Production", "Not in production"],
            "excludeDuplicates": "true",
            "boost": "false",
            "includeGTSInfra": "true",
            "includeCount": "true",
            "skip": "0",
            "limit": str(args.limit),
            "depthUntil": str(args.depth_until),
        }

        log.info("[%d/%d] uid=%s", idx, len(uids), uid)

        try:
            data = get_json(
                endpoint,
                params=params,
                timeout=args.timeout_seconds,
                token_timeout=args.token_timeout_seconds,
            )
            consolidated["items"].append({"uid": uid, "response": data})
        except SystemExit as e:
            msg = str(e)
            log.error("Failed uid=%s: %s", uid, msg)
            consolidated["errors"].append({"uid": uid, "error": msg})

        if args.sleep_ms > 0:
            time.sleep(args.sleep_ms / 1000.0)

    # Write consolidated JSON
    pretty = json.dumps(consolidated, ensure_ascii=False, indent=2)
    out_json.write_text(pretty + "\n", encoding="utf-8")
    log.info("Consolidated JSON saved to: %s", out_json)

    # NEW: Write Excel if requested
    if args.excel:
        if not args.headers_xlsx:
            raise SystemExit("Option --excel requiert --headers-xlsx <file>.")

        headers_xlsx = Path(args.headers_xlsx).expanduser().resolve()
        if not headers_xlsx.exists():
            raise SystemExit(f"headers.xlsx introuvable: {headers_xlsx}")

        mapping = read_headers_mapping(headers_xlsx, sheet_name=args.headers_sheet)
        if not mapping:
            raise SystemExit("Mapping vide: vérifie headers.xlsx (col A=header, col B=key).")

        rows_written = write_excel_from_consolidated(consolidated, mapping, out_xlsx)
        log.info("Excel saved to: %s (rows=%d)", out_xlsx, rows_written)

    # Print JSON path to stdout (useful in pipelines)
    print(str(out_json))


if __name__ == "__main__":
    main()
