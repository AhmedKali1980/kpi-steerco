import argparse
import csv
import gzip
import json
import logging
from pathlib import Path
from typing import Any, Dict, List

from elasticsearch.helpers import scan

from config import QUERY_CONFIG
from d4s_client import Data4secClient

log = logging.getLogger(__name__)
TECHNICAL_FIELDS = ["exposure_scopes", "is_dali_exposed", "is_masai_exposed"]
ALL_FILTERS_FIELD = "F_ALL_FILTERS"
FILTER_DEFINITIONS: List[Dict[str, str]] = [
    {"name": "F_INTEXP.INCLUDE_server_os_name", "field": "server_os_name", "mode": "include_exact"},
    {"name": "F_INTEXP.INCLUDE_server_cloud_type", "field": "server_cloud_type", "mode": "include_exact"},
    {"name": "F_INTEXP.EXCLUDE_application_dali_dsi", "field": "application_dali_dsi", "mode": "exclude_contains"},
    {"name": "F_INTEXP.INCLUDE_server_status", "field": "server_status", "mode": "include_exact"},
    {"name": "F_INTEXP.EXCLUDE_server_typology", "field": "server_typology", "mode": "exclude_contains"},
    {"name": "F_INTEXP.INCLUDE_server_environment", "field": "server_environment", "mode": "include_contains"},
    {"name": "F_INTEXP.EXCLUDE_server_silo", "field": "server_silo", "mode": "exclude_contains"},
]


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")


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


def parse_filter_tokens(filters: Dict[str, str], filter_name: str) -> List[str]:
    raw_value = filters.get(filter_name, "")
    tokens: List[str] = []
    seen = set()
    for raw_token in raw_value.split(","):
        token = raw_token.strip().strip("*").strip().casefold()
        if token and token not in seen:
            seen.add(token)
            tokens.append(token)
    return tokens


def apply_filter(value: Any, tokens: List[str], mode: str) -> str:
    if not tokens:
        return "Y"
    normalized_value = value_to_text(value).strip().casefold()
    if mode == "include_exact":
        return "Y" if normalized_value in tokens else "N"
    if mode == "include_contains":
        return "Y" if any(token in normalized_value for token in tokens) else "N"
    if mode == "exclude_contains":
        return "N" if any(token in normalized_value for token in tokens) else "Y"
    raise ValueError(f"Unsupported INTERNET.EXPOSED filter mode: {mode}")


def validate_filter_targets(source_fields: List[str]) -> None:
    missing = [definition["field"] for definition in FILTER_DEFINITIONS if definition["field"] not in source_fields]
    if missing:
        raise ValueError(f"INTERNET.EXPOSED filter target columns are missing from source fields: {', '.join(missing)}")


def build_fieldnames(source_fields: List[str]) -> List[str]:
    validate_filter_targets(source_fields)
    filters_by_field: Dict[str, List[str]] = {}
    for definition in FILTER_DEFINITIONS:
        filters_by_field.setdefault(definition["field"], []).append(definition["name"])

    fieldnames = list(TECHNICAL_FIELDS)
    for field in source_fields:
        fieldnames.append(field)
        fieldnames.extend(filters_by_field.get(field, []))
    fieldnames.append(ALL_FILTERS_FIELD)
    return fieldnames


def apply_internet_exposed_filters(rows: List[Dict[str, Any]], filters: Dict[str, str]) -> None:
    for row in rows:
        filter_values = []
        for definition in FILTER_DEFINITIONS:
            filter_name = definition["name"]
            result = apply_filter(
                row.get(definition["field"], ""),
                parse_filter_tokens(filters, filter_name),
                definition["mode"],
            )
            row[filter_name] = result
            filter_values.append(result)
        row[ALL_FILTERS_FIELD] = "Y" if all(value == "Y" for value in filter_values) else "N"


def build_internet_exposed_query(cfg: Dict[str, Any], size: int) -> Dict[str, Any]:
    return {
        "_source": cfg["source_fields"],
        "query": {
            "bool": {
                "filter": [{"terms": {cfg["usage_field"]: cfg["usage_values"]}}],
                "should": [
                    {"terms": {cfg["dali_exposed_field"]: cfg["dali_exposed_values"]}},
                    {
                        "wildcard": {
                            cfg["masai_exposed_field"]: {
                                "value": cfg["masai_exposed_wildcard"],
                                "case_insensitive": True,
                            }
                        }
                    },
                ],
                "minimum_should_match": 1,
            }
        },
        "size": size,
        "sort": ["_doc"],
    }


def value_to_text(value: Any) -> str:
    if isinstance(value, list):
        return ", ".join(str(item) for item in value if str(item).strip())
    if value is None:
        return ""
    return str(value)


def annotate_scope(source: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    server_exposed = str(source.get("server_exposed") or "").strip().lower()
    masai_exposition = str(source.get("application_internet_exposition_masai") or "").strip().lower()
    is_dali = server_exposed == "yes"
    is_masai = "internet" in masai_exposition
    scopes = []
    if is_dali:
        scopes.append("DALI.EXPOSED")
    if is_masai:
        scopes.append("MASAI.EXPOSED")
    return {
        **{field: value_to_text(source.get(field, "")) for field in cfg["source_fields"]},
        "exposure_scopes": ", ".join(scopes),
        "is_dali_exposed": "Y" if is_dali else "N",
        "is_masai_exposed": "Y" if is_masai else "N",
    }


def dedupe_key(row: Dict[str, Any]) -> str:
    for field in ("server_uid", "server_hostname", "server_name", "server_friendly_name"):
        value = str(row.get(field) or "").strip().upper()
        if value:
            return f"{field}:{value}"
    return json.dumps(row, sort_keys=True, ensure_ascii=False)


def fetch_internet_exposed() -> List[Dict[str, Any]]:
    cfg = QUERY_CONFIG["internet_exposed"]
    client = Data4secClient()
    if not client.es_connection:
        raise RuntimeError("No Elasticsearch connection available for Data4Sec internet exposed extract")

    query = build_internet_exposed_query(cfg, size=QUERY_CONFIG.get("batch_size", 500))
    log.info("Data4Sec INTERNET.EXPOSED query index=%s payload=%s", cfg["index"], json.dumps(query, ensure_ascii=False))

    rows: List[Dict[str, Any]] = []
    seen = set()
    for hit in scan(
        client.es_connection,
        index=cfg["index"],
        query=query,
        scroll=QUERY_CONFIG.get("scroll_timeout", "10m"),
        size=QUERY_CONFIG.get("batch_size", 500),
    ):
        row = annotate_scope(hit.get("_source", {}) or {}, cfg)
        key = dedupe_key(row)
        if key not in seen:
            seen.add(key)
            rows.append(row)
    log.info("Data4Sec INTERNET.EXPOSED extract done rows=%s", len(rows))
    return rows


def write_csv(path: Path, rows: List[Dict[str, Any]], fieldnames: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_json_gz(path: Path, rows: List[Dict[str, Any]], query: Dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"meta": {"row_count": len(rows), "query": query}, "rows": rows}
    gz_path = path if path.suffix == ".gz" else path.with_suffix(path.suffix + ".gz")
    with gzip.open(gz_path, "wt", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
    return gz_path


def write_xlsx(path: Path, rows: List[Dict[str, Any]], fieldnames: List[str]) -> None:
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill

    filter_fieldnames = {definition["name"] for definition in FILTER_DEFINITIONS}
    filter_fieldnames.add(ALL_FILTERS_FIELD)

    path.parent.mkdir(parents=True, exist_ok=True)
    wb = Workbook()
    ws = wb.active
    ws.title = "RAW_INTERNET_EXPOSED"
    ws.append(fieldnames)
    for row in rows:
        ws.append([row.get(field, "") for field in fieldnames])
    header_fill = PatternFill("solid", fgColor="1F4E78")
    filter_fill = PatternFill("solid", fgColor="D9D9D9")
    header_font = Font(bold=True, color="FFFFFF")
    filter_columns = [idx for idx, field in enumerate(fieldnames, start=1) if field in filter_fieldnames]
    for cell in ws[1]:
        cell.fill = filter_fill if cell.value in filter_fieldnames else header_fill
        cell.font = header_font
    for row in ws.iter_rows(min_row=2, max_row=ws.max_row):
        for col_idx in filter_columns:
            row[col_idx - 1].fill = filter_fill
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = ws.dimensions
    stats = wb.create_sheet("STATS")
    stats.append(["metric", "value"])
    stats.append(["total_servers", len(rows)])
    stats.append(["dali_exposed_servers", sum(1 for r in rows if r.get("is_dali_exposed") == "Y")])
    stats.append(["masai_exposed_servers", sum(1 for r in rows if r.get("is_masai_exposed") == "Y")])
    stats.append(["distinct_application_uid", len({r.get("application_uid") for r in rows if str(r.get("application_uid") or "").strip()})])
    for cell in stats[1]:
        cell.fill = header_fill
        cell.font = header_font
    wb.save(path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Extract INTERNET.EXPOSED servers from Data4Sec dali_servers.")
    parser.add_argument("--output", required=True, help="Output XLSX path")
    parser.add_argument("--csv-out", help="Optional CSV output path")
    parser.add_argument("--json-out", help="Optional JSON.GZ output path")
    parser.add_argument("--filters-file", default="user_inputs/filters.conf", help="Filters configuration file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    setup_logging(args.verbose)
    cfg = QUERY_CONFIG["internet_exposed"]
    fieldnames = build_fieldnames(cfg["source_fields"])
    filters = read_filters_conf(args.filters_file)
    rows = fetch_internet_exposed()
    apply_internet_exposed_filters(rows, filters)
    output = Path(args.output)
    write_xlsx(output, rows, fieldnames)
    if args.csv_out:
        write_csv(Path(args.csv_out), rows, fieldnames)
    if args.json_out:
        gz_path = write_json_gz(Path(args.json_out), rows, build_internet_exposed_query(cfg, QUERY_CONFIG.get("batch_size", 500)))
        print(f"JSON.GZ written to: {gz_path}")
    print(f"INTERNET.EXPOSED rows: {len(rows)}")
    print(f"XLSX written to: {output}")


if __name__ == "__main__":
    main()
