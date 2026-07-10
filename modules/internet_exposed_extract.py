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


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")


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

    path.parent.mkdir(parents=True, exist_ok=True)
    wb = Workbook()
    ws = wb.active
    ws.title = "RAW_INTERNET_EXPOSED"
    ws.append(fieldnames)
    for row in rows:
        ws.append([row.get(field, "") for field in fieldnames])
    header_fill = PatternFill("solid", fgColor="1F4E78")
    header_font = Font(bold=True, color="FFFFFF")
    for cell in ws[1]:
        cell.fill = header_fill
        cell.font = header_font
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
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    setup_logging(args.verbose)
    cfg = QUERY_CONFIG["internet_exposed"]
    fieldnames = TECHNICAL_FIELDS + cfg["source_fields"]
    rows = fetch_internet_exposed()
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
