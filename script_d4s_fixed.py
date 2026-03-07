import argparse
import csv
import json
import logging

from config import QUERY_CONFIG
from d4s_client import Data4secClient

log = logging.getLogger(__name__)


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")


def normalize_value(value: str) -> str:
    return value.strip().upper()


def read_input_values(input_file: str) -> list[str]:
    values = []
    seen = set()
    with open(input_file, "r", encoding="utf-8") as f:
        for raw_line in f:
            value = normalize_value(raw_line)
            if not value:
                continue
            if value not in seen:
                seen.add(value)
                values.append(value)
    return values


def pick_first_non_empty(docs: list[dict], output_fields: list[str]) -> dict:
    if not docs:
        return {}
    row = {}
    first = docs[0]
    for field in output_fields:
        val = first.get(field, "")
        if isinstance(val, list):
            val = ", ".join(str(x) for x in val if str(x).strip())
        row[field] = val
    return row


def query_mode(input_values: list[str], mode: str) -> list[dict]:
    cfg = QUERY_CONFIG[mode]
    index_name = cfg["index"]
    search_fields = cfg["search_fields"]
    source_fields = cfg["source_fields"]
    scroll_timeout = QUERY_CONFIG.get("scroll_timeout", "10m")
    batch_size = QUERY_CONFIG.get("batch_size", 500)

    client = Data4secClient()
    aggregated = {value: [] for value in input_values}

    for search_field in search_fields:
        log.info("Querying index=%s field=%s", index_name, search_field)
        result_map = client.bulk_search_multi(
            index_name=index_name,
            search_field=search_field,
            values=input_values,
            source_fields=source_fields,
            scroll_timeout=scroll_timeout,
            size=batch_size,
        )
        for input_value, docs in result_map.items():
            if docs:
                aggregated[input_value].extend(docs)

    rows = []
    for input_value in input_values:
        unique_docs = []
        fingerprints = set()
        for doc in aggregated.get(input_value, []):
            fp = json.dumps(doc, sort_keys=True, ensure_ascii=False)
            if fp not in fingerprints:
                fingerprints.add(fp)
                unique_docs.append(doc)

        if unique_docs:
            picked = pick_first_non_empty(unique_docs, source_fields)
            row = {"input_value": input_value, **picked, "lookup_status": "FOUND", "match_count": len(unique_docs)}
        else:
            row = {"input_value": input_value, **{field: "" for field in source_fields}, "lookup_status": "NOT_FOUND", "match_count": 0}
        rows.append(row)
    return rows


def write_csv(output_file: str, rows: list[dict], mode: str) -> None:
    source_fields = QUERY_CONFIG[mode]["source_fields"]
    fieldnames = ["input_value"] + source_fields + ["lookup_status", "match_count"]
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_json(output_file: str, rows: list[dict]) -> None:
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)


def parse_args():
    parser = argparse.ArgumentParser(description="Simple Data4Sec lookup on dali_servers or inventory.")
    parser.add_argument("input_file", help="CSV/text file without header, one value per line")
    parser.add_argument("-o", "--output", required=True, help="Output CSV file")
    parser.add_argument("--mode", choices=["dali_servers", "inventory"], default="dali_servers", help="Lookup mode")
    parser.add_argument("--json-out", help="Optional JSON output file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    return parser.parse_args()


def main():
    args = parse_args()
    setup_logging(args.verbose)
    input_values = read_input_values(args.input_file)
    rows = query_mode(input_values, args.mode)
    write_csv(args.output, rows, args.mode)
    if args.json_out:
        write_json(args.json_out, rows)

    found = sum(1 for row in rows if row["lookup_status"] == "FOUND")
    not_found = sum(1 for row in rows if row["lookup_status"] == "NOT_FOUND")
    print(f"D4S lookup completed on mode: {args.mode}")
    print(f"Total unique input values: {len(input_values)}")
    print(f"FOUND: {found} | NOT_FOUND: {not_found}")
    print(f"CSV written to: {args.output}")
    if args.json_out:
        print(f"JSON written to: {args.json_out}")


if __name__ == "__main__":
    main()
