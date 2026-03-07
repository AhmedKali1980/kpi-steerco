import argparse
import csv
import logging
import os
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


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


load_env_file()


class DaliImpactAnalysisClient:
    """DALI client used to retrieve an OAuth2 token and call DALI APIs."""

    def __init__(self) -> None:
        self.base_url = (os.getenv("DALI_BASE_URL") or "").rstrip("/")
        self.token_url = (os.getenv("SGMARKET_TOKEN_URL") or "").strip()
        self.client_id = (os.getenv("SGCONNECT_CLIENT_ID") or "").strip()
        self.client_secret = (os.getenv("SGCONNECT_CLIENT_SECRET") or "").strip()
        self.scopes = (os.getenv("SGCONNECT_SCOPES") or "").strip()
        self.verify = os.getenv("VERIFY_CA", True)

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

    def get_access_token(self) -> str:
        """Fetch OAuth2 token from SGConnect/SGMarkets token endpoint."""
        self._validate_settings()
        payload = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": self.scopes,
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        import requests

        response = requests.post(
            self.token_url,
            data=payload,
            headers=headers,
            timeout=30,
            verify=self.verify,
        )
        response.raise_for_status()
        body = response.json()
        token = body.get("access_token")
        if not token:
            raise RuntimeError("No access_token found in OAuth2 response")
        return token

    def call_api(self, endpoint: str, method: str = "GET", params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Call a DALI endpoint using bearer token authentication."""
        token = self.get_access_token()
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }
        import requests

        response = requests.request(
            method=method.upper(),
            url=url,
            params=params,
            headers=headers,
            timeout=60,
            verify=self.verify,
        )
        response.raise_for_status()
        return response.json()


def read_headers_mapping(headers_file: str) -> list[tuple[str, str]]:
    """Read headers.csv: two columns without header (display_name, dali_attribute)."""
    mappings: list[tuple[str, str]] = []
    with open(headers_file, "r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        for row in reader:
            display_name = str(row[0]).strip() if len(row) > 0 and row[0] else ""
            dali_attr = str(row[1]).strip() if len(row) > 1 and row[1] else ""
            if display_name and dali_attr:
                mappings.append((display_name, dali_attr))

    if not mappings:
        raise ValueError(f"No valid mappings found in {headers_file}")

    return mappings


def read_monitored_kears(monitored_file: str) -> list[dict[str, str]]:
    """Read monitored_kears.csv with required columns: kear, program, network, taken."""
    with open(monitored_file, "r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        headers = [h.strip().lower() for h in (reader.fieldnames or [])]
        required = ["kear", "program", "network", "taken"]
        missing = [col for col in required if col not in headers]
        if missing:
            raise ValueError(f"Missing required columns in {monitored_file}: {', '.join(missing)}")

        rows: list[dict[str, str]] = []
        for raw in reader:
            normalized = {str(k).strip().lower(): (str(v).strip() if v is not None else "") for k, v in raw.items()}
            kear = normalized.get("kear", "")
            if not kear:
                continue
            rows.append(
                {
                    "kear": kear,
                    "program": normalized.get("program", ""),
                    "network": normalized.get("network", ""),
                    "taken": normalized.get("taken", ""),
                }
            )

    if not rows:
        raise ValueError(f"No monitored KEAR rows found in {monitored_file}")

    return rows


def read_filters_conf(filters_file: str) -> dict[str, str]:
    """Read simple key,value custom filters file."""
    filters: dict[str, str] = {}
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


def flatten_api_payload(payload: Any) -> dict[str, Any]:
    if isinstance(payload, dict):
        return payload
    return {"raw_payload": payload}


def build_output_rows(
    monitored_kears: list[dict[str, str]],
    mappings: list[tuple[str, str]],
    dali_payload_by_kear: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for kear_row in monitored_kears:
        kear = kear_row["kear"]
        dali_doc = dali_payload_by_kear.get(kear, {})
        output = {
            "kear": kear,
            "program": kear_row["program"],
            "network": kear_row["network"],
            "taken": kear_row["taken"],
        }
        for display_name, dali_attr in mappings:
            value = dali_doc.get(dali_attr, "")
            if isinstance(value, list):
                value = ", ".join(str(v) for v in value if str(v).strip())
            output[display_name] = value
        rows.append(output)
    return rows


def write_output_csv(output_file: str, rows: list[dict[str, Any]], mappings: list[tuple[str, str]]) -> None:
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["kear", "program", "network", "taken"] + [display_name for display_name, _ in mappings]
    with open(output_file, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def fetch_dali_payloads(
    client: DaliImpactAnalysisClient,
    monitored_kears: list[dict[str, str]],
    endpoint_template: str | None,
) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}

    if not endpoint_template:
        for row in monitored_kears:
            results[row["kear"]] = {}
        return results

    for row in monitored_kears:
        kear = row["kear"]
        endpoint = endpoint_template.format(kear=kear)
        try:
            payload = client.call_api(endpoint=endpoint)
            results[kear] = flatten_api_payload(payload)
        except Exception as exc:
            log.error("Unable to fetch DALI data for kear=%s on endpoint=%s: %s", kear, endpoint, exc)
            results[kear] = {}

    return results


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="DALI impact analysis export based on monitored KEARs and header mapping.")
    parser.add_argument("--monitored-file", default="user_inputs/monitored_kears.csv", help="Path to monitored_kears.csv")
    parser.add_argument("--headers-file", default="user_inputs/headers.csv", help="Path to headers.csv")
    parser.add_argument("--filters-file", default="user_inputs/filters.conf", help="Path to filters.conf (key,value)")
    parser.add_argument("--output", default="RUNS/dali_impact_analysis.csv", help="Output CSV path")
    parser.add_argument(
        "--endpoint-template",
        help="Optional DALI endpoint template. Example: api/v1/applications/{kear}. If omitted, DALI calls are skipped.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    return parser.parse_args()


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s | %(levelname)s | %(name)s | %(message)s")


def main() -> None:
    args = parse_args()
    setup_logging(args.verbose)

    mappings = read_headers_mapping(args.headers_file)
    monitored_kears = read_monitored_kears(args.monitored_file)
    filters = read_filters_conf(args.filters_file) if Path(args.filters_file).is_file() else {}

    client = DaliImpactAnalysisClient()
    dali_payload_by_kear = fetch_dali_payloads(client, monitored_kears, args.endpoint_template)

    rows = build_output_rows(monitored_kears, mappings, dali_payload_by_kear)
    write_output_csv(args.output, rows, mappings)

    print(f"Monitored KEAR rows: {len(monitored_kears)}")
    print(f"Header mappings: {len(mappings)}")
    print(f"Custom filters loaded: {len(filters)}")
    print(f"Output CSV written to: {args.output}")
    if args.endpoint_template:
        print("DALI API calls enabled via endpoint template.")
    else:
        print("DALI API calls skipped (no --endpoint-template provided).")


if __name__ == "__main__":
    main()
