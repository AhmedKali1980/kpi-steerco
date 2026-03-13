#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${ENV_FILE:-${ROOT_DIR}/.env}"

RUN_DIR="${1:?run directory is required}"
RAW_DIR="${RUN_DIR}/raw"
WORKLOADER_LOG="${RUN_DIR}/workloader.log"

WKLD_SCRIPT="${SCRIPT_DIR}/workloader_wkld_export.sh"
IPL_SCRIPT="${SCRIPT_DIR}/workloader_ipl_export.sh"

STUB_DIR="${PCE_STUB_DIR:-}"
STUB_WKLD_FILE="${PCE_STUB_WKLD_FILE:-${STUB_DIR}/export_wkld.csv}"
STUB_IPL_FILE="${PCE_STUB_IPL_FILE:-${STUB_DIR}/export_iplists.csv}"

mkdir -p "${RAW_DIR}"

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "ERROR: .env file not found at ${ENV_FILE}" >&2
  exit 2
fi

if [[ ! -x "${WKLD_SCRIPT}" ]]; then
  echo "ERROR: workload export script missing or not executable: ${WKLD_SCRIPT}" >&2
  exit 2
fi

if [[ ! -x "${IPL_SCRIPT}" ]]; then
  echo "ERROR: iplist export script missing or not executable: ${IPL_SCRIPT}" >&2
  exit 2
fi

exec > >(tee -a "${WORKLOADER_LOG}") 2>&1

build_derived_exports() {
  local wkld_csv="$1"
  local ipl_csv="$2"

  python3 - "$wkld_csv" "$ipl_csv" <<'PY'
import csv
import ipaddress
import pathlib
import re
import sys
from typing import Iterable


def parse_include_subnets(include_value: str) -> list[ipaddress.IPv4Network]:
    subnets: list[ipaddress.IPv4Network] = []
    for raw_entry in (include_value or "").split(";"):
        token = raw_entry.strip()
        if not token:
            continue
        token = token.split("#", 1)[0].strip()
        if not token:
            continue
        try:
            network = ipaddress.ip_network(token, strict=False)
        except ValueError:
            continue
        if isinstance(network, ipaddress.IPv4Network):
            subnets.append(network)
    return subnets


def parse_ipv4_interfaces(interfaces_value: str) -> list[ipaddress.IPv4Address]:
    ipv4s: list[ipaddress.IPv4Address] = []
    seen: set[str] = set()

    for interface_entry in re.split(r"[;,]", interfaces_value or ""):
        item = interface_entry.strip()
        if not item:
            continue

        # Workload export formats can be: iface:ip, iface:ip/mask, or richer blobs.
        # We extract IPv4 tokens directly to avoid dropping valid IPs.
        for token in re.findall(r"(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?", item):
            try:
                if "/" in token:
                    ip = ipaddress.ip_interface(token).ip
                else:
                    ip = ipaddress.ip_address(token)
            except ValueError:
                continue

            if isinstance(ip, ipaddress.IPv4Address):
                rendered = str(ip)
                if rendered not in seen:
                    seen.add(rendered)
                    ipv4s.append(ip)

    return ipv4s


def build_ipl_derived(path: pathlib.Path) -> tuple[pathlib.Path, list[tuple[str, ipaddress.IPv4Network]]]:
    derived = path.with_name(f"{path.stem}.derived{path.suffix}")
    iplist_networks: list[tuple[str, ipaddress.IPv4Network]] = []

    with path.open("r", encoding="utf-8", newline="") as src, derived.open("w", encoding="utf-8", newline="") as dst:
        reader = csv.DictReader(src)
        if not reader.fieldnames or "name" not in reader.fieldnames or "include" not in reader.fieldnames:
            raise ValueError(f"Missing required 'name/include' columns in {path}")

        writer = csv.DictWriter(dst, fieldnames=["name", "include"])
        writer.writeheader()
        for row in reader:
            name = (row.get("name") or "").strip()
            include_value = (row.get("include") or "").strip()
            if not name.startswith("NZ3_"):
                continue

            writer.writerow({"name": name, "include": include_value})
            for subnet in parse_include_subnets(include_value):
                iplist_networks.append((name, subnet))

    return derived, iplist_networks


def find_first_match(
    ipv4_list: Iterable[ipaddress.IPv4Address],
    iplist_networks: Iterable[tuple[str, ipaddress.IPv4Network]],
) -> tuple[str, str]:
    for ipv4 in ipv4_list:
        for iplist_name, network in iplist_networks:
            if ipv4 in network:
                return iplist_name, str(network)
    return "", ""


def build_ocs_name_from_ip(ip_with_default_gw: str, os_id: str, managed: str) -> str:
    if (managed or "").strip().upper() != "TRUE":
        return ""

    ip = (ip_with_default_gw or "").strip()
    if not ip:
        return ""

    ip_slug = ip.replace(".", "-")
    if "win" in (os_id or "").strip().lower():
        return ip_slug
    return f"IP-{ip_slug}"


def build_wkld_derived(path: pathlib.Path, iplist_networks: list[tuple[str, ipaddress.IPv4Network]]) -> pathlib.Path:
    derived = path.with_name(f"{path.stem}.derived{path.suffix}")
    with path.open("r", encoding="utf-8", newline="") as src, derived.open("w", encoding="utf-8", newline="") as dst:
        reader = csv.DictReader(src)
        required_columns = {"hostname", "interfaces", "ip_with_default_gw", "os_id", "managed"}
        if not reader.fieldnames or not required_columns.issubset(reader.fieldnames):
            missing = sorted(required_columns.difference(set(reader.fieldnames or [])))
            raise ValueError(f"Missing required workload columns {','.join(missing)} in {path}")

        columns = list(reader.fieldnames)
        hostname_idx = columns.index("hostname")
        out_columns = columns[: hostname_idx + 1] + ["short_hostname"] + columns[hostname_idx + 1 :]
        out_columns.extend(["ocs_name_from_IP", "IPLIST", "SUBNET"])

        writer = csv.DictWriter(dst, fieldnames=out_columns)
        writer.writeheader()
        for row in reader:
            hostname = (row.get("hostname") or "").strip()
            row["short_hostname"] = hostname.split(".", 1)[0].upper()
            row["ocs_name_from_IP"] = build_ocs_name_from_ip(
                row.get("ip_with_default_gw") or "",
                row.get("os_id") or "",
                row.get("managed") or "",
            )

            ipv4_list = parse_ipv4_interfaces(row.get("interfaces") or "")
            iplist_name, subnet = find_first_match(ipv4_list, iplist_networks)
            row["IPLIST"] = iplist_name
            row["SUBNET"] = subnet
            writer.writerow(row)

    return derived


wkld_path = pathlib.Path(sys.argv[1])
ipl_path = pathlib.Path(sys.argv[2])

ipl_derived, iplist_networks = build_ipl_derived(ipl_path)
wkld_derived = build_wkld_derived(wkld_path, iplist_networks)

print(f"Derived iplist CSV generated: {ipl_derived}")
print(f"Derived workload CSV generated: {wkld_derived}")
print(f"Subnet entries parsed from iplists: {len(iplist_networks)}")
PY
}

echo "$(date '+%F %T') INFO pce import started"
echo "$(date '+%F %T') INFO root_dir=${ROOT_DIR}"
echo "$(date '+%F %T') INFO run_dir=${RUN_DIR}"
echo "$(date '+%F %T') INFO raw_dir=${RAW_DIR}"

if [[ -n "${STUB_DIR}" ]]; then
  echo "$(date '+%F %T') INFO stub mode enabled: ${STUB_DIR}"
  [[ -s "${STUB_WKLD_FILE}" ]] || { echo "ERROR: missing workload stub file: ${STUB_WKLD_FILE}"; exit 2; }
  [[ -s "${STUB_IPL_FILE}" ]] || { echo "ERROR: missing iplist stub file: ${STUB_IPL_FILE}"; exit 2; }

  cp "${STUB_WKLD_FILE}" "${RAW_DIR}/export_wkld.csv"
  cp "${STUB_IPL_FILE}" "${RAW_DIR}/export_iplists.csv"
  echo "$(date '+%F %T') INFO stub files copied into ${RAW_DIR}"
else
  "${WKLD_SCRIPT}" "${RAW_DIR}/export_wkld.csv"
  "${IPL_SCRIPT}" "${RAW_DIR}/export_iplists.csv"
fi

build_derived_exports "${RAW_DIR}/export_wkld.csv" "${RAW_DIR}/export_iplists.csv"

echo "$(date '+%F %T') INFO pce import completed successfully"
