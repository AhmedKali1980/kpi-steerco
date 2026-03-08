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
import pathlib
import sys


def build_wkld_derived(path: pathlib.Path) -> pathlib.Path:
    derived = path.with_name(f"{path.stem}.derived{path.suffix}")
    with path.open("r", encoding="utf-8", newline="") as src, derived.open("w", encoding="utf-8", newline="") as dst:
        reader = csv.DictReader(src)
        if not reader.fieldnames or "hostname" not in reader.fieldnames:
            raise ValueError(f"Missing required 'hostname' column in {path}")

        columns = list(reader.fieldnames)
        hostname_idx = columns.index("hostname")
        out_columns = columns[: hostname_idx + 1] + ["short_hostname"] + columns[hostname_idx + 1 :]

        writer = csv.DictWriter(dst, fieldnames=out_columns)
        writer.writeheader()
        for row in reader:
            hostname = (row.get("hostname") or "").strip()
            short_hostname = hostname.split(".", 1)[0].upper()
            row["short_hostname"] = short_hostname
            writer.writerow(row)

    return derived


def build_ipl_derived(path: pathlib.Path) -> pathlib.Path:
    derived = path.with_name(f"{path.stem}.derived{path.suffix}")
    with path.open("r", encoding="utf-8", newline="") as src, derived.open("w", encoding="utf-8", newline="") as dst:
        reader = csv.DictReader(src)
        if not reader.fieldnames or "name" not in reader.fieldnames or "include" not in reader.fieldnames:
            raise ValueError(f"Missing required 'name/include' columns in {path}")

        writer = csv.DictWriter(dst, fieldnames=["name", "include"])
        writer.writeheader()
        for row in reader:
            name = (row.get("name") or "")
            if name.startswith("NZ3_"):
                writer.writerow({"name": name, "include": row.get("include") or ""})

    return derived


wkld_path = pathlib.Path(sys.argv[1])
ipl_path = pathlib.Path(sys.argv[2])

wkld_derived = build_wkld_derived(wkld_path)
ipl_derived = build_ipl_derived(ipl_path)

print(f"Derived workload CSV generated: {wkld_derived}")
print(f"Derived iplist CSV generated: {ipl_derived}")
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
