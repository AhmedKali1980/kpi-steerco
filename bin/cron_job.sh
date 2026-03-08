#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BIN_DIR="${ROOT_DIR}/bin"
ENV_FILE="${ENV_FILE:-${ROOT_DIR}/.env}"
EXPORT_ROOT="${EXPORT_ROOT:-${ROOT_DIR}/RUNS}"
TIMESTAMP="$(date '+%Y%m%d_%H%M%S')"
RUN_DIR="${EXPORT_ROOT}/${TIMESTAMP}"
WORKLOADER_LOG="${RUN_DIR}/workloader.log"

mkdir -p "${RUN_DIR}"

if [[ ! -d "${BIN_DIR}" ]]; then
  echo "ERROR: bin directory not found at ${BIN_DIR}" >&2
  exit 2
fi

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "ERROR: .env file not found at ${ENV_FILE}" >&2
  exit 2
fi

WKLD_SCRIPT="${BIN_DIR}/workloader_wkld_m_export.sh"
IPL_SCRIPT="${BIN_DIR}/workloader_ipl_export.sh"

if [[ ! -x "${WKLD_SCRIPT}" ]]; then
  echo "ERROR: workload export script missing or not executable: ${WKLD_SCRIPT}" >&2
  exit 2
fi

if [[ ! -x "${IPL_SCRIPT}" ]]; then
  echo "ERROR: iplist export script missing or not executable: ${IPL_SCRIPT}" >&2
  exit 2
fi

exec > >(tee -a "${WORKLOADER_LOG}") 2>&1

echo "$(date '+%F %T') INFO cron_job started"
echo "$(date '+%F %T') INFO root_dir=${ROOT_DIR}"
echo "$(date '+%F %T') INFO run_dir=${RUN_DIR}"
echo "$(date '+%F %T') INFO env_file=${ENV_FILE}"

"${WKLD_SCRIPT}" "${RUN_DIR}/export_wkld.csv"
"${IPL_SCRIPT}" "${RUN_DIR}/export_iplists.csv"

echo "$(date '+%F %T') INFO cron_job completed successfully"
