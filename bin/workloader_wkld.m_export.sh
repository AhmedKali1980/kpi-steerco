#!/usr/bin/env bash
set -Eeuo pipefail
source "$(dirname "$0")/workloader_common.sh"

OUT="${1:?output csv}"
mkdir -p "$(dirname "$OUT")"

HEADERS='href,hostname,name,external_data_set,created_at,interfaces,public_ip,ip_with_default_gw,app,env,loc,role,managed,enforcement,external_data_reference,OS,os_id'
retry_backoff "wkld-export-managed" -- wkld-export -m --headers "$HEADERS" --output-file "$OUT"
