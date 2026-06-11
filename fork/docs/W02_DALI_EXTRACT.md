# Step 02 - W02 DALI-only extract

## Purpose

Step 02 creates the `W02` worksheet. This worksheet is the raw DALI extraction layer of the KPI workbook. Its only responsibility is to query DALI `impactAnalysis` for every distinct monitored UID and to flatten the returned DALI edges into tabular Excel rows.

This step is intentionally narrow. It must remain an extract-only brick so the following pipeline steps can be added and tested independently.

## Source files

### `fork/users_input/monitored_kears.csv`

The input file provides the application scope to query in DALI.

Accepted UID columns:

- `uid` - preferred column name.
- `kear` - compatibility alias.

Additional context columns are preserved in `W02` when present:

- `program`
- `network`
- `taken`
- `short_label`
- `slide`

The extractor de-duplicates UIDs while preserving their original order. If the same UID appears multiple times, DALI is called once for that UID in this extract-only step.

### `fork/users_input/headers.csv`

The DALI mapping file has two columns and no header row:

| column | meaning |
| --- | --- |
| 1 | Excel display column name |
| 2 | DALI attribute to extract |

Example:

```csv
Application Name,application_name
Environment,application_dali_environment
Server Status,server.status
Server Count,total_hosts
```

Supported DALI attribute forms:

| mapping form | behavior |
| --- | --- |
| `<attr>` | Reads the attribute from the leading node first, then from the trailing node. |
| `leading.<attr>` | Reads the attribute only from `leading_node.properties`. |
| `trailing.<attr>` | Reads the attribute only from `trailing_node.properties`. |
| `server.<attr>` | Reads the attribute from whichever edge node has the `Server` label. |
| `application.<attr>` | Reads the attribute from whichever edge node has the `Application` label. |

## DALI call contract

The extractor calls the configured DALI endpoint once per distinct UID.

Default endpoint:

```text
/api/v1/impactAnalysis
```

Default parameters are configured in `fork/modules/config.py` and can be overridden through environment variables:

| parameter | default | env override |
| --- | --- | --- |
| `attributeType` | `uid` | `DALI_ATTRIBUTE_TYPE` |
| `attributeValue` | current monitored UID | not static; set per UID |
| `impactType` | `Applicative` | `DALI_IMPACT_TYPE` |
| `depthUntil` | `8` | `DALI_DEPTH_UNTIL` |
| `limit` | `10000` | `DALI_LIMIT` |

Authentication uses SGConnect client credentials:

```text
SGMARKET_TOKEN_URL
SGCONNECT_CLIENT_ID
SGCONNECT_CLIENT_SECRET
SGCONNECT_SCOPES
```

The DALI request uses the returned bearer token. If `DALI_CLIENT_ID` is set, it is added to the DALI request using `DALI_CLIENT_ID_HEADER`, whose default is `x-client-id`.

## `W02` worksheet schema

The first columns are fixed context and traceability columns:

| column | description |
| --- | --- |
| `uid` | Distinct UID read from `monitored_kears.csv`. |
| `kear` | KEAR value when present, otherwise the UID. |
| `program` | Program context copied from the input file when present. |
| `network` | Network context copied from the input file when present. |
| `taken` | Input flag copied from the input file when present. |
| `short_label` | Optional input label copied from the input file. |
| `slide` | Optional slide indicator copied from the input file. |
| `Server UID` | UID of the DALI node labeled `Server` when an edge contains one. |
| `lookup_status` | Extraction status for the UID/edge. |
| `count` | DALI response count for the UID. |
| `error` | Error text when the DALI call fails. |

The remaining columns are appended from `headers.csv` in the same order as the mapping file.

## Lookup statuses

| status | meaning |
| --- | --- |
| `FOUND` | DALI returned one or more edges. One row is written per returned edge. |
| `NOT_FOUND` | DALI responded successfully but no edge was available to flatten. One trace row is written for the UID. |
| `ERROR` | The DALI call failed. One trace row is written for the UID with the error message. |

## JSON trace

The orchestrator writes a compressed JSON trace next to the workbook:

```text
fork/RUNS/<timestamp>/dali_extract.json.gz
```

The JSON payload contains:

- `meta.generated_at`
- `meta.job_started_at`
- `meta.job_end_at`
- `meta.dali_base_url`
- `meta.endpoint`
- `meta.uid_count`
- `meta.success_count`
- `meta.found_uid_count`
- `meta.error_count`
- `meta.row_count`
- `meta.depth_until`
- `meta.limit`
- `meta.dry_run`
- `items[]` with the raw DALI response per UID
- `errors[]` with per-UID failures

## Logging in `execution.log`

Step 02 logs are written by the orchestrator into the timestamped `execution.log` file. The log includes:

1. start of the W02 step,
2. monitored UID count,
3. header mapping count,
4. per-UID progress,
5. per-UID row count,
6. DALI errors when any UID fails,
7. final W02 row count,
8. JSON trace location.

## Boundaries of this step

Step 02 does not perform any enrichment or business filtering. In particular, it does not run:

- Data4Sec inventory lookups,
- PCE exports,
- workload/IP list correlation,
- Marley lookups,
- scope computation,
- manual exclusions,
- KPI recap generation,
- PowerPoint generation,
- email notification.

These responsibilities belong to later bricks.

## Commands

### Full W01 + W02 orchestration

```bash
python fork/kpi_orchestrator.py --verbose
```

### W02-only dry run

```bash
python fork/modules/dali_extract.py \
  --monitored-file fork/users_input/monitored_kears.csv \
  --headers-file fork/users_input/headers.csv \
  --output-file fork/RUNS/dali_extract_test.xlsx \
  --json-out fork/RUNS/dali_extract_test.json \
  --dry-run \
  --verbose
```
