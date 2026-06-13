# Step 02 - W02 DALI-only extract

## Purpose

Step 02 creates the base `W02` rows from DALI `impactAnalysis`. In the fork orchestrator, Step 02B then appends the fork-only inventory enrichment block after W03 has been built and after W01 has been completed with Not Business Account rows.

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

Default parameters are configured in `fork/modules/config.py` and match the parent project's DALI query contract:

| parameter | default | note |
| --- | --- | --- |
| `ciLabel` | `Application` | Required by DALI for application UID lookups. |
| `attributeName` | `uid` | The monitored UID is passed separately as `attributeValue`. |
| `attributeValue` | current monitored UID | Set per UID by the extractor. |
| `matchType` | `equals` | Same as the parent extractor. |
| `direction` | `to` | Same as the parent extractor. |
| `relationship` | parent relationship list | Includes `CHANGES`, `IS_ASSIGNED_TO`, `IS_HOSTED_BY`, `USE`, `CLUSTER_CONTAINS`, etc. |
| `impactedCis` | `Server` | W02 extracts impacted server edges. |
| `status` | `In use` | Same as the parent extractor. |
| `criticality` | `Critical`, `High`, `Medium`, `Low`, `Unknown` | Same as the parent extractor. |
| `includeLiveSources` | `true` | Same as the parent extractor. |
| `zones` | `EUR`, `ASIA`, `AMER`, `BCO`, `UK`, `Unknown` | Same as the parent extractor. |
| `environments` | `Production`, `Not in production` | Same as the parent extractor. |
| `excludeDuplicates` | `true` | Same as the parent extractor. |
| `boost` | `false` | Same as the parent extractor. |
| `includeGTSInfra` | `true` | Same as the parent extractor. |
| `includeCount` | `true` | Same as the parent extractor. |
| `skip` | `0` | Same as the parent extractor. |
| `depthUntil` | `8` | Can be overridden by `DALI_DEPTH_UNTIL`. |
| `limit` | `10000` | Can be overridden by `DALI_LIMIT`. |

Authentication uses SGConnect client credentials:

```text
SGMARKET_TOKEN_URL
SGCONNECT_CLIENT_ID
SGCONNECT_CLIENT_SECRET
SGCONNECT_SCOPES
```

The DALI request uses the returned bearer token. If `DALI_CLIENT_ID` is set, it is added to the DALI request using `DALI_CLIENT_ID_HEADER`, whose default is `x-client-id`.

## `W02` worksheet schema

The base `W02` extract contains the display columns declared in `headers.csv`, in the same order as the mapping file. The fork orchestrator then appends these inventory columns at the end of `W02`:

| Column | Fill rule |
| --- | --- |
| `INV_owner_account_id` | W01 `account_id` for the matched W03 `owner_app_name`, resolved after W01 contains both Business Account and Not Business Account entries. |
| `INV_owner_account_name` | W03 `owner_app_name` when `W03.Normalized_uuid_from_hostid` matches `W02.DALI [CI] SERVER UID`. |
| `INV_beneficiary_account_id` | W01 `account_id` for the matched W03 `beneficiary`, resolved after W01 contains both Business Account and Not Business Account entries. |
| `INV_beneficiary_account_name` | W03 `beneficiary` when `W03.Normalized_uuid_from_hostid` matches `W02.DALI [CI] SERVER UID`. |
| `INV_region` | W03 `region` when `W03.Normalized_uuid_from_hostid` matches `W02.DALI [CI] SERVER UID`. |
| `Gen 2 Asset linked to` | Copied from W03 `Asset linked to` (`Business Account` or `Not Business Account`) for matched Gen 2 rows; non-Gen2 rows are marked `NOT_GEN2`. |

For every W02 asset whose `DALI [CI] CLOUD TYPE` is different from `Gen 2`, Step 02B sets all six appended inventory columns to `NOT_GEN2`. For `Gen 2` assets, Step 02B matches `W02.DALI [CI] SERVER UID` with `W03.Normalized_uuid_from_hostid`, copies W03 owner, beneficiary, region and asset-linkage values, then resolves owner and beneficiary account ids through the completed W01 account dictionary. When a Gen 2 asset has no W03 match, the appended columns remain empty for later investigation.

The appended columns use a light green workbook background so they are visually distinct from the original DALI extract columns.

Operational context (`uid`, DALI count, errors, status per UID, raw responses) is kept outside the worksheet in the compressed JSON trace and in `execution.log`. If a UID returns no DALI edge, no data row is added to `W02` for that UID.

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
7. final base W02 row count,
8. Step 02B inventory enrichment start/end and match counters,
9. JSON trace location.

## Boundaries of this step

The base DALI extraction module still does not perform business filtering. The only orchestrated W02 enrichment currently appended in the fork is Step 02B inventory ownership/region lookup from W03. Step 02/02B does not run:

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
