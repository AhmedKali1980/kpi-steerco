# Fork - KPI workbook increments W01 + W02 + W03 + W04

This fork contains the clean incremental implementation used to build the KPI workbook step by step. The current scope is deliberately limited to the first four worksheet bricks:

1. `W01` - Kears/Accounts dictionary.
2. `W02` - DALI-only `impactAnalysis` extract.
3. `W03` - Data4Sec inventory extract by beneficiary account.
4. `W04` - Data4Sec Marley original assets extract by monitored UID.

The orchestration entry point is now `fork/kpi_orchestrator.py`. It calls the dedicated business modules and writes one workbook containing `Index`, `W01`, `W02`, `W03`, and `W04`.

## Workbook contract

### `Index`

The `Index` worksheet is the workbook dictionary. It contains one row per generated worksheet:

| worksheet | feature | description |
| --- | --- | --- |
| `W01` | Kears/Accounts dictionary | Describes the Data4Sec/platform_accounts account dictionary built from monitored KEAR UIDs. |
| `W02` | DALI impactAnalysis extract | Describes the raw DALI extraction performed for every distinct monitored UID. |
| `W03` | Inventory extract by beneficiary account | Describes the Data4Sec/inventory extraction performed with W01 `account_name` values as beneficiary accounts. |
| `W04` | Marley original assets by monitored UID | Describes the direct Data4Sec/marley_original extract performed with monitored `uid` values against `app_info.kear_uuid`. |

The index rows are configured centrally in `fork/modules/config.py` so every writer uses the same sheet dictionary.

### `W01` - Kears/Accounts dictionary

`W01` is produced by `fork/modules/dict_kears_accounts.py`.

What it does:

1. Reads distinct values from `fork/users_input/monitored_kears.csv`.
2. Accepts `uid` as the preferred input column and `kear` as a compatibility alias.
3. Queries the Data4Sec Elasticsearch index `platform_accounts` by looking for each UID in the `tags` field as `KEAR_SG_UID:<uid>`.
4. Writes exactly four columns:
   - `account_id` from the `id` field.
   - `account_name` from the `name` field.
   - `env_account` from `ENV:<environment>` or `is:env=<environment>` tags.
   - `KEAR_SG_UID` from the `KEAR_SG_UID:<uid>` tag.

### `W03` - Inventory extract by beneficiary account

`W03` is produced by `fork/modules/inventory_extract.py` and is the fork equivalent of the parent workbook sheet `get_inv_by_account`.

What it does:

1. Reuses distinct `account_name` values produced by `W01`.
2. Treats those accounts as Data4Sec inventory `beneficiary` values.
3. Queries the Data4Sec Elasticsearch index `inventory` with the same source fields and active/unknown status filter as the parent project.
4. Writes a stable extract-only set of columns: `input_INV_Beneficiary_Account`, `beneficiary`, `owner_app_name`, `ocs_name`, `hostname`, `status`, `region`, `hostid`, `Normalized_uuid_from_hostid`, `lookup_in_raw`, `srn`, `Normalized_uuid_from_srn`, `ip`, `service_name`.

See `fork/docs/W03_INVENTORY_EXTRACT.md` for the detailed W03 contract and parent-query mapping.

### `W04` - Marley original assets by monitored UID

`W04` is produced by `fork/modules/marley_extract.py` and is the clean fork equivalent of the Marley extraction part behind the parent `get_marley_gen2_by_uuid` worksheet, without the parent enrichment/filtering layers.

What it does:

1. Reads distinct `uid` values from `fork/users_input/monitored_kears.csv`.
2. Queries the Data4Sec Elasticsearch index `marley_original` on `app_info.kear_uuid`.
3. Reuses the Marley source fields and active/unknown status filter family from the parent query.
4. Writes only assets retrieved from Elasticsearch: no synthetic `NOT_FOUND` rows, no inventory enrichment, no PCE data, and no scope computation.
5. Resolves Marley `app_info` when it is returned as an object, a dotted field, or a list of application objects.
6. Writes a stable extract-only set of Marley columns including `input_uid`, asset identity fields, `app_info.*`, `net_info.net_ipadress`, OS, typology, DNS, status and usage.

See `fork/docs/W04_MARLEY_EXTRACT.md` for the detailed W04 contract and parent-query cleanup notes.

### `W02` - DALI-only extract

`W02` is produced by `fork/modules/dali_extract.py`.

What it does:

1. Reads the same monitored UID list from `fork/users_input/monitored_kears.csv`.
2. Reads DALI output mappings from `fork/users_input/headers.csv`.
3. Calls DALI `impactAnalysis` once per distinct UID.
4. Flattens each DALI edge into one Excel row.
5. Writes exactly the worksheet columns declared in `headers.csv`; no hidden technical/context columns are prepended.
6. Writes a compressed JSON trace next to the workbook for audit/debugging.

What it intentionally does **not** do:

- no Data4Sec inventory enrichment,
- no PCE workload/IP list correlation,
- no Marley enrichment,
- no scope computation,
- no exclusion handling,
- no KPI recaps,
- no PPTX generation,
- no email sending.

See `fork/docs/W02_DALI_EXTRACT.md` for the detailed W02 contract.

## Included files

- `kpi_orchestrator.py`: orchestrates W01 + W02 + W03 + W04 and writes the combined workbook.
- `build_dict_kears_accounts.py`: compatibility entry point for the first increment only.
- `modules/config.py`: Data4Sec, DALI and worksheet configuration.
- `modules/data4sec_client.py`: minimal Elasticsearch client for `platform_accounts`, `inventory`, and `marley_original`.
- `modules/input_reader.py`: strict monitored UID CSV reader.
- `modules/dict_kears_accounts.py`: business transformation for `W01` rows.
- `modules/dali_extract.py`: DALI-only extractor for `W02` rows.
- `modules/inventory_extract.py`: Data4Sec inventory extractor for `W03` rows.
- `modules/marley_extract.py`: Data4Sec Marley original extractor for `W04` rows.
- `modules/certificates.py`: CA bundle resolution for Elasticsearch.
- `users_input/monitored_kears.csv`: monitored UID input file.
- `users_input/headers.csv`: DALI output mapping file.
- `RUNS/`: output directory for timestamped workbooks, JSON traces and `execution.log`.
- `docs/W02_DALI_EXTRACT.md`: detailed documentation for the second brick.
- `docs/W03_INVENTORY_EXTRACT.md`: detailed documentation for the third brick.
- `docs/W04_MARLEY_EXTRACT.md`: detailed documentation for the fourth brick.

## Configuration

The fork loads environment variables from `fork/.env` first, then from the current working directory `.env`.

### Data4Sec settings for `W01`

```env
ELASTICSEARCH_WRITE_HOST=data4sec-api.fr.world.socgen
ELASTICSEARCH_WRITE_PORT=443
ELASTICSEARCH_WRITE_LOGIN=<login>
ELASTICSEARCH_WRITE_PASS=<password>
```

Optional Data4Sec overrides:

```env
PLATFORM_ACCOUNTS_INDEX=platform_accounts
PLATFORM_ACCOUNTS_TAGS_FIELD=tags
PLATFORM_ACCOUNTS_KEAR_TAG_KEY=KEAR_SG_UID
PLATFORM_ACCOUNTS_SCROLL_TIMEOUT=10m
PLATFORM_ACCOUNTS_BATCH_SIZE=500
```

### Data4Sec inventory settings for `W03`

```env
INVENTORY_INDEX=inventory
INVENTORY_BENEFICIARY_SEARCH_FIELD=beneficiary
INVENTORY_SCROLL_TIMEOUT=10m
INVENTORY_BATCH_SIZE=500
```

### Data4Sec Marley settings for `W04`

```env
MARLEY_ORIGINAL_INDEX=marley_original
MARLEY_ORIGINAL_UID_SEARCH_FIELD=app_info.kear_uuid
MARLEY_ORIGINAL_SCROLL_TIMEOUT=10m
MARLEY_ORIGINAL_BATCH_SIZE=500
```

### DALI settings for `W02`

```env
DALI_BASE_URL=<dali-base-url>
SGMARKET_TOKEN_URL=<oauth2-token-url>
SGCONNECT_CLIENT_ID=<client-id>
SGCONNECT_CLIENT_SECRET=<client-secret>
SGCONNECT_SCOPES=<scope>
DALI_CLIENT_ID=<optional-dali-client-id>
DALI_CLIENT_ID_HEADER=x-client-id
DALI_IMPACT_ENDPOINT=/api/v1/impactAnalysis
DALI_DEPTH_UNTIL=8
DALI_LIMIT=10000
```

The W02 impactAnalysis query intentionally reuses the same default query contract as the parent project: `ciLabel=Application`, `attributeName=uid`, `direction=to`, `impactedCis=Server`, the same relationship list, status, criticality, zones, environments, and count/dedup flags. Only `DALI_DEPTH_UNTIL` and `DALI_LIMIT` are exposed as routine run-time overrides.

Optional TLS override:

```env
VERIFY_CA=true
```

## Run the orchestrator

```bash
python fork/kpi_orchestrator.py --verbose
```

Default outputs:

```text
fork/RUNS/<timestamp>/
  execution.log
  kpi_steerco_<timestamp>.xlsx
  dali_extract.json.gz
```

The workbook contains:

```text
Index
W01
W02
W03
W04
```

## Run W02 alone for local checks

`fork/modules/dali_extract.py` can also be run directly when you only want to validate the DALI extract brick.

```bash
python fork/modules/dali_extract.py \
  --monitored-file fork/users_input/monitored_kears.csv \
  --headers-file fork/users_input/headers.csv \
  --output-file fork/RUNS/dali_extract_test.xlsx \
  --json-out fork/RUNS/dali_extract_test.json \
  --dry-run \
  --verbose
```

`--dry-run` skips live DALI calls and produces one `NOT_FOUND` trace row per monitored UID. It is intended for structural validation only.

## Run W04 alone for local checks

`fork/modules/marley_extract.py` can also be run directly when you only want to validate the Marley extract brick structure.

```bash
python fork/modules/marley_extract.py \
  --monitored-file fork/users_input/monitored_kears.csv \
  --output-file fork/RUNS/marley_extract_test.xlsx \
  --dry-run \
  --verbose
```

`--dry-run` skips Elasticsearch and writes the `W04` headers with zero rows. Live runs omit non-matching UIDs rather than creating `NOT_FOUND` rows.

## Execution logging

The orchestrator writes an `execution.log` in the same timestamped output directory as the workbook. It logs:

- orchestration start and input paths,
- step 01 start/end and `W01` row count,
- step 02 start/end, monitored UID count, DALI mapping count, per-UID progress, row count and error count,
- step 03 start/end and `W03` row count,
- step 04 start/end and `W04` row count,
- JSON trace path,
- final workbook path and workbook write counters for W01 through W04.
