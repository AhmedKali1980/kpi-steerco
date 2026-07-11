# kpi-steerco

Repository for the KPI SteerCo initiative focused on microsegmentation coverage.

## Main folders

- `docs/KPI_PROCESS_FLOWCHART.md`: end-to-end flowchart documentation for KPI process orchestration and generation.
- `docs/KPI_PROCESS_ALGORITHM.md`: detailed algorithm specification for KPI extraction, enrichment, filtering, and reporting.
- `modules/`: Python source modules (`config.py`, `d4s_client.py`, `script_d4s.py`, `sg_cacert_file.py`, `dali_impact_analysis.py`).
- `user_inputs/`: manual input files (including CSV files with KEAR IDs).
- `RUNS/`: run outputs and generated artifacts.
- `docs/`: project documentation.
- `bin/`: executable wrappers (future).

## Environment configuration

A root `.env` file is provided to centralize connection settings for:

- Illumio PCE
- DALI aggregator + SGConnect OAuth2 token service
- Elasticsearch Data4Sec

> Replace all placeholder credentials with valid production values before running in production.

## Current lookup command

```bash
python modules/script_d4s.py user_inputs/input_values.txt -o RUNS/output.csv --mode dali_servers --json-out RUNS/output.json -v
```

## INTERNET.EXPOSED extract

A dedicated extract is available for the new `INTERNET.EXPOSED` perimeter and is intentionally kept separate from the historical KPI workbook so the raw internet-exposed dataset can be transported independently.

```bash
python modules/internet_exposed_extract.py --output RUNS/internet_exposed.xlsx --csv-out RUNS/internet_exposed.csv --json-out RUNS/internet_exposed.json -v
```

The extractor queries the Data4Sec Elasticsearch index `dali_servers` with a single optimized boolean query:

- common filter: `server_usage.keyword in ["In Use", "In use"]`
- `DALI.EXPOSED`: `server_exposed.keyword in ["Yes", "yes"]`
- `MASAI.EXPOSED`: `application_internet_exposition_masai.keyword` wildcard `*internet*` with case-insensitive matching

Rows are annotated with `exposure_scopes`, `is_dali_exposed`, and `is_masai_exposed` so a server matching both criteria remains identifiable as both `DALI.EXPOSED` and `MASAI.EXPOSED`. The raw sheet also applies the `F_INTEXP.*` filters from `user_inputs/filters.conf`; each filter column is inserted immediately to the right of its target source column and the final `F_ALL_FILTERS` column is `Y` only when all INTERNET.EXPOSED filters are `Y`. The output workbook contains:

- `RAW_INTERNET_EXPOSED`: one row per deduplicated server and the requested Data4Sec attributes, including `application_uid`, with grey `Y`/`N` filter columns, inventory account id/env mapping columns, and light cell borders/autofit widths
- Gen 2 rows are enriched from Data4Sec `inventory` using `VM_<UPPER(server_uid)>` against `hostid`; the added columns are `INV_owner_app_name`, `PA_owner_id`, `INV_beneficiary`, `PA_beneficiary_id`, `PA_beneficiary_ENV`, and `INV_region`, placed immediately before `F_ALL_FILTERS`
- `STATS`: first-level counts for total servers, DALI-exposed servers, MASAI-exposed servers, and distinct application UIDs
- `DictAccount`: dictionary built from distinct `INV_owner_app_name` and `INV_beneficiary` accounts, enriched from Data4Sec `platform_accounts` into `account`, `id`, and `env` columns

`kpi_orchestrator.py` now runs this extract automatically and writes `internet_exposed_<timestamp>.xlsx`, `internet_exposed_<timestamp>.csv`, and `internet_exposed.json.gz` under `RUNS/<timestamp>/raw/`.


## DALI impact analysis command

```bash
python modules/dali_impact_analysis.py --monitored-file user_inputs/monitored_kears.csv --headers-file user_inputs/headers.csv --filters-file user_inputs/filters.conf --output RUNS/dali_impact_analysis.csv -v
```

The script performs real calls to DALI `impactAnalysis` (endpoint from `.env`: `DALI_IMPACT_ENDPOINT`, default `/api/v1/impactAnalysis`) for each `uid`/`kear` from `monitored_kears.csv`, then consolidates responses in JSON and flattened CSV outputs.

Filters are defined in `user_inputs/filters.conf` (format: `key,value`) and are loaded for future refinement logic. DALI depth/limit defaults are read from `.env` (`DALI_DEPTH_UNTIL`, `DALI_LIMIT`).


## Project orchestrator (initial step)

```bash
python kpi_orchestrator.py --verbose
# optional local test without DALI calls
# python kpi_orchestrator.py --dry-run --verbose
```

This creates `RUNS/<timestamp>/`, `RUNS/<timestamp>/raw/`, writes `execution.log`, and launches `modules/dali_impact_analysis.py` to produce CSV+JSON outputs under `raw/`.


### Data4Sec inventory enrichment in FILTRED sheet

`modules/dali_impact_analysis.py` now enriches the `FILTRED` output with Data4Sec `inventory` data:

- only rows where `cloud_type == "Gen 2"` are queried
- lookup input value comes from the `hostname` column
- query is restricted to `status in {Active, <unknown status>}`
- output columns added in `FILTRED`: `INV_ocs_name`, `INV_status`, `INV_hostname`, `Retrived from`, `INV_Owner_Account`, `INV_Beneficiary_Account`
- rows with `cloud_type != "Gen 2"` are filled with `NOT_GEN2`
- additional discovery step: inventory is queried by distinct `INV_Beneficiary_Account` values from Gen2 rows and uses `FILTER_PRD_ENV` tokens when defined. If `FILTER_PRD_ENV=all`, all environments are eligible.
- final `FILTRED` output applies the `INV_Beneficiary_Account` environment filter only to rows where `cloud_type == "Gen 2"`, using tokens from `FILTER_PRD_ENV` (fallback: `PRD`, `DRP`, `BCK`). If `FILTER_PRD_ENV=all`, no Gen2 environment exclusion is applied.

This enrichment reuses the shared Data4Sec client (`modules/d4s_client.py`) and `QUERY_CONFIG["inventory"]` in `modules/config.py`.

### Manual exclusion list in FILTRED scope

`modules/dali_impact_analysis.py` reads `user_inputs/servers_to_exclude.csv` (configurable via `--servers-to-exclude-file`) and applies a manual exclusion logic:

- hostnames are normalized (case-insensitive, short hostname comparison)
- lookup is performed against `HOSTNAME`, `USUAL NAME`, `FRIENDLY NAME` (only if no spaces), `INV_ocs_name`, and `INV_hostname`
- `F_Excluded` is added to `FILTRED` (`N` by default, `Y` when matched)
- matched rows are forced out of scope with `In scope = N`
- a dedicated `EXCLUDED` sheet is generated in XLSX with the requested traceability columns (`Retrived by`, `uid`, `short_label`, `DSI REL`, `DALI STATUS`, etc.)


## PCE exports (workloads + iplists)

The orchestrator now launches a dedicated PCE import step before DALI extraction.

- live mode: executes `bin/workloader_wkld_export.sh` and `bin/workloader_ipl_export.sh`
- stub mode: copies existing CSV files instead of querying PCE

Expected output files are always written to `RUNS/<timestamp>/raw/`:

- `export_wkld.csv`
- `export_wkld.l3sm.m.csv` (managed workloads exported from `PCE_L3SM_FQDN`, then appended into `export_wkld.csv`)
- `export_iplists.csv`

Live mode now runs the workload export in this order:

1. full workload export from `PCE_L1_FQDN` into `export_wkld.csv`
2. managed-only workload export (`wkld-export -m`) from `PCE_L3SM_FQDN` into `export_wkld.l3sm.m.csv`
3. append rows from `export_wkld.l3sm.m.csv` into `export_wkld.csv`
4. iplist export from `PCE_L1_FQDN` into `export_iplists.csv`

When multiple PCE profiles exist in the workloader config, you can explicitly select profile names with:

- `PCE_L1_NAME` (optional; if unset, auto-resolved from `CFG` using `PCE_L1_FQDN`, else workloader default profile is used)
- `PCE_L3SM_NAME` (recommended; if unset, auto-resolved from `CFG` using `PCE_L3SM_FQDN`)

Note: for workloader exports, authentication comes from `CFG` (`pce.yaml`). Duplicating `PCE_API_KEY`/`PCE_API_SECRET` in `.env` is not required by `bin/cron_job.sh`.

### Stub mode for faster development

```bash
python kpi_orchestrator.py --pce-stub-dir /path/to/stub_dir --dry-run --verbose
```

The stub directory must contain:

- `/path/to/stub_dir/export_wkld.csv`
- `/path/to/stub_dir/export_iplists.csv`

You can still skip this step explicitly:

```bash
python kpi_orchestrator.py --skip-pce-import --dry-run
```
