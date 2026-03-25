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
- additional discovery step: inventory is queried by distinct **production** `INV_Beneficiary_Account` values only (matching `FILTER_PRD_ENV`, with status filtered to `Active` and `<unknown status>`), then DALI is queried first by discovered `ocs_name` hostnames (including variants); if no monitored application links are found, a fallback lookup by server `uid` is attempted
- final `FILTRED` output applies the `INV_Beneficiary_Account` filter only to rows where `cloud_type == "Gen 2"`, using tokens from `FILTER_PRD_ENV` (fallback: `PRD`, `DRP`, `BCK`); non-Gen2 rows are kept

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
- `export_iplists.csv`

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
