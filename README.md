# kpi-steerco

Repository for the KPI SteerCo initiative focused on microsegmentation coverage.

## Main folders

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
- additional discovery step: inventory is queried by distinct `INV_Beneficiary_Account` values (status filtered to `Active` and `<unknown status>`), then DALI is queried by the discovered `ocs_name` hostnames to append extra servers whose `uid` exists in `user_inputs/monitored_kears.csv`
- final `FILTRED` output keeps only rows where `INV_Beneficiary_Account` contains one of `PRD`, `DRP` or `BCK` (to keep production perimeter assets)

This enrichment reuses the shared Data4Sec client (`modules/d4s_client.py`) and `QUERY_CONFIG["inventory"]` in `modules/config.py`.
