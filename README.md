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

Add `--endpoint-template` when the DALI endpoint is confirmed. Example: `api/v1/applications/{kear}`.

Filters are defined in `user_inputs/filters.conf` (format: `key,value`) and are loaded for future refinement logic.
