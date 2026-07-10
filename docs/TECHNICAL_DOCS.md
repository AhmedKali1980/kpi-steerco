# KPI SteerCo - Technical Documentation (Draft v0.3)

## 1. Project Overview

This project targets the production of **microsegmentation coverage KPIs** for servers linked to applications monitored by regulatory programs.

The expected deliverable is an **Excel dashboard** consolidating data from several sources:

- Illumio PCE
- application references (identified by **KEAR IDs**)
- network-zone and server metadata
- enterprise repositories (DALI, Elasticsearch/Data4Sec)

A global configuration file will define the list of applications and all attributes used for correlation and KPI computation.

---

## 2. Current Repository Structure

```text
kpi-steerco/
├── .env
├── bin/
├── docs/
│   └── TECHNICAL_DOCS.md
├── modules/
│   ├── config.py
│   ├── d4s_client.py
│   ├── dali_impact_analysis.py
│   ├── script_d4s.py
│   └── sg_cacert_file.py
├── RUNS/
├── user_inputs/
│   └── README.md
└── README.md
```

### Folder roles

- `bin/`: future executable wrappers and launch helpers.
- `docs/`: technical/functional documentation.
- `modules/`: Python source modules.
- `RUNS/`: runtime outputs (CSV/JSON exports, logs, generated dashboard files).
- `user_inputs/`: manual user-provided inputs (`monitored_kears.csv`, `headers.csv`, and other user files).

---

## 3. Environment Variables (`.env` at repository root)

The root `.env` centralizes all required credentials and connection settings.

### 3.1 Illumio PCE

- `PCE_L1_FQDN`
- `PCE_API_KEY`
- `PCE_API_SECRET`
- `PCE_ORG_ID`
- `PCE_L3SM_FQDN`
- `PCE_L3SM_API_KEY`
- `PCE_L3SM_API_SECRET`
- `PCE_L3SM_ORG_ID`
- `PCE_L1_NAME` (optional workloader PCE selector; auto-resolved from `CFG` + `PCE_L1_FQDN` when omitted)
- `PCE_L3SM_NAME` (optional workloader PCE selector; auto-resolved from `CFG` + `PCE_L3SM_FQDN` when omitted)

For `bin/cron_job.sh`, workloader credentials are read from `CFG` (`pce.yaml`) profiles. The `.env` API key/secret values are not required by this shell export flow.

### 3.2 DALI Aggregator + SGConnect OAuth2

- `DALI_BASE_URL`
- `SGMARKET_TOKEN_URL`
- `SGCONNECT_CLIENT_ID`
- `SGCONNECT_CLIENT_SECRET`
- `SGCONNECT_SCOPES`

### 3.3 Elasticsearch Data4Sec

- `ELASTICSEARCH_WRITE_HOST`
- `ELASTICSEARCH_WRITE_PORT`
- `ELASTICSEARCH_WRITE_LOGIN`
- `ELASTICSEARCH_WRITE_PASS`

### 3.4 TLS/Certificate Option

- `VERIFY_CA` (optional override for certificate bundle path/verification behavior)

---

## 4. Python Module Review (Current State)

### 4.1 `modules/config.py`

Defines configuration dictionaries loaded from `.env`:

- `ELASTICSEARCH`
- `PCE`
- `DALI`
- `QUERY_CONFIG` (lookup indexes, fields, scroll timeout, batch size)

### 4.2 `modules/d4s_client.py`

Provides `Data4secClient`:

- creates HTTPS Elasticsearch connection using basic auth + CA bundle
- builds multi-value terms queries
- executes scroll extraction with `elasticsearch.helpers.scan`
- returns a dictionary: `{input_value: [matching_documents]}`

### 4.3 `modules/script_d4s.py`

Current CLI flow:

1. read input values
2. normalize and deduplicate
3. query Data4Sec indexes according to selected mode
4. aggregate and deduplicate results
5. export CSV (mandatory) and JSON (optional)
6. print FOUND / NOT_FOUND summary

### 4.4 `modules/internet_exposed_extract.py`

Dedicated Data4Sec extract for the new `INTERNET.EXPOSED` perimeter.

- configuration is centralized in `QUERY_CONFIG["internet_exposed"]` and `INTERNET_EXPOSED_SOURCE_FIELDS` in `modules/config.py`
- source index: `dali_servers`
- common filter: `server_usage.keyword in ["In Use", "In use"]`
- `DALI.EXPOSED` condition: `server_exposed.keyword in ["Yes", "yes"]`
- `MASAI.EXPOSED` condition: case-insensitive wildcard `*internet*` on `application_internet_exposition_masai.keyword`
- the query uses one Elasticsearch `bool` request with `minimum_should_match: 1`, then annotates each row with `exposure_scopes`, `is_dali_exposed`, and `is_masai_exposed`
- outputs are an XLSX workbook (`RAW_INTERNET_EXPOSED` and `STATS` sheets), optional CSV, and optional compressed JSON

Example:

```bash
python modules/internet_exposed_extract.py --output RUNS/internet_exposed.xlsx --csv-out RUNS/internet_exposed.csv --json-out RUNS/internet_exposed.json -v
```

The orchestrator runs this module automatically after the PCE export step and before the historical DALI impact analysis, producing `internet_exposed_<timestamp>.xlsx`, `internet_exposed_<timestamp>.csv`, and `internet_exposed.json.gz` in `RUNS/<timestamp>/raw/`.

### 4.5 `modules/dali_impact_analysis.py`

Initial DALI integration module:

- validates required DALI/SGConnect settings from `.env`
- requests OAuth2 client-credentials access token
- provides generic API call helper to query DALI endpoints with bearer authentication

### 4.5 `modules/sg_cacert_file.py`

Finds a valid CA certificate bundle path by checking:

- dedicated environment variables
- known Linux certificate paths

Raises `FileNotFoundError` when no CA bundle is available.

---

## 5. Input/Output Conventions

### User inputs

- `user_inputs/` is the dedicated folder where users manually place source files.
- `monitored_kears.csv` contains 4 required columns: `kear`, `program`, `network`, `taken` (separator can be `,` or `;`).
- `headers.csv` contains 2 columns without header: output display name and equivalent DALI attribute (separator can be `,` or `;`).
- `filters.conf` is a simple `key,value` file for custom user filters (loaded for future refinement logic).
- These three files drive how each KEAR is processed and how DALI attributes are mapped in the output CSV.

### Runtime outputs

- `RUNS/` stores generated outputs for each execution:
  - lookup CSV/JSON files
  - (future) KPI computation artifacts
  - (future) Excel dashboard deliverables

---

## 6. Known Gaps / Next Increments

1. Implement ingestion of KEAR IDs from CSV files in `user_inputs/`.
2. Connect DALI extraction (`dali_impact_analysis.py`) to the KPI pipeline.
3. Add Illumio PCE connector and correlation with Elasticsearch and DALI data.
4. Build normalization and reconciliation for app/server/zone relationships.
5. Implement KPI computation logic (coverage by app/program).
6. Generate final Excel dashboard with KPI and drill-down tabs.

---

## 7. Execution Notes

Current lookup command example:

```bash
python modules/script_d4s.py user_inputs/input_values.txt -o RUNS/output.csv --mode dali_servers --json-out RUNS/output.json -v
```

Prerequisites:

- Python dependencies: `elasticsearch`, `python-dotenv`, `requests`
- root `.env` file with valid credentials
- valid CA bundle path detectable by `modules/sg_cacert_file.py`


### DALI export command

```bash
python modules/dali_impact_analysis.py --monitored-file user_inputs/monitored_kears.csv --headers-file user_inputs/headers.csv --filters-file user_inputs/filters.conf --output RUNS/dali_impact_analysis.csv -v
```

Use `--endpoint-template` to activate DALI API fetches once the target endpoint pattern is validated (example: `api/v1/applications/{kear}`).


## 8. KPI Orchestrator (initial engine)

`kpi_orchestrator.py` is the root engine script for the project initialization phase.

Current responsibilities:

1. create a timestamped run folder under `RUNS/`
2. create `RUNS/<timestamp>/raw/`
3. validate user inputs (`monitored_kears.csv`, `headers.csv`, `filters.conf`)
4. read DALI execution parameters from `.env` (`DALI_IMPACT_ENDPOINT`, `DALI_DEPTH_UNTIL`, `DALI_LIMIT`)
5. launch `modules/dali_impact_analysis.py` and execute real DALI `impactAnalysis` requests for each UID/KEAR
6. store outputs in `RUNS/<timestamp>/raw/` (`dali_impact_analysis.csv`, `dali_impact_analysis.json`)
7. log all orchestration steps to `RUNS/<timestamp>/execution.log`

Example command:

```bash
python kpi_orchestrator.py --verbose
```


### Note on local validation

Use `--dry-run` on `kpi_orchestrator.py` when credentials or network are not ready. In dry-run mode, the pipeline still validates inputs and output structure, but does not call DALI APIs.


### 4.7 Inventory enrichment on DALI FILTRED output

`modules/dali_impact_analysis.py` now executes a Data4Sec inventory enrichment step after DALI filtering:

1. read `cloud_type` and `hostname` columns from each FILTRED row
2. select only rows with `cloud_type = Gen 2`
3. query Data4Sec `inventory` using hostname terms (`hostname.keyword` + fallback `ocs_name.keyword`)
4. enforce `status in {Active, <unknown status>}` via query filters
5. append 3 columns in FILTRED exports:
   - `INV_ocs_name`
   - `INV_hostname`
   - `INV_Beneficiary_Account`

Special values:

- `NOT_GEN2` for rows where `cloud_type != Gen 2`
- `NOT_FOUND` when a Gen 2 hostname has no active inventory match

The orchestrator (`kpi_orchestrator.py`) uses this automatically because it already launches `modules/dali_impact_analysis.py`.
