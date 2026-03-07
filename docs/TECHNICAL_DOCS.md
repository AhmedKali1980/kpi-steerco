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
- `user_inputs/`: manual user-provided inputs (including Excel files with KEAR IDs).

---

## 3. Environment Variables (`.env` at repository root)

The root `.env` centralizes all required credentials and connection settings.

### 3.1 Illumio PCE

- `PCE_L1_FQDN`
- `PCE_API_KEY`
- `PCE_API_SECRET`
- `PCE_ORG_ID`

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

### 4.4 `modules/dali_impact_analysis.py`

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
- Planned standard input: an Excel file containing KEAR IDs of applications to protect.

### Runtime outputs

- `RUNS/` stores generated outputs for each execution:
  - lookup CSV/JSON files
  - (future) KPI computation artifacts
  - (future) Excel dashboard deliverables

---

## 6. Known Gaps / Next Increments

1. Implement ingestion of KEAR IDs from Excel files in `user_inputs/`.
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
