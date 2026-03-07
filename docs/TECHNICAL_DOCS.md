# KPI SteerCo - Technical Documentation (Draft v0.2)

## 1. Project Overview

This project targets the production of **microsegmentation coverage KPIs** for servers linked to applications monitored by regulatory programs.

The expected deliverable is an **Excel dashboard** consolidating data from several sources:

- Illumio PCE
- application references (identified by **KEAR IDs**)
- network-zone and server metadata
- enterprise repositories (currently Elasticsearch indexes)

A global configuration file will define the list of applications and all attributes used for correlation and KPI computation.

---

## 2. Current Repository Structure

```text
kpi-steerco/
├── bin/
├── docs/
│   └── TECHNICAL_DOCS.md
├── modules/
│   ├── config.py
│   ├── d4s_client.py
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

## 3. Python Module Review (Current State)

### 3.1 `modules/config.py`

Defines two configuration blocks:

1. **`ELASTICSEARCH`**
   - host / port / credentials from environment variables
   - `.env` loading via `python-dotenv`

2. **`QUERY_CONFIG`**
   - lookup modes:
     - `dali_servers`
     - `inventory`
   - per-mode parameters:
     - index name
     - search fields
     - source fields
   - shared extraction settings:
     - scroll timeout (`10m`)
     - batch size (`500`)

### 3.2 `modules/d4s_client.py`

Provides `Data4secClient`:

- creates HTTPS Elasticsearch connection using:
  - basic auth
  - certificate validation
  - CA bundle from `sg_cacert_file.get_cacert_path()`
- builds multi-value terms queries
- executes scroll extraction with `elasticsearch.helpers.scan`
- returns a dictionary: `{input_value: [matching_documents]}`

### 3.3 `modules/script_d4s.py`

Current CLI data flow:

1. read one input value per line
2. normalize and deduplicate values
3. query Elasticsearch for each configured search field
4. aggregate and deduplicate results
5. export CSV (mandatory) and JSON (optional)
6. print FOUND / NOT_FOUND summary

Output behavior:

- one line per input value
- for multiple matches, fields come from the first selected document
- `match_count` keeps the number of distinct matching documents

### 3.4 `modules/sg_cacert_file.py`

Finds a valid CA certificate bundle path by checking:

- dedicated environment variables
- known Linux certificate paths

Raises `FileNotFoundError` when no CA bundle is available.

---

## 4. Input/Output Conventions

### User inputs

- `user_inputs/` is the dedicated folder where users manually place source files.
- Planned standard input: an Excel file containing KEAR IDs of applications to protect.

### Runtime outputs

- `RUNS/` stores generated outputs for each execution:
  - lookup CSV/JSON files
  - (future) KPI computation artifacts
  - (future) Excel dashboard deliverables

---

## 5. Known Gaps / Next Increments

1. Implement ingestion of KEAR IDs from Excel files in `user_inputs/`.
2. Add Illumio PCE connector and correlation with Elasticsearch data.
3. Build normalization and reconciliation for app/server/zone relationships.
4. Implement KPI computation logic (coverage by app/program).
5. Generate final Excel dashboard with KPI and drill-down tabs.

---

## 6. Execution Notes

Current lookup command example:

```bash
python modules/script_d4s.py user_inputs/input_values.txt -o RUNS/output.csv --mode dali_servers --json-out RUNS/output.json -v
```

Prerequisites:

- Python dependencies: `elasticsearch`, `python-dotenv`
- `.env` file with Elasticsearch credentials
- valid CA bundle path detectable by `modules/sg_cacert_file.py`
