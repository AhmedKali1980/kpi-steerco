# KPI SteerCo - Technical Documentation (Draft v0.1)

## 1. Project Overview

This project aims to produce **microsegmentation coverage KPIs** for servers attached to applications monitored by regulatory programs.

The target end result is an **Excel dashboard** that consolidates information from multiple data sources:

- Illumio PCE data
- Application reference data (identified by **KEAR IDs**)
- Network-zone and server metadata
- Existing enterprise repositories (initially Elasticsearch indexes)

A global configuration file will provide the list of applications and the attributes/parameters to consider during KPI calculation.

---

## 2. Current Repository Structure

At this stage, the repository contains:

- `config_fixed.py`: connection and query configuration.
- `d4s_client_fixed.py`: Elasticsearch client wrapper and bulk lookup helper.
- `script_d4s_fixed.py`: command-line extraction script (input list -> enriched output).
- `sg_cacert_file.py`: CA certificate path resolver.
- `README.md`: minimal project placeholder.

Project folders initialized for future increments:

- `bin/`: executable scripts and entry points.
- `docs/`: technical/functional documentation.
- `RUNS/`: execution artifacts (exports, logs, run outputs).

---

## 3. Script Review (Current State)

### 3.1 `config_fixed.py`

Defines two main configuration blocks:

1. **`ELASTICSEARCH`**
   - Reads host, port, username, and password from environment variables.
   - Uses `python-dotenv` (`load_dotenv`) to load values from a `.env` file.

2. **`QUERY_CONFIG`**
   - Defines lookup modes:
     - `dali_servers`
     - `inventory`
   - Each mode contains:
     - target index name
     - searchable fields
     - source fields to return in output
   - Common query settings:
     - scroll timeout (`10m`)
     - batch size (`500`)

### 3.2 `d4s_client_fixed.py`

Provides class `Data4secClient`:

- Creates an HTTPS Elasticsearch connection with:
  - Basic auth
  - TLS verification
  - CA bundle path from `sg_cacert_file.get_cacert_path()`
- Builds a terms query for multi-value search (`build_terms_query`).
- Executes scroll-based extraction using `elasticsearch.helpers.scan` (`bulk_search_multi`).
- Returns a mapping `{input_value: [matching_documents]}`.

Important behavior:

- Input matching is normalized to uppercase.
- Supports multi-valued fields in Elasticsearch documents.
- Returns empty lists when connection/search fails.

### 3.3 `script_d4s_fixed.py`

CLI workflow:

1. Reads one input value per line from a text/CSV-like file (no header).
2. Normalizes values (`strip + uppercase`) and deduplicates.
3. For each configured search field in the selected mode:
   - calls `Data4secClient.bulk_search_multi`
4. Aggregates and de-duplicates matching documents.
5. Produces:
   - CSV output (required)
   - JSON output (optional)
6. Prints execution summary (FOUND / NOT_FOUND counts).

Current output semantics:

- One output row per input value.
- If multiple matches are found, only the first document is used for field values, while `match_count` stores total distinct matches.

### 3.4 `sg_cacert_file.py`

Resolves the first existing CA certificate file from:

- dedicated env vars (`ELASTICSEARCH_CA_CERT`, `ELASTICSEARCH_CA_CERTS`, etc.)
- common Linux system certificate paths

Raises `FileNotFoundError` if no candidate exists.

---

## 4. Technical Observations / Gaps to Address

1. **Module naming consistency**
   - `script_d4s_fixed.py` imports `from config import ...` and `from d4s_client import ...`
   - `d4s_client_fixed.py` imports `from config import ...`
   - Current file names include `_fixed`, so imports may fail unless mirrored files/symlinks exist.

2. **Output model limitations**
   - Multi-match handling currently keeps only one representative document in CSV columns.
   - A richer output may be needed for KPI-grade traceability.

3. **Data-source scope**
   - Current scripts are focused on Elasticsearch lookups.
   - Future increments must integrate Illumio PCE and KEAR-driven application inputs.

4. **KPI pipeline not yet implemented**
   - No KPI computation logic yet (coverage rates, segmentation status by app/program, zone recoupling).
   - No Excel dashboard generator yet.

---

## 5. Proposed Next Increment (High-Level)

1. Define a **global configuration schema**:
   - application list (KEAR IDs)
   - regulator program mapping
   - network-zone attributes
   - KPI formulas and thresholds

2. Build data ingestion adapters:
   - Elasticsearch adapter (existing base)
   - Illumio PCE adapter
   - optional file-based reference loaders

3. Implement a normalization & correlation layer:
   - server identity reconciliation
   - app-server-zone joins
   - protection status harmonization

4. Implement KPI computation:
   - coverage per app
   - coverage per program
   - protected vs non-protected server ratios

5. Generate Excel dashboard in `RUNS/`:
   - KPI summary sheet
   - application detail sheet
   - exception/not-found sheet

---

## 6. Execution Notes (Current)

When module names are aligned, an example command is:

```bash
python script_d4s_fixed.py input_values.txt -o RUNS/output.csv --mode dali_servers --json-out RUNS/output.json -v
```

Environment prerequisites:

- Python dependencies: `elasticsearch`, `python-dotenv`
- `.env` with Elasticsearch credentials
- valid CA bundle path resolvable by `sg_cacert_file.py`

---

## 7. Status

This document is the initial technical baseline for the new project kickoff.
It will be expanded in the next increments with:

- finalized architecture
- data contracts
- KPI formulas
- Excel dashboard design
- runbook and operational guidance
