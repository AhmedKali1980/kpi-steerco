# KPI Pipeline Algorithm Specification (Detailed)

## Objective

Define, in an implementation-faithful way, the algorithm used to compute and generate KPI outputs (RAW/FILTRED/diagnostic sheets) from DALI, Data4Sec, and PCE-derived workload metadata.

---

## 1. Inputs, Parameters, and Preconditions

### 1.1 Mandatory functional inputs

1. **Monitored applications file** (`monitored_kears.csv`): provides `uid`/`kear`, `program`, `network`, `taken`.
2. **Header mapping file** (`headers.csv`): maps output display columns to DALI attributes.
3. **Filters file** (`filters.conf`): key/value configuration for inclusion/exclusion rules.

### 1.2 Runtime/system inputs

4. `.env` with DALI auth/token endpoint and Data4Sec connection settings.
5. PCE exports (`export_wkld.csv`, `export_iplists.csv`) or their stub equivalents.
6. Optional `servers_to_exclude.csv` manual override list.

### 1.3 Preconditions

- `.env` is readable.
- Required input files exist.
- If PCE import is enabled: workload and iplist scripts are executable and produce non-empty files.

---

## 2. High-Level Algorithm

### Phase A — Orchestration bootstrap

1. Load `.env` values into process environment (without overriding already-defined env vars).
2. Create run folder structure: `RUNS/<UTC_timestamp>/raw`.
3. Initialize structured logging to both stdout and `execution.log`.
4. Execute PCE import unless explicitly skipped.
5. Validate user input files.
6. Build DALI extraction command with effective `impact_endpoint`, `limit`, and `depth_until`.
7. Execute `modules/dali_impact_analysis.py` as subprocess.
8. Validate expected outputs (`.xlsx` and `.json.gz`) and parse JSON meta for post-run safety checks.

### Phase B — DALI extraction and row materialization

9. Parse CLI args and load mappings/monitored rows/filters.
10. For each monitored UID:
    - Build impactAnalysis request parameters from defaults + UID + depth/limit.
    - Call DALI endpoint with OAuth2 bearer token (cached with expiry).
    - Apply retry strategy for transient HTTP failures.
    - Cache response per UID to avoid duplicate calls.
11. Convert each DALI response into:
    - **RAW rows** (no filtering gate, one extraction flow per distinct `uid`).
    - **FILTRED rows** (must pass all filter predicates, program/network/taken kept for business scope).

### Phase C — Gen2 inventory enrichment

12. From FILTRED, select Gen2 rows and collect normalized server UIDs.
13. Query Data4Sec `inventory` by hostid/srn strategy.
14. Enrich each Gen2 row with:
    - `INV_ocs_name`, `INV_status`, `INV_hostname`, `Retrived from`,
    - `INV_Owner_Account`, `INV_Beneficiary_Account`.
15. For non-Gen2 rows, set inventory columns to `NOT_GEN2`.
16. Apply beneficiary exclusion tokens (`FILTER_BENEFICIARY_NOT_TAKEN`) and production-scope beneficiary filtering (`FILTER_PRD_ENV`) on Gen2 rows.

### Phase D — Workload, Marley, and scope consolidation

17. Enrich SCOPE candidate rows with workload-derived attributes (`managed`, `IPLIST`, `SUBNET`, etc.) by hostname candidate matching.
18. Build `Dict_Kear_Account` pivot from existing Gen2 DALI-export rows.
19. Query Marley index from inventory-derived UUID candidates.
20. Filter Marley rows with strict eligibility gates (status/usage/in-scope/not-already-present/filter compatibility).
21. Append eligible Marley rows to SCOPE candidate using mapping table rules and monitored UID context.
22. Compute `In scope` based on network/IPLIST consistency.
23. Deduplicate SCOPE candidate rows by application/program/server identity and ranking strategy.
24. Apply manual exclusion list; force excluded rows out of scope and generate exclusion traceability rows.

### Phase E — KPI artifacts generation

25. Write RAW CSV and FILTRED CSV.
26. Write compressed JSON payload (`.json.gz`).
27. Build summary metrics and KPI recap sheets (computed from final SCOPE):
    - STATS, TOTAL.PROGRAM, TOTAL.ENTITY,
    - KearLabelsAccounts,
    - EXCLUDED and diagnostic sheets.
28. Build final XLSX workbook with formatted sheets and conditional visual cues.
29. Print runtime summary and artifact paths.

---

## 3. Detailed Algorithmic Rules

### 3.1 DALI call and resilience logic

- **Token management**: OAuth2 client credentials, cached with early refresh margin.
- **Retries**: for 429/5xx statuses and request exceptions, using exponential backoff + jitter.
- **Auth refresh**: 401/403 can trigger token refresh and retry.
- **Batch continuity**: a UID-level failure does not stop the full run; errors are recorded in payload.

### 3.2 Row extraction from DALI response

For each edge:

1. Extract leading/trailing node properties.
2. Resolve `Server UID` from node labeled `Server`.
3. For each header mapping, resolve value using scoped logic:
   - `leading.<attr>`, `trailing.<attr>`, `server.<attr>`, `application.<attr>`, or fallback search order.
4. Populate debug filter columns (`FILTER_VALUE_*`, `F_FILTER_*`, `F_FILTER_ALL`).
5. Emit row into RAW always; emit into FILTRED only if `_edge_matches_filters == True`.

Special cases:

- If response is empty => one `NOT_FOUND` row.
- If error occurred => one `ERROR` row with empty mapped fields.

### 3.3 Filter predicate semantics

A FILTRED row is accepted only if all active predicates pass:

1. `environment` contains one of `FILTER_PRD_ENV` tokens (if configured).
2. `os_name` exactly matches one of `FILTER_OS_NAME` tokens (if configured).
3. `Server Status` matches `FILTER_SERVER_STATUS` (if configured).
4. `cloud_type` does **not** contain forbidden tokens (`FILTER_CLOUD_TYPE_NOT_TAKEN`).
5. `main_application` does **not** contain forbidden tokens (`FILTER_MAIN_APP_NOT_TAKEN`).
6. `typology` does **not** contain forbidden tokens (`FILTER_TYPOLOGY_NOT_TAKEN`).
7. `dns_name`/domain does **not** contain forbidden tokens (`FILTER_DOMAIN_NOT_TAKEN`).

### 3.4 Inventory lookup strategy by server UID

For each normalized server UID:

1. Build candidate lookup values (`hostid` and `srn`) from UID variants.
2. Query inventory index via configured search fields.
3. Deduplicate matched docs.
4. Pick first effective row and normalize status/hostname.
5. Mark retrieval source in `Retrived from`.

Outputs are keyed by normalized server UID.

### 3.5 Scope computation logic

`In scope` is determined as:

- `TRUE` if network is empty **or** contains `L1`.
- Else `TRUE` if normalized `network` is contained in normalized `IPLIST`.
- Else `FALSE`.

`F_Excluded` defaults to `N`, then may be set to `Y` by manual exclusions.

### 3.6 Deduplication policy

Deduplication key: `(uid, program, server_identity, taken)` where `server_identity = Server UID or short hostname or ROW_<index>`.

When duplicates exist, keep row with ranking:

1. best: `network` matches `IPLIST`,
2. next: empty `IPLIST`,
3. otherwise: first row.

### 3.7 Manual exclusion policy

1. Read exclusion values from `servers_to_exclude.csv`.
2. Normalize hostnames (case-insensitive, short-name comparison).
3. Match against lookup columns in priority order:
   - `HOSTNAME`, `USUAL NAME`, `FRIENDLY NAME` (no spaces), `INV_ocs_name`, `INV_hostname`.
4. If matched: set `F_Excluded=Y`, force `In scope=FALSE`.
5. Emit one EXCLUDED trace row per input exclusion value (matched or unmatched).

### 3.8 Marley append logic (controlled enrichment)

1. Build candidate Marley rows from inventory-by-account lookup UUIDs.
2. Mark if Marley app UID is in monitored scope.
3. Apply keep criteria (`F_final_keep`):
   - lookup FOUND,
   - status Active,
   - usage In use,
   - UUID not already in FILTRED,
   - owner/main app/env/os/account rules satisfied.
4. Map Marley + inventory fields into FILTRED schema via mapping table.
5. Append only non-duplicate `(uid, Server UID)` pairs.

---

## 4. Outputs and KPI-Ready Artifacts

### 4.1 Core artifacts

- `dali_impact_analysis_<timestamp>_RAW.csv`
- `dali_impact_analysis_<timestamp>_FILTRED.csv`
- `dali_impact_analysis.json.gz`
- `dali_impact_analysis_<timestamp>.xlsx`

### 4.2 Workbook composition (current)

- Summary
- RAW
- FILTRED
- get_inv_by_account
- get_marley_gen2_by_uuid
- ENRICH
- SCOPE
- STATS
- TOTAL.PROGRAM
- TOTAL.ENTITY
- NOT_IN_ILLUMIO
- IN_ILLUMIO_BUT_NOT_BLOCKING

---

## 5. Why this algorithm is robust

- **Traceable**: every stage emits auditable artifacts and diagnostic tabs.
- **Resilient**: retries + caching + partial-failure tolerance avoid all-or-nothing execution.
- **Governed**: explicit filter gates and manual exclusion controls support operational governance.
- **Presentation-ready**: summary/KPI sheets and structured workbook improve executive readability.
