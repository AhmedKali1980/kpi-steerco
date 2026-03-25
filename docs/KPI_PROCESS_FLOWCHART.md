# KPI Pipeline Flowchart (End-to-End)

## Purpose

This flowchart documents the complete KPI calculation and generation process currently implemented in the project, from orchestration bootstrap to multi-sheet XLSX publication.

## 1) Global Orchestration Flow

```mermaid
flowchart TD
    A[Start Orchestrator] --> B[Load .env and parse CLI args]
    B --> C[Create RUNS/<timestamp>/raw and execution.log]
    C --> D{--skip-pce-import?}
    D -- No --> E[Run bin/cron_job.sh]
    D -- Yes --> F[Skip PCE import]
    E --> G{PCE mode}
    G -- Stub --> H[Copy export_wkld.csv and export_iplists.csv]
    G -- Live --> I[Run workloader exports]
    H --> J[Build derived exports<br/>export_wkld.derived.csv + export_iplists.derived.csv]
    I --> J
    J --> K[Validate required inputs<br/>monitored_kears.csv, headers.csv, filters.conf]
    F --> K
    K --> L[Build and execute DALI impact analysis command]
    L --> M[modules/dali_impact_analysis.py]
    M --> N{Process status OK?}
    N -- No --> O[Stop with exit code]
    N -- Yes --> P[Check JSON.GZ summary and safety gates]
    P --> Q[Publish outputs + log completion]
```

## 2) DALI Impact & KPI Data Processing Flow

```mermaid
flowchart TD
    A1[Load .env + parse args] --> A2[Read headers mapping]
    A2 --> A3[Read monitored KEAR/UID rows]
    A3 --> A4[Load filters.conf]
    A4 --> B1[Run DALI impact batch]

    B1 --> B2[For each monitored UID:<br/>build params + call DALI (or dry-run)]
    B2 --> B3[Extract RAW rows from DALI edges]
    B2 --> B4[Extract FILTRED rows with filter predicates]
    B3 --> C1[RAW dataset ready]
    B4 --> C2[FILTRED dataset ready]

    C2 --> D1[Inventory enrichment for Gen2 via Data4Sec]
    D1 --> D2[Populate INV_* columns and Retrieved from]
    D2 --> D3[Apply beneficiary exclusions and PROD account scope]

    D3 --> E1[Enrich FILTRED with workload match<br/>managed/IPLIST/SUBNET/etc]
    E1 --> E2[Build Dict_Kear_Account]
    E2 --> E3[Marley UUID lookup + filtering]
    E3 --> E4[Append eligible Marley rows to FILTRED]

    E4 --> F1[Compute In scope + initialize F_Excluded]
    F1 --> F2[Deduplicate FILTRED rows (network/IPLIST ranking)]
    F2 --> F3[Apply manual server exclusion list]

    C1 --> G1[Write RAW CSV]
    F3 --> G2[Write FILTRED CSV]
    B1 --> G3[Write JSON.GZ payload]

    G1 --> H1[Build recap sheets<br/>STATS, TOTAL.PROGRAM, TOTAL.ENTITY]
    G2 --> H1
    F3 --> H2[Build EXCLUDED, get_inv_by_account,<br/>get_marley_gen2_by_uuid, Dict_Kear_Account,<br/>KearLabelsAccounts]

    H1 --> I1[Assemble XLSX workbook<br/>Summary + RAW + FILTRED + diagnostics]
    H2 --> I1
    G3 --> I2[Print execution summary to stdout]
    I1 --> I2
```

## 3) Filter Decision Logic (Applied on DALI Edges)

```mermaid
flowchart LR
    S[Edge from DALI result] --> F1{FILTER_PRD_ENV matches environment?}
    F1 -- No --> R[Reject edge]
    F1 -- Yes --> F2{FILTER_OS_NAME matches os_name?}
    F2 -- No --> R
    F2 -- Yes --> F3{FILTER_SERVER_STATUS matches status?}
    F3 -- No --> R
    F3 -- Yes --> F4{cloud_type not in FILTER_CLOUD_TYPE_NOT_TAKEN?}
    F4 -- No --> R
    F4 -- Yes --> F5{main_application not in FILTER_MAIN_APP_NOT_TAKEN?}
    F5 -- No --> R
    F5 -- Yes --> F6{typology not in FILTER_TYPOLOGY_NOT_TAKEN?}
    F6 -- No --> R
    F6 -- Yes --> F7{dns/domain not in FILTER_DOMAIN_NOT_TAKEN?}
    F7 -- No --> R
    F7 -- Yes --> K[Keep edge in FILTRED]
```

## 4) Artifact Lineage (What is produced)

```mermaid
flowchart TB
    I1[user_inputs/*.csv + filters.conf] --> O1[DALI RAW rows]
    I1 --> O2[DALI FILTRED rows]
    P1[export_wkld.csv + export_iplists.csv] --> P2[Derived workload/iplist CSV]
    P2 --> O2
    O2 --> O3[Inventory-enriched FILTRED]
    O3 --> O4[Scope + exclusion + dedup FILTRED]
    O1 --> R1[RAW CSV]
    O4 --> R2[FILTRED CSV]
    O1 --> R3[JSON.GZ detailed payload]
    O4 --> R4[XLSX dashboard with KPI tabs]
```

---

## Presentation Notes

- The first diagram is best for executive storytelling (macro process reliability and controls).
- The second and third diagrams are best for technical workshops (data lineage and rule engine transparency).
- The fourth diagram is best for governance and auditability (input/output traceability).
