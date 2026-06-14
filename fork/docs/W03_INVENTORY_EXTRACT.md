# W03 - Data4Sec inventory extract by beneficiary account

`W03` is the clean fork implementation of the parent workbook sheet named
`get_inv_by_account`.

## Input

`W03` does not read a user CSV directly. It consumes the rows already produced in
`W01` and uses distinct non-empty `account_name` values as Data4Sec inventory
beneficiary accounts.

In business terms, the `W01` accounts are the Beneficiary Accounts attached to
the monitored Business Applications.

## Parent query reproduced

The parent project builds `get_inv_by_account` during inventory enrichment in
`modules/dali_impact_analysis.py`:

1. collect `INV_Beneficiary_Account` values,
2. query Data4Sec Elasticsearch index `inventory`,
3. search field `beneficiary`,
4. retrieve source fields:
   - `hostid`
   - `srn`
   - `ocs_name`
   - `hostname`
   - `beneficiary`
   - `owner_app_name`
   - `status`
   - `region`
   - `ip`
   - `service_name`
5. keep the same active/unknown status terms used by the parent project.

The fork centralizes those settings in `fork/modules/config.py` under
`INVENTORY` and executes the extraction in `fork/modules/inventory_extract.py`.

## W03 columns

The W03 column contract is explicit and stable:

| Column | Source / rule |
| --- | --- |
| `input_INV_Beneficiary_Account` | normalized W01 `account_name` used as input lookup key |
| `beneficiary` | inventory `beneficiary`, normalized for matching |
| `owner_app_name` | inventory `owner_app_name` |
| `ocs_name` | inventory `ocs_name` |
| `hostname` | short hostname from inventory `hostname` |
| `status` | inventory `status`, defaulting to `<UNKNOWN STATUS>` when empty |
| `region` | inventory `region` |
| `hostid` | inventory `hostid` |
| `Normalized_uuid_from_hostid` | trailing server UUID parsed from `hostid`, with `VM_` removed and the result lowercased |
| `lookup_in_raw` | `ALREADY IN DALI RAW` when `Normalized_uuid_from_hostid` exists in W02 column `DALI [CI] SERVER UID`, otherwise `NEW ASSET` |
| `srn` | inventory `srn` |
| `Normalized_uuid_from_srn` | server UUID parsed from `srn` |
| `ip` | inventory `ip` |
| `service_name` | inventory `service_name` |

W03 also performs the first lightweight cross-check with W02: `lookup_in_raw`
is derived from the exact W02 `DALI [CI] SERVER UID` column and does not call DALI again.

## Orchestration

`fork/kpi_orchestrator.py` now runs W03 after W01 and W02:

```bash
python fork/kpi_orchestrator.py --verbose
```

For structural checks without calling Data4Sec/inventory, keep W01 live but dry
run W03:

```bash
python fork/kpi_orchestrator.py --dry-run-inventory --verbose
```

`execution.log` records the start and row count of step 03.

## Standalone module check

The module can also generate a standalone workbook from one or more account
names:

```bash
python fork/modules/inventory_extract.py \
  --account MY_ACCOUNT \
  --output-file fork/RUNS/inventory_extract_test.xlsx \
  --dry-run \
  --verbose
```

## Second enrichment: not-business Gen 2 assets from W02

After the beneficiary-account inventory extraction, W03 now performs a second
inventory enrichment scoped to DALI raw assets that are not already represented
in W03:

1. read W02 rows where `DALI [CI] CLOUD TYPE` is `Gen 2`,
2. normalize `DALI [CI] SERVER UID`,
3. discard UIDs already present in W03 `Normalized_uuid_from_hostid`,
4. query Data4Sec `inventory` for the remaining UIDs:
   - primary lookup: UID is contained in `srn`, because inventory SRNs include
     other path segments around the server identifier,
   - fallback lookup: `hostid` equals `VM_<SERVER_UID_IN_UPPERCASE>`,
5. append matched documents to W03 with the same column contract as the
   beneficiary-account rows.

Rows appended by this second enrichment are explicitly marked as:

| Column | Value |
| --- | --- |
| `lookup_in_raw` | `ALREADY IN DALI RAW` |
| `Asset linked to` | `Not Business Account` |

`execution.log` records the number of missing Gen 2 W02 server UIDs, the
inventory query dimensions, matched UID count, total documents and appended row
count.

## Downstream W01 enrichment for Not Business Account rows

Once W03 has been built, the fork orchestrator runs an additional W01 enrichment
step before W02 inventory enrichment. It collects distinct non-empty account
names from W03 column `beneficiary` only for rows where `Asset linked to`
equals `Not Business Account`. It then collects W03 `owner_app_name` values
from all W03 rows, but only when those owner values do not already exist in
the full W03 beneficiary set.

The not-business beneficiary and owner-only account names are queried against Data4Sec `platform_accounts` on the
`name` field, using the same source fields as the initial W01 query (`id`,
`name`, `tags`). Any platform account not already present in W01 is appended to
W01 with:

| W01 column | Value |
| --- | --- |
| `account_id` | `platform_accounts.id` |
| `account_name` | `platform_accounts.name` |
| `env_account` | `ENV:<value>` or `is:env=<value>` parsed from `tags` |
| `appName` | filled later from DALI `search` attribute `name` using W01 `KEAR_SG_UID` |
| `dsi` | filled later from DALI `search` attribute `dsi` using W01 `KEAR_SG_UID` |
| `KEAR_SG_UID` | `KEAR_SG_UID:<value>` parsed from `tags`, when present |
| `Account linked to` | `Not Business App` for beneficiary rows; `Infra Owner of Business App` for owner-only rows |

`execution.log` records the STEP 01B start, candidate count, infra-owner candidate count, appended W01 row count, appended infra-owner row count, and new W01 total row count. The following STEP 01C enriches W01
`appName` and `dsi` from DALI `search` with distinct W01 `KEAR_SG_UID`
values, taking the first value before `|` when multiple KEAR values are present.
