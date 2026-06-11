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
| `ocs_name` | inventory `ocs_name` |
| `hostname` | short hostname from inventory `hostname` |
| `status` | inventory `status`, defaulting to `<UNKNOWN STATUS>` when empty |
| `hostid` | inventory `hostid` |
| `Normalized_uuid_from_hostid` | trailing server UUID parsed from `hostid` |
| `srn` | inventory `srn` |
| `Normalized_uuid_from_srn` | server UUID parsed from `srn` |
| `owner_app_name` | inventory `owner_app_name` |
| `ip` | inventory `ip` |
| `service_name` | inventory `service_name` |

The parent workbook also later appends an `asset_origin` marker after comparing
inventory rows with RAW DALI server UIDs. W03 is intentionally an extract-only
brick at this stage, so that derived scope marker is not included yet.

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
