# Step 06 - W06 retained W02 consolidation

## Purpose

`W06` is the consolidated assets worksheet for the fork workbook. For this first
step, `W06` transports **only the values retained from W02**. W03 and W04 are not
transported into W06 yet; they will be added in later increments.

The objective is to give users a clean, consumable asset list based on the W02
DALI export after W02 inventory enrichment and W02 filters have been applied.

## Source module

`W06` is built by `fork/modules/w06_consolidation.py` and orchestrated by
`fork/kpi_orchestrator.py` after W02 filtering and after W03/W04 extraction have
completed.

Even though W03 and W04 already exist in the workbook, this increment does not
merge any of their rows into W06.

## Input worksheet and timing

The only transported data source is the final in-memory W02 dataset:

1. W02 starts with the DALI `impactAnalysis` extract.
2. W02 receives fork-specific inventory enrichment columns.
3. W02 receives filter decision columns from `fork/users_input/filters.conf`.
4. W06 is built from that final W02 state.

This means W06 sees the same W02 values that are written to the W02 worksheet,
including inventory enrichment columns, but it does not copy the technical filter
decision columns.

## Row selection rule

A W02 row is transported into W06 only when:

```text
W02.F_ALL_FILTERS = Y
```

The comparison is case-insensitive after trimming whitespace. Rows where
`F_ALL_FILTERS` is missing, empty, or different from `Y` are skipped.

## Column selection rule

W06 starts from the final W02 header list and removes every technical filter
column whose header starts with:

```text
F_
```

Examples of excluded W02 columns include:

- `F_EXCLUDE_CLOUDTYPE`
- `F_INCLUDE_OSNAME`
- `F_EXCLUDE_MAINAPP`
- `F_ALL_FILTERS`

All non-filter W02 columns are kept in their W02 order. The W02 inventory
enrichment columns are therefore retained because they do not start with `F_`.

## Provenance column

W06 appends one provenance column:

```text
Retrieved from
```

For every W02-origin row transported by this increment, the value is:

```text
Dali Export
```

This value identifies assets that entered W06 through the W02 DALI export path.

## Current non-goals

This first W06 implementation intentionally does not:

- transport W03 inventory-only rows into W06,
- transport W04 Marley-only rows into W06,
- deduplicate W02 rows against W03 or W04,
- compute a cross-source matching status,
- change W02 filtering behavior.

Those W03 and W04 consolidation rules will be added in later increments.

## Logging in `execution.log`

The orchestrator writes Step 06 messages to `execution.log` when W06 starts and
when it completes. The W06 module also logs the consolidation details, including:

- source worksheet (`W02` only),
- number of W02 input rows,
- number of retained rows where `F_ALL_FILTERS=Y`,
- number of skipped rows,
- number of transported columns,
- names of excluded `F_*` filter columns,
- provenance value used for transported rows (`Dali Export`).

These log entries make it possible to audit how W06 was constructed for each run.
