# W04 - Marley original assets by monitored UID

`W04` is the fourth clean fork worksheet. It is a direct extract from
`data4sec/marley_original` and is intentionally limited to assets returned by
Elasticsearch.

## Input

- File: `fork/users_input/monitored_kears.csv`
- Column: `uid` (the shared monitored KEAR identifier input)
- Reader: `fork/modules/input_reader.py`, which deduplicates UIDs while keeping
  the original file order.

## Query contract

`fork/modules/marley_extract.py` queries Data4Sec through the shared
`Data4SecClient`:

- index: `marley_original` by default (`MARLEY_ORIGINAL_INDEX` override)
- lookup field: `app_info.kear_uuid` by default (`MARLEY_ORIGINAL_UID_SEARCH_FIELD` override)
- lookup values: distinct monitored `uid` values
- source fields: `hostname`, `ocs_name`, `app_info`, `uuid`, `net_info`,
  `os_name`, `os_version`, `typologie`, `silos`, `dns`, `status`, `usage`
- status filter: the same active/unknown status family used by the parent Marley
  query.

The module reuses the parent project idea behind `get_marley_gen2_by_uuid`
(source fields and Marley status filter) but removes enrichment behavior. `W04`
does not create `NOT_FOUND` rows and does not append any non-Elasticsearch data.

Marley documents can expose `app_info` either as an object, as a dotted source
field, or as a list of application objects. The W04 extractor resolves all three
shapes and, when `app_info` contains multiple applications, displays the
`app_info.*` values matching the requested input UID.

## Output columns

`W04` writes a stable extract-only schema configured in `fork/modules/config.py`:

- `input_uid`
- `hostname`
- `ocs_name`
- `uuid`
- `app_info.kear_uuid`
- `app_info.account_id`
- `app_info.app_id`
- `app_info.app_name`
- `app_info.env`
- `app_info.factor`
- `app_info.kear_library`
- `app_info.ref_app`
- `app_info.service_line_name`
- `net_info.net_ipadress`
- `os_name`
- `os_version`
- `typologie`
- `silos`
- `dns`
- `status`
- `usage`

## Execution logging

The orchestrator writes `STEP 04` entries to `execution.log`:

1. start of the Marley query against `data4sec/marley_original`,
2. query counters from the module (`matched_uids`, `total_docs`),
3. final `W04` row count,
4. workbook write counters including `W04 rows`.

## Standalone check

```bash
python fork/modules/marley_extract.py \
  --monitored-file fork/users_input/monitored_kears.csv \
  --output-file fork/RUNS/marley_extract_test.xlsx \
  --dry-run \
  --verbose
```

`--dry-run` skips Elasticsearch and writes the `W04` headers with zero rows.
