# W05 - DALI application dictionary

`W05` is the fifth fork worksheet. It is intentionally limited to the DALI application dictionary lookup and does not perform server impact analysis, inventory enrichment, scope calculation, PCE correlation, PPTX generation or email sending.

## Input

The worksheet is driven by the distinct `uid` values read from `fork/users_input/monitored_kears.csv` by the fork orchestrator. W05 preserves the UID exactly as it appears in the input file when building the DALI `search` equality filter; it does not uppercase UUID-style values.

## DALI endpoint

`W05` uses DALI `search`, not `impactAnalysis`.

The endpoint is configurable with:

```env
DALI_SEARCH_ENDPOINT=/api/v1/search
```

For each monitored UID, the request body is:

```json
{
  "filters": [
    {
      "attributeName": "uid",
      "attributeValue": "<APPLICATION_UID>",
      "matchType": "equals"
    }
  ],
  "includeCount": true,
  "label": "Application",
  "limit": 100,
  "orderBy": [
    {
      "direction": "asc",
      "labelProperty": "string"
    }
  ],
  "skip": 0
}
```

## Data4Sec kear_appli enrichment

After the DALI `search` extraction, W05 queries Data4Sec index `kear_appli` for all W05 `uid` values. The W05 `uid` is matched against `global_id` in Elasticsearch.

The enrichment retrieves:

- `global_id`, used as the ID part of the proposed label.
- `identifiers.issuer`, used as the ordered attribute list.
- `identifiers.identifier`, used as the ordered value list.

Configurable settings:

```env
KEAR_APPLI_INDEX=kear_appli
KEAR_APPLI_SEARCH_FIELD=global_id
KEAR_APPLI_SCROLL_TIMEOUT=10m
KEAR_APPLI_BATCH_SIZE=500
```

## Proposed application label

The proposed label follows the same algorithm as the reference script:

1. Build an issuer -> identifier mapping from `identifiers.issuer` and `identifiers.identifier`.
2. Keep values only when their issuer is present in this order: `IRT`, `IAPPLI (Trigram)`, `IAPPLI`.
3. Join retained values with `.`.
4. Return `APMA_<global_id>_<joined_values>` when at least one value exists, otherwise `APMA_<global_id>`.

## Output columns

The module extracts `result[0].leading_node.properties` and writes these DALI columns:

1. `uid`
2. `name`
3. `short_label`
4. `irt_code`
5. `iappli_code`
6. `trigram`
7. `dsi`
8. `application_management_rc`
9. `application_development_manager`
10. `asa`
11. `status`

It then appends these Data4Sec / computed columns:

12. `KEAR_APPLI (identifiers.issuer)`
13. `KEAR_APPLI (identifiers.identifier)`
14. `proposed application label`

## Trace and logging

The fork orchestrator stores the W05 trace inside `dali_extract.json.gz` under `application_dictionary`, including a `kear_appli` enrichment summary. It logs W05 progress in `execution.log` with the prefixes `STEP 05 - DALI application dictionary W05` and `STEP 05 - KEAR_APPLI enrichment`.
