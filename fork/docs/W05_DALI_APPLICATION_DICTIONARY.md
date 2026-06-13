# W05 - DALI application dictionary

`W05` is the fifth fork worksheet. It is intentionally limited to the DALI application dictionary lookup and does not perform server impact analysis, inventory enrichment, scope calculation, PCE correlation, PPTX generation or email sending.

## Input

The worksheet is driven by the distinct `uid` values read from `fork/users_input/monitored_kears.csv` by the fork orchestrator.

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

## Output columns

The module extracts `result[0].leading_node.properties` and writes these columns:

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

## Trace and logging

The fork orchestrator stores the W05 trace inside `dali_extract.json.gz` under `application_dictionary` and logs W05 progress in `execution.log` with the prefix `STEP 05 - DALI application dictionary W05`.
