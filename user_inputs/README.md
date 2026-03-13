# user_inputs

Manual inputs to be dropped in this folder:

- `monitored_kears.csv` with columns: `kear`, `program`, `network`, `taken`
- `headers.csv` with 2 columns and no header:
  - column 1: output display name
  - column 2: equivalent DALI attribute name

These files are used by `modules/dali_impact_analysis.py`.

- `filters.conf` (key,value) for custom user filters
- `servers_to_exclude.csv` with one hostname per line (optional header accepted) to manually exclude servers from scope and recap

- For multiple networks on the same application scope, duplicate rows using the same `kear` + `program` and one `network` per row.
- Query execution is optimized by UID de-duplication during DALI/inventory lookups, so duplicated scope rows do not multiply backend calls.
