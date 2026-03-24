# user_inputs

Manual inputs to be dropped in this folder:

- `monitored_kears.csv` with columns: `kear`, `program`, `network`, `taken`
- `headers.csv` with 2 columns and no header:
  - column 1: output display name
  - column 2: equivalent DALI attribute name
  - the file drives the base columns exported in `RAW` and also the base columns propagated into `FILTRED`
  - you can now target a specific DALI node in column 2 with:
    - `leading.<attr>`: property taken from `leading_node.properties`
    - `trailing.<attr>`: property taken from `trailing_node.properties`
    - `server.<attr>`: property taken from the node labeled `Server`
    - `application.<attr>`: property taken from the node labeled `Application`
  - default mappings now include `Server Status,server.status` so the server-side DALI `status` property is exported into a dedicated `Server Status` column in `RAW` without being confused with another node's `status`

These files are used by `modules/dali_impact_analysis.py`.

- `filters.conf` (key,value) for custom user filters
- `servers_to_exclude.csv` with one hostname per line (optional header accepted) to manually exclude servers from scope and recap

Other columns present in `FILTRED` do **not** necessarily come from `headers.csv`:

- inventory enrichment adds: `INV_ocs_name`, `INV_status`, `INV_hostname`, `Retrived from`, `INV_Owner_Account`, `INV_Beneficiary_Account`
- workload / PCE correlation adds: `managed`, `IPLIST`, `SUBNET`, `enforcement`, `role`, `app`, `env`, `loc`, `F_Excluded`, `In scope`
- Marley enrichment also fills business columns such as `DALI STATUS`, `STATUS`, `HOSTNAME`, `UID REL`, etc.

- For multiple networks on the same application scope, duplicate rows using the same `kear` + `program` and one `network` per row.
- Query execution is optimized by UID de-duplication during DALI/inventory lookups, so duplicated scope rows do not multiply backend calls.
