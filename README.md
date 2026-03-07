# kpi-steerco

Repository for the KPI SteerCo initiative focused on microsegmentation coverage.

## Main folders

- `modules/`: Python source modules.
- `user_inputs/`: manual input files (including Excel files with KEAR IDs).
- `RUNS/`: run outputs and generated artifacts.
- `docs/`: project documentation.
- `bin/`: executable wrappers (future).

## Current lookup command

```bash
python modules/script_d4s.py user_inputs/input_values.txt -o RUNS/output.csv --mode dali_servers --json-out RUNS/output.json -v
```
