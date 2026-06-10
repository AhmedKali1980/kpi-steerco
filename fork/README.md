# Fork - Increment 1: W01 Kears/Accounts dictionary

This directory contains only the skeleton and files required for the first increment: creating the `W01` Excel worksheet.

## What this increment does

1. Reads distinct values from the `uid` column in `fork/users_input/monitored_kears.csv` (`kear` is accepted as a compatibility alias).
2. Queries the Data4Sec Elasticsearch index `platform_accounts` by looking for each UID in the `tags` field as `KEAR_SG_UID:<uid>`.
3. Writes an Excel workbook with:
   - `Index`: workbook dictionary listing the purpose of each worksheet.
   - `W01`: Kears/Accounts dictionary with exactly four columns:
     - `account_id` from the `id` field
     - `account_name` from the `name` field
     - `env_account` from `ENV:<environment>` or `is:env=<environment>`
     - `KEAR_SG_UID` from the `KEAR_SG_UID:<uid>` tag
4. Writes a timestamped `execution.log` file in the same `RUNS/<timestamp>/` directory as the workbook.

## Included files

- `build_dict_kears_accounts.py`: entry point for this first increment.
- `modules/config.py`: minimal Data4Sec/platform_accounts and worksheet configuration.
- `modules/data4sec_client.py`: minimal Elasticsearch client for `platform_accounts`.
- `modules/input_reader.py`: strict `monitored_kears.csv` reader.
- `modules/dict_kears_accounts.py`: business transformation for `W01` rows.
- `modules/certificates.py`: CA bundle resolution for Elasticsearch.
- `users_input/monitored_kears.csv`: first-increment input file.
- `RUNS/`: output directory for the workbook and `execution.log`.

## Run

```bash
python fork/build_dict_kears_accounts.py
```

By default, the Excel workbook is written to `fork/RUNS/<timestamp>/dict_kears_accounts_<timestamp>.xlsx` and the execution trace to `fork/RUNS/<timestamp>/execution.log`.
