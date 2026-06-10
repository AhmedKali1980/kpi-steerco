# Fork - incrément 1 : DictKearsAccounts

Ce répertoire contient uniquement le squelette et les fichiers nécessaires au premier incrément : créer la feuille Excel `DictKearsAccounts`.

## Ce que fait cet incrément

1. Lire les valeurs distinctes de la colonne `uid` depuis `fork/users_input/monitored_kears.csv` (`kear` est accepté comme alias pour compatibilité avec le fichier actuel).
2. Requêter l'index Data4Sec Elasticsearch `platform_accounts` pour ces KEARs.
3. Écrire le résultat dans une feuille Excel `DictKearsAccounts` avec les colonnes :
   - `account_id` depuis le champ `id`
   - `account_name` depuis le champ `name`
   - `env_account` depuis le tag `ENV:<environment>` dans le champ `tags`

## Fichiers inclus

- `build_dict_kears_accounts.py` : point d'entrée de ce premier incrément.
- `modules/config.py` : configuration minimale Data4Sec/platform_accounts.
- `modules/data4sec_client.py` : client Elasticsearch minimal pour `platform_accounts`.
- `modules/input_reader.py` : lecture stricte du fichier `monitored_kears.csv`.
- `modules/dict_kears_accounts.py` : transformation métier vers les lignes `DictKearsAccounts`.
- `modules/certificates.py` : résolution du bundle CA pour Elasticsearch.
- `users_input/monitored_kears.csv` : input du premier incrément.
- `RUNS/` : dossier de sortie.

## Exécution

```bash
python fork/build_dict_kears_accounts.py
```

Par défaut, le fichier Excel est écrit sous `fork/RUNS/<timestamp>/dict_kears_accounts_<timestamp>.xlsx`.
