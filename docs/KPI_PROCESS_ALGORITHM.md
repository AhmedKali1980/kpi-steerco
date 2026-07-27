# Documentation algorithmique complète — KPI SteerCo

## 1) Objectif du projet

Le pipeline calcule des KPI de couverture microsegmentation (présence Illumio, mode blocking, périmètre in/out scope) à partir de plusieurs sources :

- **inputs métier** (`user_inputs/*.csv`, `filters.conf`),
- **DALI impactAnalysis**,
- **Data4Sec / Elasticsearch**,
- **exports PCE Illumio** (workloads + iplists),
- puis génère des artefacts **CSV / JSON.GZ / XLSX / PPTX** pilotés par `kpi_orchestrator.py`.

---

## 2) Vue d’ensemble (ordre réel d’exécution)

1. `kpi_orchestrator.py` charge l’environnement, crée `RUNS/<timestamp>/raw`, initialise les logs.
2. Il lance l’import PCE via `bin/cron_job.sh` (live ou stub), qui produit les CSV bruts et dérivés.
3. L’orchestrateur valide les fichiers d’entrée utilisateur.
4. Il exécute `modules/dali_impact_analysis.py` (pipeline principal data).
5. Le module DALI construit RAW/FILTRED + enrichissements (inventory, workload, Marley), puis KPI sheets.
6. L’orchestrateur vérifie les artefacts, prépare un classeur mail réduit, extrait des chartes KPI (TOTAL.PROGRAM), fabrique les PNG et peut envoyer une notification email.

---

## 3) Entrées attendues et paramètres

## 3.1 Inputs utilisateurs (`user_inputs/`)

- `monitored_kears.csv` : colonnes attendues (alias acceptés) `kear`/`uid`, `program`, `network`, `taken`.
- `headers.csv` : mapping `Nom affiché` -> `attribut DALI` (2 colonnes, sans header).
- `filters.conf` : filtres fonctionnels (`FILTER_PRD_ENV`, `FILTER_OS_NAME`, `FILTER_SERVER_STATUS`, exclusions domaine/typologie/cloud/app, etc.).
- `servers_to_exclude.csv` : liste manuelle de serveurs à forcer hors scope.

## 3.2 Variables d’environnement majeures

- DALI OAuth/API: `DALI_BASE_URL`, `SGMARKET_TOKEN_URL`, `SGCONNECT_CLIENT_ID`, `SGCONNECT_CLIENT_SECRET`, `SGCONNECT_SCOPES`.
- DALI impact tuning: `DALI_IMPACT_ENDPOINT`, `DALI_DEPTH_UNTIL`, `DALI_LIMIT`.
- Elasticsearch: `ELASTICSEARCH_WRITE_HOST`, `ELASTICSEARCH_WRITE_PORT`, `ELASTICSEARCH_WRITE_LOGIN`, `ELASTICSEARCH_WRITE_PASS`.
- SMTP (notification): `SMTP_*`.
- PCE/workloader: `EXECUTABLE`, `CFG`, `PCE_L1_FQDN`, `PCE_L3SM_FQDN`, `PCE_L1_NAME`, `PCE_L3SM_NAME`, etc.

## 3.3 Config statique (code)

`modules/config.py` définit :

- les connexions (`ELASTICSEARCH`, `PCE`, `DALI`),
- les profils d’index `QUERY_CONFIG` : `dali_servers`, `inventory`, `marley_original`, `platform_accounts`,
- `batch_size` et `scroll_timeout` des recherches bulk.

---

## 4) Étape 1 — Orchestrateur (`kpi_orchestrator.py`)

### 4.1 Bootstrap

- Parse des arguments CLI (`--runs-dir`, `--dry-run`, `--pce-stub-dir`, `--skip-pce-import`, etc.).
- Création des dossiers run + log file.
- Vérification présence des fichiers d’entrée obligatoires.

### 4.2 Import PCE (pré-DALI)

- Appel `bin/cron_job.sh <run_dir>`.
- Contrôle que `raw/export_wkld.csv` et `raw/export_iplists.csv` existent et non vides.

### 4.3 Exécution pipeline DALI

- Construction commande subprocess vers `modules/dali_impact_analysis.py` avec paramètres effectifs (endpoint/depth/limit + inputs).
- En sortie, attend notamment workbook XLSX + payload JSON.GZ.

### 4.4 Post-traitements de diffusion

- Détection/renommage PPTX.
- Création d’un classeur XLSX allégé (sheets sélectionnées mail).
- Extraction des métriques `TOTAL.PROGRAM`, génération de feuille `PROGRAM_CHARTS`, production optionnelle d’images PNG.
- Construction corps email et envoi SMTP (si activé).

---

## 5) Étape 2 — Import PCE (`bin/cron_job.sh` + wrappers)

## 5.1 Modes

- **Stub**: copie de CSV existants (`PCE_STUB_DIR`).
- **Live**:
  1. export workloads L1 (`workloader_wkld_export.sh`),
  2. export workloads managés L3SM (`workloader_wkld.m_export.sh`),
  3. append L3SM -> `export_wkld.csv`,
  4. export iplists L1 (`workloader_ipl_export.sh`).

## 5.2 Fiabilisation

`bin/workloader_common.sh` applique:

- chargement `.env`,
- retry exponentiel + jitter,
- timeout par tentative,
- pause inter-attempt et post-success,
- vérification de fichier de sortie.

## 5.3 Fichiers dérivés

`cron_job.sh` génère ensuite :

- `export_iplists.derived.csv` : filtre `NZ3_*`, parse subnet `include`.
- `export_wkld.derived.csv` : ajoute `short_hostname`, `ocs_name_from_IP`, `IPLIST`, `SUBNET` en corrélant IP interfaces ↔ subnets iplist. `ocs_name_from_IP` conserve l'IP de passerelle par défaut pour les workloads managés ; pour les workloads non managés issus de `Automation GEN2`, elle est dérivée de la première IPv4 valide de `interfaces`. Les autres workloads non managés restent inchangés.

---

## 6) Étape 3 — Pipeline principal (`modules/dali_impact_analysis.py`)

## 6.1 Préparation

1. Chargement `.env` + args CLI.
2. Lecture `headers.csv` (mapping colonnes de sortie).
3. Lecture `monitored_kears.csv` avec normalisation d’alias colonnes.
4. Lecture `filters.conf`.
5. Initialisation client DALI (`DaliImpactAnalysisClient`) + client Data4Sec.

## 6.2 Appels DALI impactAnalysis

Pour chaque UID surveillé:

- construit les paramètres (`IMPACT_DEFAULT_PARAMS` + `attributeValue=uid` + limit/depth),
- récupère token OAuth2 client_credentials,
- exécute GET DALI avec retry (429/5xx + erreurs réseau),
- refresh token sur 401/403,
- sérialise résultats/erreurs dans payload.

## 6.3 Construction des lignes RAW

À partir de chaque edge DALI:

- lecture `leading_node` / `trailing_node` properties,
- extraction `Server UID` (node label `Server`),
- résolution des attributs via mapping (`leading.<x>`, `trailing.<x>`, `server.<x>`, `application.<x>`, fallback),
- calcul des colonnes debug de filtre (`FILTER_VALUE_*`, `F_FILTER_*`, `F_FILTER_ALL`),
- calcul de scope initial (`In Scope(s)`, `Program(s)`) selon UID + network/IPLIST.

## 6.4 Filtrage fonctionnel

Une ligne passe si toutes les conditions actives sont vraies:

- environnement (`FILTER_PRD_ENV`, sauf `ALL`),
- OS (`FILTER_OS_NAME`),
- status serveur (`FILTER_SERVER_STATUS`),
- exclusions cloud/app/domain/typology,
- non exclusion manuelle (`F_Excluded != Y`).

## 6.5 Enrichissement Inventory Gen2 (Data4Sec)

- cible les lignes cloud `Gen 2`,
- lookup par variantes de `Server UID` (`hostid`, `srn`),
- enrichit `INV_*`, owner/beneficiary, source retrieval,
- déduit `INV_Beneficiary_Account_ENV` via `platform_accounts.tags`,
- applique exclusions beneficiary/owner selon filtres.

## 6.6 Corrélation workload/iplist

- charge `export_wkld.derived.csv` et `export_iplists.derived.csv`,
- matching multi-clés hostname/IP/ocs_name,
- enrichit champs `ILU_*` (managed, enforcement, role/app/env/loc, iplist, subnet…),
- recalcule `In scope` selon network vs IPLIST.

## 6.7 Enrichissement Marley complémentaire

- découvre candidats via inventory/accounts,
- interroge index `marley_original`,
- applique gate d’éligibilité (status/usage/not duplicate/in scope),
- mappe les champs vers schéma cible (`MARLEY_ENRICHMENT_MAPPING_TABLE`),
- append au scope final.

## 6.8 Exclusion manuelle

- charge `servers_to_exclude.csv`,
- normalise noms (short hostname, case-insensitive),
- match contre HOSTNAME/USUAL/FRIENDLY/INV,
- force `F_Excluded=Y` et `In scope=N`,
- remplit sheet `EXCLUDED` traçable.

## 6.9 KPI & artefacts

Le module produit:

- CSV `RAW` et `FILTRED`,
- payload `json.gz`,
- workbook XLSX multi-onglets (`Summary`, `SCOPE`, `STATS`, `TOTAL.PROGRAM`, `TOTAL.ENTITY`, `EXCLUDED`, etc.),
- données prêtes pour PPTX KPI.

---

## 7) Sous-modules techniques

- `modules/d4s_client.py` : client Elasticsearch (TLS + CA), requêtes bulk/scroll, wildcard, normalisation hostname/casse.
- `modules/script_d4s.py` : utilitaire CLI de lookup D4S indépendant (modes `dali_servers` / `inventory`).
- `modules/sg_cacert_file.py` : résolution du bundle CA (env vars puis chemins système).
- `modules/email_utils.py` : parsing destinataires, génération tableaux durées, SMTP TLS/SSL, attachments + inline images.

---

## 8) Artefacts de sortie (run)

Sous `RUNS/<timestamp>/raw/` et `RUNS/<timestamp>/`:

- `export_wkld.csv`, `export_wkld.l3sm.m.csv`, `export_iplists.csv`,
- `export_wkld.derived.csv`, `export_iplists.derived.csv`,
- `dali_impact_analysis_<timestamp>_RAW.csv`,
- `dali_impact_analysis_<timestamp>_FILTRED.csv`,
- `dali_impact_analysis_<timestamp>.xlsx`,
- `dali_impact_analysis_<timestamp>.json.gz`,
- (optionnel) `kpi_microseg_slides_<timestamp>.pptx`, PNG charts, workbook mail réduit.

---

## 9) Résumé algorithmique court

Le projet implémente une **chaîne déterministe et traçable** :

1. Préparer et fiabiliser les sources PCE,
2. Interroger DALI pour chaque UID monitoré,
3. Transformer en lignes analytiques normalisées,
4. Appliquer les filtres métier,
5. Enrichir via inventory/workload/Marley,
6. Calculer le scope final + exclusions,
7. Publier des sorties KPI orientées exploitation (CSV/JSON/XLSX/PPTX/email).

