import argparse
import gzip
import json
import logging
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def load_env_file(env_file: str = ".env") -> None:
    path = Path(env_file)
    if not path.is_file():
        return
    with open(path, "r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value


def setup_logging(log_file: Path, verbose: bool) -> None:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    level = logging.DEBUG if verbose else logging.INFO
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)

    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setLevel(level)
    stream_handler.setFormatter(formatter)
    root.addHandler(stream_handler)


def ensure_inputs_exist(paths: list[Path]) -> None:
    missing = [str(path) for path in paths if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"Missing required input files: {', '.join(missing)}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="KPI project orchestrator (initial DALI extraction step).")
    parser.add_argument("--runs-dir", default="RUNS", help="Base directory for timestamped runs")
    parser.add_argument("--monitored-file", default="user_inputs/monitored_kears.csv", help="Monitored KEAR input CSV")
    parser.add_argument("--headers-file", default="user_inputs/headers.csv", help="Headers mapping CSV")
    parser.add_argument("--filters-file", default="user_inputs/filters.conf", help="Custom filters conf file")
    parser.add_argument("--dry-run", action="store_true", help="Run extraction without calling DALI API")
    parser.add_argument(
        "--pce-stub-dir",
        default="",
        help="Use existing PCE CSV files from this directory instead of running live exports",
    )
    parser.add_argument("--skip-pce-import", action="store_true", help="Skip PCE workload/iplist import step")
    parser.add_argument("--verbose", action="store_true", help="Verbose logs")
    return parser.parse_args()


def run_pce_import(run_dir: Path, raw_dir: Path, stub_dir: str, log: logging.Logger) -> None:
    cmd = ["bash", "bin/cron_job.sh", str(run_dir)]
    env = os.environ.copy()
    if stub_dir:
        env["PCE_STUB_DIR"] = stub_dir

    log.info("Prepared PCE import command: %s", " ".join(cmd))
    if stub_dir:
        log.info("PCE import mode: stub (source=%s)", stub_dir)
    else:
        log.info("PCE import mode: live")

    result = subprocess.run(cmd, capture_output=True, text=True, env=env)
    if result.stdout:
        log.info("pce import stdout:\n%s", result.stdout.strip())
    if result.stderr:
        log.warning("pce import stderr:\n%s", result.stderr.strip())
    if result.returncode != 0:
        log.error("PCE import failed with exit code %s", result.returncode)
        raise SystemExit(result.returncode)

    expected_files = [raw_dir / "export_wkld.csv", raw_dir / "export_iplists.csv"]
    missing = [str(path) for path in expected_files if not path.is_file() or path.stat().st_size == 0]
    if missing:
        log.error("PCE import completed but missing/empty files: %s", ", ".join(missing))
        raise SystemExit(2)

    log.info("PCE import completed: %s", ", ".join(str(path) for path in expected_files))


def main() -> None:
    args = parse_args()
    load_env_file()

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    run_dir = Path(args.runs_dir) / timestamp
    raw_dir = run_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    log_file = run_dir / "execution.log"
    setup_logging(log_file=log_file, verbose=args.verbose)
    log = logging.getLogger("kpi_orchestrator")

    log.info("Starting KPI orchestration")
    log.info("Run directory initialized: %s", run_dir)
    log.info("Raw directory initialized: %s", raw_dir)

    if args.skip_pce_import:
        log.info("PCE import skipped by --skip-pce-import")
    else:
        run_pce_import(run_dir=run_dir, raw_dir=raw_dir, stub_dir=args.pce_stub_dir.strip(), log=log)

    monitored_file = Path(args.monitored_file)
    headers_file = Path(args.headers_file)
    filters_file = Path(args.filters_file)
    ensure_inputs_exist([monitored_file, headers_file, filters_file])
    log.info("Validated user inputs: %s, %s, %s", monitored_file, headers_file, filters_file)

    depth_until = (os.getenv("DALI_DEPTH_UNTIL") or "").strip()
    limit = (os.getenv("DALI_LIMIT") or "").strip()
    impact_endpoint = (os.getenv("DALI_IMPACT_ENDPOINT") or "/api/v1/impactAnalysis").strip()

    if not depth_until:
        log.warning("DALI_DEPTH_UNTIL is not set in .env; default from dali_impact_analysis.py will apply.")
    if not limit:
        log.warning("DALI_LIMIT is not set in .env; default from dali_impact_analysis.py will apply.")
    if not impact_endpoint:
        impact_endpoint = "/api/v1/impactAnalysis"

    if "xxxxxxxx" in (os.getenv("SGCONNECT_CLIENT_ID") or "") or "xxxxxxxx" in (os.getenv("SGCONNECT_CLIENT_SECRET") or ""):
        log.warning("SGCONNECT credentials appear to be placeholders; DALI live calls may fail.")

    output_xlsx = raw_dir / f"dali_impact_analysis_{timestamp}.xlsx"
    output_json = raw_dir / "dali_impact_analysis.json"
    output_json_gz = Path(str(output_json) + ".gz")

    cmd = [
        sys.executable,
        "modules/dali_impact_analysis.py",
        "--monitored-file",
        str(monitored_file),
        "--headers-file",
        str(headers_file),
        "--filters-file",
        str(filters_file),
        "--output",
        str(output_xlsx),
        "--json-out",
        str(output_json),
    ]

    if depth_until:
        cmd.extend(["--depth-until", depth_until])
    if limit:
        cmd.extend(["--limit", limit])
    cmd.extend(["--impact-endpoint", impact_endpoint])
    if args.dry_run:
        cmd.append("--dry-run")
    if args.verbose:
        cmd.append("--verbose")

    log.info("Prepared DALI extraction command: %s", " ".join(cmd))

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.stdout:
        log.info("dali_impact_analysis stdout:\n%s", result.stdout.strip())
    if result.stderr:
        log.warning("dali_impact_analysis stderr:\n%s", result.stderr.strip())

    if result.returncode != 0:
        log.error("dali_impact_analysis.py failed with exit code %s", result.returncode)
        raise SystemExit(result.returncode)

    if not output_xlsx.is_file() or not output_json_gz.is_file():
        log.error("Expected output files missing in %s", raw_dir)
        raise SystemExit(2)

    try:
        with gzip.open(output_json_gz, "rt", encoding="utf-8") as handle:
            payload = json.load(handle)
        meta = payload.get("meta", {}) if isinstance(payload, dict) else {}
        uid_count = int(meta.get("uid_count", 0) or 0)
        success_count = int(meta.get("success_count", 0) or 0)
        error_count = int(meta.get("error_count", 0) or 0)
        found_count = int(meta.get("found_count", 0) or 0)

        log.info("DALI summary: uid_count=%s success_count=%s found_count=%s error_count=%s", uid_count, success_count, found_count, error_count)

        if not args.dry_run and uid_count > 0 and success_count == 0:
            errors = payload.get("errors", []) if isinstance(payload, dict) else []
            all_http_400 = bool(errors) and all("HTTP 400" in str(err.get("error", "")) for err in errors if isinstance(err, dict))
            for err in errors[:3]:
                if isinstance(err, dict):
                    log.error("DALI error detail uid=%s: %s", err.get("uid", "<unknown>"), err.get("error", ""))
            if all_http_400:
                log.error(
                    "All DALI requests failed with HTTP 400. TLS seems configured; check impact endpoint and query params (filters/status/zones/environments) against DALI API contract."
                )
            else:
                log.error(
                    "All DALI requests failed (0 successful calls). Check TLS/CA config (VERIFY_CA or SG CA bundle), credentials, and API parameters."
                )
            raise SystemExit(3)
    except SystemExit:
        raise
    except Exception as exc:
        log.warning("Unable to parse JSON summary for post-check: %s", exc)

    log.info("DALI extraction completed successfully")
    log.info("XLSX output: %s", output_xlsx)
    log.info("JSON.GZ output: %s", output_json_gz)
    log.info("Execution log: %s", log_file)


if __name__ == "__main__":
    main()
