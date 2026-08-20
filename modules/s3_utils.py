import logging
from pathlib import Path
from typing import Dict

S3_CONF_KEYS = (
    "S3_ENDPOINT_URL", "S3_BUCKET", "S3_PREFIX", "S3_ACCESS_KEY",
    "S3_SECRET_KEY", "S3_REGION", "S3_VERIFY_SSL",
)


def build_s3_conf_from_env(environment: Dict[str, str]) -> Dict[str, str]:
    """Return normalized S3 settings from an environment-like mapping."""
    return {key: (environment.get(key) or "").strip() for key in S3_CONF_KEYS}


def _is_truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "y"}


def _create_s3_client(**kwargs):
    # Imported only when delivery is requested so unrelated orchestrator modes
    # can still start and report a clear missing-dependency error at that point.
    import boto3

    return boto3.client("s3", **kwargs)


def upload_and_verify_file(path: Path, conf: Dict[str, str], log: logging.Logger) -> str:
    """Upload *path* and verify it with HEAD; return its ``s3://`` URI."""
    required = ("S3_ENDPOINT_URL", "S3_BUCKET", "S3_ACCESS_KEY", "S3_SECRET_KEY")
    missing = [key for key in required if not conf.get(key)]
    if missing:
        log.error("S3 upload cannot start; missing configuration keys: %s", ", ".join(missing))
        raise ValueError(f"Missing S3 configuration: {', '.join(missing)}")
    if not path.is_file():
        log.error("S3 upload cannot start; local file does not exist: %s", path)
        raise FileNotFoundError(f"Cannot upload missing file: {path}")

    prefix = conf.get("S3_PREFIX", "").strip("/")
    object_key = "/".join(part for part in (prefix, path.name) if part)
    verify_value = conf.get("S3_VERIFY_SSL", "true")
    booleans = {"0", "1", "true", "false", "yes", "no", "y", "n"}
    verify = _is_truthy(verify_value) if verify_value.lower() in booleans else verify_value
    log.info(
        "Preparing S3 client: endpoint=%s bucket=%s prefix=%s region=%s verify_ssl=%s",
        conf["S3_ENDPOINT_URL"],
        conf["S3_BUCKET"],
        prefix or "<root>",
        conf.get("S3_REGION") or "<default>",
        verify_value,
    )
    client = _create_s3_client(
        endpoint_url=conf["S3_ENDPOINT_URL"].rstrip("/"),
        aws_access_key_id=conf["S3_ACCESS_KEY"],
        aws_secret_access_key=conf["S3_SECRET_KEY"],
        region_name=conf.get("S3_REGION") or None,
        verify=verify,
    )

    local_size = path.stat().st_size
    log.info("Starting S3 upload: local_file=%s object_key=%s size=%s bytes", path, object_key, local_size)
    try:
        client.upload_file(str(path), conf["S3_BUCKET"], object_key)
        log.info("S3 upload API call completed; starting HEAD verification for %s", object_key)
        metadata = client.head_object(Bucket=conf["S3_BUCKET"], Key=object_key)
    except Exception:
        log.exception(
            "S3 upload or verification request failed: endpoint=%s bucket=%s key=%s",
            conf["S3_ENDPOINT_URL"],
            conf["S3_BUCKET"],
            object_key,
        )
        raise
    remote_size = int(metadata.get("ContentLength", -1))
    if remote_size != local_size:
        log.error(
            "S3 verification size mismatch: key=%s local_size=%s remote_size=%s",
            object_key,
            local_size,
            remote_size,
        )
        raise RuntimeError(
            f"S3 verification failed for {object_key}: local size={local_size}, remote size={remote_size}"
        )

    uri = f"s3://{conf['S3_BUCKET']}/{object_key}"
    log.info("Uploaded and verified KPI report in S3: %s (%s bytes)", uri, local_size)
    return uri
