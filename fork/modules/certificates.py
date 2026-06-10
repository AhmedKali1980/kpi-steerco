"""Certificate bundle resolution for Data4Sec Elasticsearch calls."""

from __future__ import annotations

import os
from pathlib import Path


def get_cacert_path() -> str:
    candidates = [
        os.getenv("ELASTICSEARCH_CA_CERT"),
        os.getenv("ELASTICSEARCH_CA_CERTS"),
        os.getenv("REQUESTS_CA_BUNDLE"),
        os.getenv("SSL_CERT_FILE"),
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/certs/ca-bundle.crt",
        "/etc/ssl/certs/ca-certificates.crt",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return str(Path(candidate))
    raise FileNotFoundError("No CA certificate bundle found. Set ELASTICSEARCH_CA_CERT or REQUESTS_CA_BUNDLE.")
