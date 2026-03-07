import os
from dotenv import load_dotenv

load_dotenv()

ELASTICSEARCH = {
    "HOST": (os.getenv("ELASTICSEARCH_WRITE_HOST") or "").strip().strip("'").strip('"'),
    "PORT": (os.getenv("ELASTICSEARCH_WRITE_PORT") or "").strip().strip("'").strip('"'),
    "USERNAME": (os.getenv("ELASTICSEARCH_WRITE_LOGIN") or "").strip().strip("'").strip('"'),
    "PASSWORD": (os.getenv("ELASTICSEARCH_WRITE_PASS") or "").strip().strip("'").strip('"'),
}

QUERY_CONFIG = {
    "dali_servers": {
        "index": "dali_servers",
        "search_fields": [
            "server_hostname",
            "server_usual_name",
            "server_friendly_name",
        ],
        "source_fields": [
            "application_name",
            "application_short_label",
            "application_dali_dsi",
            "server_main_application",
            "application_dali_environment",
            "server_environment",
            "server_hostname",
            "application_dali_status",
            "server_status",
            "server_main_ip_address",
            "ip_address",
            "server_usual_name",
            "server_friendly_name",
            "server_cloud_type",
            "server_os_name",
            "total_hosts",
            "hosts_not_in_pce",
            "protected_hosts",
            "not_protected_hosts",
        ],
    },
    "inventory": {
        "index": "inventory",
        "search_fields": ["ocs_name"],
        "source_fields": ["ocs_name", "hostname", "beneficiary"],
    },
    "scroll_timeout": "10m",
    "batch_size": 500,
}
