"""Minimal Data4Sec Elasticsearch client for platform_accounts lookups."""

from __future__ import annotations

import logging
from typing import Dict, List

from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan

from certificates import get_cacert_path
from config import ELASTICSEARCH

log = logging.getLogger(__name__)


def _case_variants(value: str) -> List[str]:
    output: List[str] = []
    seen: set[str] = set()
    raw = str(value or "").strip()
    for candidate in (raw, raw.lower(), raw.upper()):
        if candidate and candidate not in seen:
            seen.add(candidate)
            output.append(candidate)
    return output


class Data4SecClient:
    def __init__(self) -> None:
        host = (ELASTICSEARCH["HOST"] or "").replace("https://", "").replace("http://", "").rstrip("/")
        port = int(ELASTICSEARCH["PORT"] or "443")
        username = ELASTICSEARCH["USERNAME"]
        password = ELASTICSEARCH["PASSWORD"]
        if not host or not username or not password:
            raise ValueError("Missing Data4Sec Elasticsearch settings. Check fork/.env or the project .env.")

        self.es_connection = Elasticsearch(
            hosts=[{"host": host, "port": port, "scheme": "https"}],
            basic_auth=(username, password),
            verify_certs=True,
            ca_certs=get_cacert_path(),
            request_timeout=60,
        )
        log.info("Data4Sec Elasticsearch client initialized for host=%s port=%s", host, port)

    @staticmethod
    def build_kear_tag_query(kear_uid: str, tags_field: str, tag_key: str, source_fields: List[str], size: int) -> dict:
        """Build the platform_accounts query for tags containing KEAR_SG_UID:<uid>."""
        tag_values = [f"{tag_key}:{uid_variant}" for uid_variant in _case_variants(kear_uid)]
        tags_keyword_field = tags_field if tags_field.endswith(".keyword") else f"{tags_field}.keyword"
        return {
            "_source": source_fields,
            "query": {
                "bool": {
                    "should": [
                        {"terms": {tags_field: tag_values}},
                        {"terms": {tags_keyword_field: tag_values}},
                    ],
                    "minimum_should_match": 1,
                }
            },
            "size": size,
            "sort": ["_doc"],
        }

    def search_platform_accounts_by_kear_tag(
        self,
        index_name: str,
        kear_uids: List[str],
        source_fields: List[str],
        scroll_timeout: str,
        size: int,
        tags_field: str,
        tag_key: str,
    ) -> Dict[str, List[dict]]:
        results: Dict[str, List[dict]] = {uid: [] for uid in kear_uids}
        log.info("Querying Data4Sec index=%s tags_field=%s tag_key=%s uid_count=%s", index_name, tags_field, tag_key, len(kear_uids))

        for uid in kear_uids:
            query = self.build_kear_tag_query(
                kear_uid=uid,
                tags_field=tags_field,
                tag_key=tag_key,
                source_fields=source_fields,
                size=size,
            )
            log.debug("Data4Sec platform_accounts query for uid=%s: %s", uid, query)
            for hit in scan(self.es_connection, index=index_name, query=query, scroll=scroll_timeout, size=size):
                results[uid].append(hit.get("_source", {}) or {})
            log.info("Data4Sec platform_accounts uid=%s docs=%s", uid, len(results[uid]))

        matched = sum(1 for docs in results.values() if docs)
        log.info("Data4Sec platform_accounts query done matched_uids=%s/%s", matched, len(kear_uids))
        return results
