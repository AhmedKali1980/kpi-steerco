"""Minimal Data4Sec Elasticsearch client for platform_accounts lookups."""

from __future__ import annotations

import logging
from typing import Dict, Iterable, List

from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan

from certificates import get_cacert_path
from config import ELASTICSEARCH
from input_reader import normalize_uid

log = logging.getLogger(__name__)


def _case_variants(values: Iterable[str]) -> List[str]:
    output: List[str] = []
    seen: set[str] = set()
    for value in values:
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
    def build_terms_query(search_field: str, values: List[str], source_fields: List[str], size: int) -> dict:
        keyword_field = search_field if search_field.endswith(".keyword") else f"{search_field}.keyword"
        return {
            "_source": source_fields,
            "query": {"bool": {"filter": [{"terms": {keyword_field: _case_variants(values)}}]}},
            "size": size,
            "sort": ["_doc"],
        }

    def search_platform_accounts_by_kear(
        self,
        index_name: str,
        kear_field: str,
        kear_uids: List[str],
        source_fields: List[str],
        scroll_timeout: str,
        size: int,
    ) -> Dict[str, List[dict]]:
        query = self.build_terms_query(
            search_field=kear_field,
            values=kear_uids,
            source_fields=source_fields,
            size=size,
        )
        results: Dict[str, List[dict]] = {uid: [] for uid in kear_uids}
        log.info("Querying Data4Sec index=%s field=%s uid_count=%s", index_name, kear_field, len(kear_uids))

        for hit in scan(self.es_connection, index=index_name, query=query, scroll=scroll_timeout, size=size):
            source = hit.get("_source", {}) or {}
            key = normalize_uid(source.get(kear_field, ""))
            if key in results:
                results[key].append(source)

        matched = sum(1 for docs in results.values() if docs)
        log.info("Data4Sec platform_accounts query done matched_uids=%s/%s", matched, len(kear_uids))
        return results
