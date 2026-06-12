"""Minimal Data4Sec Elasticsearch client for fork Data4Sec lookups."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan

from certificates import get_cacert_path
from config import ELASTICSEARCH

log = logging.getLogger(__name__)


def _nested_get(data: dict, dotted_path: str) -> Any:
    if dotted_path in data:
        return data.get(dotted_path)
    current: Any = data
    for part in str(dotted_path or "").split("."):
        if not part:
            continue
        if not isinstance(current, dict):
            return None
        current = current.get(part)
        if current is None:
            return None
    return current


def _normalize_result_candidates(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(item or "").strip().upper() for item in value if str(item or "").strip()]
    if value is None:
        return []
    return [str(value or "").strip().upper()]


def _short_hostname(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    return raw.split(".", 1)[0].strip()


def _case_variants_many(values: List[str]) -> List[str]:
    output: List[str] = []
    seen: set[str] = set()
    for value in values:
        raw = str(value or "").strip()
        for candidate in (raw, raw.lower(), raw.upper()):
            if candidate and candidate not in seen:
                seen.add(candidate)
                output.append(candidate)
    return output


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


    @staticmethod
    def build_terms_query(
        search_field: str,
        values: List[str],
        source_fields: List[str],
        size: int,
        term_filters: Optional[Dict[str, List[str]]] = None,
    ) -> dict:
        keyword_field = search_field if search_field.endswith(".keyword") else f"{search_field}.keyword"
        normalized_values = [str(value or "").strip() for value in values if str(value or "").strip()]
        case_variants = _case_variants_many(normalized_values)
        if search_field in {"hostname", "ocs_name"}:
            short_values = [short for short in {_short_hostname(value) for value in case_variants} if short]
            short_case_variants = _case_variants_many(short_values)
            filters = [
                {
                    "bool": {
                        "should": [
                            {"terms": {keyword_field: case_variants}},
                            {"terms": {search_field: short_case_variants}},
                        ],
                        "minimum_should_match": 1,
                    }
                }
            ]
        else:
            filters = [{"terms": {keyword_field: case_variants}}]

        for field_name, field_values in (term_filters or {}).items():
            if field_values:
                filters.append({"terms": {field_name: field_values}})

        return {
            "_source": source_fields,
            "query": {"bool": {"filter": filters}},
            "size": size,
            "sort": ["_doc"],
        }

    def bulk_search_multi(
        self,
        index_name: str,
        search_field: str,
        values: List[str],
        source_fields: List[str],
        scroll_timeout: str = "10m",
        size: int = 500,
        term_filters: Optional[Dict[str, List[str]]] = None,
    ) -> Dict[str, List[dict]]:
        query = self.build_terms_query(search_field, values, source_fields, size, term_filters=term_filters)
        normalized_values = [str(value or "").strip().upper() for value in values if str(value or "").strip()]
        results: Dict[str, List[dict]] = {value: [] for value in normalized_values}

        log.info(
            "Data4Sec bulk_search_multi start index=%s search_field=%s lookup_values=%s source_fields=%s term_filters=%s",
            index_name,
            search_field,
            len(normalized_values),
            source_fields,
            term_filters or {},
        )
        log.debug("Data4Sec query payload for index=%s field=%s: %s", index_name, search_field, query)

        hit_count = 0
        for hit in scan(self.es_connection, index=index_name, query=query, scroll=scroll_timeout, size=size):
            hit_count += 1
            source = hit.get("_source", {}) or {}
            raw_value = _nested_get(source, search_field)
            candidates = _normalize_result_candidates(raw_value)

            expanded_candidates = set(candidates)
            expanded_candidates.update(_short_hostname(candidate).upper() for candidate in candidates if candidate)
            for candidate in expanded_candidates:
                if candidate in results:
                    results[candidate].append(source)

        log.info(
            "Data4Sec bulk_search_multi done index=%s search_field=%s scanned_hits=%s matched_lookup_values=%s matched_docs=%s",
            index_name,
            search_field,
            hit_count,
            sum(1 for docs in results.values() if docs),
            sum(len(docs) for docs in results.values()),
        )
        return results

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
