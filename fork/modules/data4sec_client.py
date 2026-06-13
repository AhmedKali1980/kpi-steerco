"""Minimal Data4Sec Elasticsearch client for fork Data4Sec lookups."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan

from certificates import get_cacert_path
from config import ELASTICSEARCH

log = logging.getLogger(__name__)


def _nested_values(data: Any, dotted_path: str) -> List[Any]:
    parts = [part for part in str(dotted_path or "").split(".") if part]
    if not parts:
        return [data] if data is not None else []

    def walk(current: Any, remaining: List[str]) -> List[Any]:
        if current is None:
            return []
        if not remaining:
            if isinstance(current, list):
                values: List[Any] = []
                for item in current:
                    values.extend(walk(item, []))
                return values
            return [current]
        if isinstance(current, list):
            values: List[Any] = []
            for item in current:
                values.extend(walk(item, remaining))
            return values
        if not isinstance(current, dict):
            return []
        dotted_remaining = ".".join(remaining)
        if dotted_remaining in current:
            return walk(current.get(dotted_remaining), [])
        return walk(current.get(remaining[0]), remaining[1:])

    if isinstance(data, dict) and dotted_path in data:
        return walk(data.get(dotted_path), [])
    return walk(data, parts)


def _normalize_result_candidates(value: Any) -> List[str]:
    values = value if isinstance(value, list) else [value]
    output: List[str] = []
    seen: set[str] = set()
    for item in values:
        normalized = str(item or "").strip().upper()
        if normalized and normalized not in seen:
            seen.add(normalized)
            output.append(normalized)
    return output


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

    @staticmethod
    def build_contains_or_terms_query(
        contains_field: str,
        contains_values: List[str],
        terms_field: str,
        terms_values: List[str],
        source_fields: List[str],
        size: int,
        term_filters: Optional[Dict[str, List[str]]] = None,
    ) -> dict:
        """Build a query that matches values contained in one field or exact terms in another."""
        contains_candidates = _case_variants_many([str(value or "").strip() for value in contains_values])
        term_candidates = _case_variants_many([str(value or "").strip() for value in terms_values])
        contains_keyword_field = contains_field if contains_field.endswith(".keyword") else f"{contains_field}.keyword"
        terms_keyword_field = terms_field if terms_field.endswith(".keyword") else f"{terms_field}.keyword"

        should = []
        for candidate in contains_candidates:
            should.append({"wildcard": {contains_keyword_field: {"value": f"*{candidate}*", "case_insensitive": True}}})
        if term_candidates:
            should.append({"terms": {terms_keyword_field: term_candidates}})

        filters = [{"bool": {"should": should, "minimum_should_match": 1}}] if should else []
        for field_name, field_values in (term_filters or {}).items():
            if field_values:
                filters.append({"terms": {field_name: field_values}})

        return {
            "_source": source_fields,
            "query": {"bool": {"filter": filters}},
            "size": size,
            "sort": ["_doc"],
        }

    def search_contains_or_terms(
        self,
        index_name: str,
        contains_field: str,
        contains_values: List[str],
        terms_field: str,
        terms_values: List[str],
        source_fields: List[str],
        scroll_timeout: str = "10m",
        size: int = 500,
        term_filters: Optional[Dict[str, List[str]]] = None,
    ) -> List[dict]:
        """Return docs where contains_field contains a value or terms_field equals a fallback value."""
        query = self.build_contains_or_terms_query(
            contains_field=contains_field,
            contains_values=contains_values,
            terms_field=terms_field,
            terms_values=terms_values,
            source_fields=source_fields,
            size=size,
            term_filters=term_filters,
        )
        log.info(
            "Data4Sec search_contains_or_terms start index=%s contains_field=%s contains_values=%s terms_field=%s terms_values=%s term_filters=%s",
            index_name,
            contains_field,
            len([value for value in contains_values if str(value or "").strip()]),
            terms_field,
            len([value for value in terms_values if str(value or "").strip()]),
            term_filters or {},
        )
        log.debug("Data4Sec contains/terms query payload for index=%s: %s", index_name, query)

        docs: List[dict] = []
        for hit in scan(self.es_connection, index=index_name, query=query, scroll=scroll_timeout, size=size):
            docs.append(hit.get("_source", {}) or {})

        log.info("Data4Sec search_contains_or_terms done index=%s matched_docs=%s", index_name, len(docs))
        return docs

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
            candidates = _normalize_result_candidates(_nested_values(source, search_field))

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
