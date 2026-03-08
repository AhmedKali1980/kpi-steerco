import logging
from typing import Dict, List, Optional
from elasticsearch import Elasticsearch
from elasticsearch.helpers import scan

from config import ELASTICSEARCH
from sg_cacert_file import get_cacert_path

log = logging.getLogger(__name__)


class Data4secClient:
    def __init__(self):
        self.es_connection = None
        try:
            host = (ELASTICSEARCH["HOST"] or "").replace("https://", "").replace("http://", "").rstrip("/")
            port = int(ELASTICSEARCH["PORT"])
            username = ELASTICSEARCH["USERNAME"]
            password = ELASTICSEARCH["PASSWORD"]
            ca_cert = get_cacert_path()

            if not host or not username or not password:
                raise ValueError("Missing Elasticsearch connection settings in .env")

            self.es_connection = Elasticsearch(
                hosts=[{"host": host, "port": port, "scheme": "https"}],
                basic_auth=(username, password),
                verify_certs=True,
                ca_certs=ca_cert,
                request_timeout=60,
            )
            log.info(
                "Data4Sec Elasticsearch client initialized (host=%s, port=%s, verify_certs=%s)",
                host,
                port,
                True,
            )
        except Exception as exc:
            log.error("Error creating Elasticsearch connection: %s", exc)

    @staticmethod
    def build_terms_query(
        search_field: str,
        values: list[str],
        source_fields: list[str],
        size: int,
        term_filters: Optional[Dict[str, List[str]]] = None,
    ) -> dict:
        keyword_field = f"{search_field}.keyword" if not search_field.endswith(".keyword") else search_field
        filters = [{"terms": {keyword_field: values}}]
        for field_name, field_values in (term_filters or {}).items():
            if not field_values:
                continue
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
        values: list[str],
        source_fields: list[str],
        scroll_timeout: str = "10m",
        size: int = 500,
        term_filters: Optional[Dict[str, List[str]]] = None,
    ) -> dict[str, list[dict]]:
        if not self.es_connection:
            log.error("No Elasticsearch connection available.")
            return {v: [] for v in values}

        query = self.build_terms_query(search_field, values, source_fields, size, term_filters=term_filters)
        results: dict[str, list[dict]] = {v: [] for v in values}
        log.info(
            "Data4Sec bulk_search_multi start index=%s search_field=%s lookup_values=%s source_fields=%s term_filters=%s",
            index_name,
            search_field,
            len(values),
            source_fields,
            term_filters or {},
        )
        log.debug("Data4Sec query payload for index=%s field=%s: %s", index_name, search_field, query)

        try:
            hit_count = 0
            for hit in scan(
                self.es_connection,
                index=index_name,
                query=query,
                scroll=scroll_timeout,
                size=size,
            ):
                hit_count += 1
                source = hit.get("_source", {}) or {}
                raw_value = source.get(search_field)

                if isinstance(raw_value, list):
                    candidates = [str(v).strip().upper() for v in raw_value if str(v).strip()]
                elif raw_value is None:
                    candidates = []
                else:
                    candidates = [str(raw_value).strip().upper()]

                for candidate in candidates:
                    if candidate in results:
                        results[candidate].append(source)

            matched_keys = sum(1 for docs in results.values() if docs)
            matched_docs = sum(len(docs) for docs in results.values())
            log.info(
                "Data4Sec bulk_search_multi done index=%s search_field=%s scanned_hits=%s matched_lookup_values=%s matched_docs=%s",
                index_name,
                search_field,
                hit_count,
                matched_keys,
                matched_docs,
            )
            return results
        except Exception as exc:
            log.error("Error during search on index %s field %s: %s", index_name, search_field, exc)
            return {v: [] for v in values}
