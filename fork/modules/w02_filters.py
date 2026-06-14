"""Apply user-configured W02 filter decision columns.

This fork-local module reads ``fork/users_input/filters.conf`` and inserts one
filter decision column immediately to the right of each configured W02 source
column. A filter column contains ``Y`` when the row value remains in scope and
``N`` when the row value is excluded by the corresponding include/exclude rule.

The input format is one filter per line::

    FILTER_EXCLUDE_CLOUDTYPE=Private Cloud;Legacy
    FILTER_INCLUDE_OSNAME=Linux;AIX

``FILTER_INCLUDE_*`` filters keep only listed values. ``FILTER_EXCLUDE_*``
filters reject listed values. Empty filter definitions are kept as visible
columns and default to ``Y`` for every row so users can see that the filter is
available but not active.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

log = logging.getLogger(__name__)

INCLUDE_PREFIX = "FILTER_INCLUDE_"
EXCLUDE_PREFIX = "FILTER_EXCLUDE_"

FILTER_COLUMN_BG_COLOR = "#D9D9D9"


@dataclass(frozen=True)
class W02FilterDefinition:
    """Declarative mapping between a user filter and its W02 decision column."""

    name: str
    target_column: str
    output_column: str
    match_mode: str = "exact"


W02_FILTER_DEFINITIONS: Tuple[W02FilterDefinition, ...] = (
    W02FilterDefinition(
        name="FILTER_EXCLUDE_CLOUDTYPE",
        target_column="DALI [CI] CLOUD TYPE",
        output_column="F_EXCLUDE_CLOUDTYPE",
    ),
    W02FilterDefinition(
        name="FILTER_INCLUDE_OSNAME",
        target_column="DALI [CI] OS NAME",
        output_column="F_INCLUDE_OSNAME",
    ),
    W02FilterDefinition(
        name="FILTER_EXCLUDE_MAINAPP",
        target_column="DALI [CI] MAIN APPLICATION",
        output_column="F_EXCLUDE_MAINAPP",
    ),
    W02FilterDefinition(
        name="FILTER_EXCLUDE_TYPOLOGY",
        target_column="DALI [CI] TYPOLOGY",
        output_column="F_EXCLUDE_TYPOLOGY",
    ),
    W02FilterDefinition(
        name="FILTER_EXCLUDE_DOMAIN",
        target_column="DALI [CI] DNS NAME",
        output_column="F_EXCLUDE_DOMAIN",
        match_mode="contains",
    ),
)

W02_FILTER_HEADERS = tuple(definition.output_column for definition in W02_FILTER_DEFINITIONS)


def _normalize(value: Any) -> str:
    return str(value or "").strip().casefold()


def read_filters_config(filters_file: Path) -> Dict[str, List[str]]:
    """Read ``filters.conf`` values using ``FILTER=value1;value2`` syntax."""
    filters: Dict[str, List[str]] = {}
    if not filters_file.is_file():
        log.warning("STEP 02C - W02 filters | Missing filters file=%s; filter columns will default to Y", filters_file)
        return filters

    with filters_file.open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                log.warning("STEP 02C - W02 filters | Ignoring invalid line %s in %s: missing '='", line_number, filters_file)
                continue
            name, raw_values = line.split("=", 1)
            filter_name = name.strip()
            if not filter_name:
                log.warning("STEP 02C - W02 filters | Ignoring invalid line %s in %s: empty filter name", line_number, filters_file)
                continue
            filters[filter_name] = [value.strip() for value in raw_values.split(";") if value.strip()]
    return filters


def _matches(value: Any, candidates: Iterable[str], match_mode: str) -> bool:
    normalized_value = _normalize(value)
    normalized_candidates = [_normalize(candidate) for candidate in candidates if _normalize(candidate)]
    if not normalized_candidates:
        return False
    if match_mode == "contains":
        return any(candidate in normalized_value for candidate in normalized_candidates)
    return normalized_value in set(normalized_candidates)


def _filter_decision(filter_name: str, value: Any, configured_values: Iterable[str], match_mode: str) -> str:
    values = list(configured_values)
    if not values:
        return "Y"
    matched = _matches(value, values, match_mode)
    if filter_name.startswith(INCLUDE_PREFIX):
        return "Y" if matched else "N"
    if filter_name.startswith(EXCLUDE_PREFIX):
        return "N" if matched else "Y"
    log.warning("STEP 02C - W02 filters | Unsupported filter prefix for %s; defaulting row to Y", filter_name)
    return "Y"


def w02_headers_with_filter_columns(headers: Iterable[str]) -> List[str]:
    """Insert each W02 filter column immediately after its configured target column."""
    output: List[str] = []
    definitions_by_target = {definition.target_column: definition for definition in W02_FILTER_DEFINITIONS}
    already_present = set(headers)
    for header in headers:
        if header in W02_FILTER_HEADERS:
            continue
        output.append(header)
        definition = definitions_by_target.get(header)
        if definition and definition.output_column not in already_present:
            output.append(definition.output_column)

    existing = set(output)
    for definition in W02_FILTER_DEFINITIONS:
        if definition.output_column not in existing:
            output.append(definition.output_column)
            log.warning(
                "STEP 02C - W02 filters | Target column not found; appended filter column at end | target=%s | filter_column=%s",
                definition.target_column,
                definition.output_column,
            )
    return output


def apply_w02_filters(
    w02_rows: List[Dict[str, Any]],
    filters_file: Path,
) -> Tuple[List[Dict[str, str]], Dict[str, Dict[str, int]]]:
    """Populate W02 filter decision columns from ``filters.conf``."""
    configured_filters = read_filters_config(filters_file)
    summary: Dict[str, Dict[str, int]] = {}
    filtered_rows: List[Dict[str, str]] = []

    log.info("STEP 02C - W02 filters | Starting | filters_file=%s | W02 rows=%s", filters_file, len(w02_rows))
    for row in w02_rows:
        filtered = {str(key): str(value or "") for key, value in row.items()}
        for definition in W02_FILTER_DEFINITIONS:
            decision = _filter_decision(
                filter_name=definition.name,
                value=filtered.get(definition.target_column, ""),
                configured_values=configured_filters.get(definition.name, []),
                match_mode=definition.match_mode,
            )
            filtered[definition.output_column] = decision
            counters = summary.setdefault(definition.name, {"Y": 0, "N": 0, "configured_values": len(configured_filters.get(definition.name, []))})
            counters[decision] += 1
        filtered_rows.append(filtered)

    for definition in W02_FILTER_DEFINITIONS:
        summary.setdefault(definition.name, {"Y": 0, "N": 0, "configured_values": len(configured_filters.get(definition.name, []))})
    log.info("STEP 02C - W02 filters | Completed | summary=%s", summary)
    return filtered_rows, summary
