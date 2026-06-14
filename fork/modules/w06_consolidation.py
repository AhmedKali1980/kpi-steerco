"""Build the fork-local W06 worksheet from retained W02 assets.

This first W06 increment deliberately transports values from W02 only. W03 and
W04 will be connected by later increments. W02 filter decision columns (headers
starting with ``F_``) are technical columns used to decide scope and are
intentionally not copied to W06.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Tuple

from w02_filters import W02_FILTER_CONSOLIDATED_HEADER

log = logging.getLogger(__name__)

RETRIEVED_FROM_HEADER = "Retrieved from"
RETRIEVED_FROM_DALI_EXPORT = "Dali Export"
FILTER_HEADER_PREFIX = "F_"


def w06_headers_from_w02(w02_headers: Iterable[str]) -> List[str]:
    """Return W06 headers derived from W02 headers without filter columns."""
    headers = [str(header) for header in w02_headers if not str(header).startswith(FILTER_HEADER_PREFIX)]
    if RETRIEVED_FROM_HEADER not in headers:
        headers.append(RETRIEVED_FROM_HEADER)
    return headers


def build_w06_rows(
    w02_rows: List[Dict[str, Any]],
    w02_headers: Iterable[str],
) -> Tuple[List[Dict[str, str]], List[str]]:
    """Build W06 rows from in-scope W02 assets.

    Args:
        w02_rows: Enriched and filtered W02 rows.
        w02_headers: Final W02 workbook headers, including inserted filter columns.

    Returns:
        A tuple containing W06 rows and W06 headers.
    """
    input_headers = [str(header) for header in w02_headers]
    headers = w06_headers_from_w02(input_headers)
    excluded_filter_headers = [header for header in input_headers if header.startswith(FILTER_HEADER_PREFIX)]
    rows: List[Dict[str, str]] = []
    skipped_rows = 0
    for row in w02_rows:
        if str(row.get(W02_FILTER_CONSOLIDATED_HEADER, "")).strip().upper() != "Y":
            skipped_rows += 1
            continue
        consolidated_row = {header: str(row.get(header, "") or "") for header in headers if header != RETRIEVED_FROM_HEADER}
        consolidated_row[RETRIEVED_FROM_HEADER] = RETRIEVED_FROM_DALI_EXPORT
        rows.append(consolidated_row)

    log.info(
        "STEP 06 - W06 consolidation | Built from W02 only | source=W02 | W02 input rows=%s | retained rows F_ALL_FILTERS=Y=%s | skipped rows=%s | transported columns=%s | excluded filter columns=%s | retrieved_from=%s",
        len(w02_rows),
        len(rows),
        skipped_rows,
        len(headers),
        excluded_filter_headers,
        RETRIEVED_FROM_DALI_EXPORT,
    )
    return rows, headers
