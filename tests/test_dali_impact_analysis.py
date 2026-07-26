import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "modules"))

from dali_impact_analysis import (
    _pptx_indicator_symbol,
    _xlsx_conditional_formatting_xml,
    apply_manual_exclusions,
    build_program_recap_sheets,
)


class StatsIndicatorFormattingTests(unittest.TestCase):
    def test_indicator_xml_keeps_traffic_lights_and_uses_absolute_business_thresholds(self):
        xml = _xlsx_conditional_formatting_xml(
            ["% servers with illumio installed Indicator Icon"],
            row_count=4,
        )

        self.assertIn('<conditionalFormatting sqref="A2:A5">', xml)
        self.assertIn('<iconSet iconSet="3TrafficLights1" showValue="0">', xml)
        self.assertIn('<cfvo type="num" val="0"/>', xml)
        self.assertIn('<cfvo type="num" val="90"/>', xml)
        self.assertIn('<cfvo type="num" val="95"/>', xml)
        self.assertNotIn('<cfvo type="percent"', xml)
        self.assertNotIn("3Triangles", xml)

    def test_threshold_change_does_not_modify_indicator_or_trend_icon_sets(self):
        fields = []
        for metric in (
            "% servers with illumio installed",
            "% servers with illumio installed (Enriched)",
            "% servers with illumio agent in blocking mode",
            "% servers with illumio agent in blocking mode (Enriched)",
        ):
            fields.extend((metric, f"{metric} Indicator Icon", f"{metric} Trend Icon"))

        xml = _xlsx_conditional_formatting_xml(fields, row_count=2)

        self.assertEqual(xml.count('<iconSet iconSet="3TrafficLights1" showValue="0">'), 4)
        self.assertEqual(xml.count('<x14:iconSet iconSet="3Triangles" custom="1" showValue="0">'), 4)
        self.assertEqual(xml.count('<cfvo type="num" val="90"/>'), 4)
        self.assertEqual(xml.count('<cfvo type="num" val="95"/>'), 4)
        self.assertEqual(xml.count('<x14:cfIcon iconSet="3Triangles"'), 12)

    def test_indicator_boundaries_match_excel_rendering_in_pptx(self):
        red = ("■", (192, 0, 0))
        orange = ("■", (191, 144, 0))
        green = ("■", (0, 128, 0))

        self.assertEqual(_pptx_indicator_symbol("0"), red)
        self.assertEqual(_pptx_indicator_symbol("89.99"), red)
        self.assertEqual(_pptx_indicator_symbol("90"), orange)
        self.assertEqual(_pptx_indicator_symbol("94.99"), orange)
        self.assertEqual(_pptx_indicator_symbol("95"), green)
        self.assertEqual(_pptx_indicator_symbol("100"), green)


class BuildProgramRecapSheetsTests(unittest.TestCase):
    def _stats_rows(self, *, monitored_rows, filtered_rows=None, scope_rows=None, raw_rows=None, enrich_rows=None):
        with tempfile.TemporaryDirectory() as tmpdir:
            sheets = build_program_recap_sheets(
                monitored_rows=monitored_rows,
                filtered_rows=filtered_rows or [],
                scope_rows=scope_rows or [],
                raw_rows=raw_rows or [],
                enrich_rows=enrich_rows or [],
                output_path=Path(tmpdir) / "dali_impact_analysis.xlsx",
            )
        return {name: rows for name, rows, _headers in sheets}["STATS"]

    def test_stats_metadata_falls_back_to_raw_when_in_scope_total_is_zero(self):
        rows = self._stats_rows(
            monitored_rows=[{"program": "P1", "uid": "APP1"}],
            raw_rows=[
                {
                    "uid": "APP1",
                    "DALI [APP] DSI": "Entity A",
                    "DALI [APP] APPLICATION MANAGEMENT RC": "SubEntity A - Something",
                    "DALI [APP] SHORT LABEL": "App A",
                }
            ],
        )

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["Total Assets in Dali (in scope)"], "0")
        self.assertEqual(rows[0]["Total Assets in Dali (Enriched)"], "0")
        self.assertEqual(rows[0]["Entity"], "Entity A")
        self.assertEqual(rows[0]["Sub-Entity"], "SubEntity A")
        self.assertEqual(rows[0]["Application Short Label"], "App A")

    def test_scope_metadata_keeps_priority_over_raw_fallback(self):
        rows = self._stats_rows(
            monitored_rows=[{"program": "P1", "uid": "APP1"}],
            scope_rows=[
                {
                    "uid": "APP1",
                    "program": "P1",
                    "DALI [APP] DSI": "Scope Entity",
                    "DALI [APP] APPLICATION MANAGEMENT RC": "Scope Sub - Label",
                    "DALI [APP] SHORT LABEL": "Scope App",
                }
            ],
            raw_rows=[
                {
                    "uid": "APP1",
                    "DALI [APP] DSI": "Raw Entity",
                    "DALI [APP] APPLICATION MANAGEMENT RC": "Raw Sub - Label",
                    "DALI [APP] SHORT LABEL": "Raw App",
                }
            ],
        )

        self.assertEqual(rows[0]["Total Assets in Dali (Enriched)"], "1")
        self.assertEqual(rows[0]["Entity"], "Scope Entity")
        self.assertEqual(rows[0]["Sub-Entity"], "Scope Sub")
        self.assertEqual(rows[0]["Application Short Label"], "Scope App")


class ApplyManualExclusionsTests(unittest.TestCase):
    def test_excludes_all_matching_server_occurrences(self):
        rows = [
            {"HOSTNAME": "DQ issue : Hostname is empty", "F_Excluded": "N", "F_FILTER_ALL": "Y", "In scope": "TRUE"},
            {"USUAL NAME": "dq issue : hostname is empty", "F_Excluded": "N", "F_FILTER_ALL": "Y", "In scope": "TRUE"},
            {"HOSTNAME": "another-server", "F_Excluded": "N", "F_FILTER_ALL": "Y", "In scope": "TRUE"},
        ]

        excluded_rows = apply_manual_exclusions(rows, ["DQ issue : Hostname is empty"])

        self.assertEqual(len(excluded_rows), 1)
        self.assertEqual(excluded_rows[0]["Retrived by"], "HOSTNAME")
        for row in rows[:2]:
            self.assertEqual(row["F_Excluded"], "Y")
            self.assertEqual(row["F_FILTER_ALL"], "N")
            self.assertEqual(row["In scope"], "FALSE")
        self.assertEqual(rows[2]["F_Excluded"], "N")

    def test_excludes_matching_dali_hostname_columns(self):
        rows = [
            {
                "DALI [CI] HOSTNAME": "DQ issue : Hostname is empty",
                "F_Excluded": "N",
                "F_FILTER_ALL": "Y",
                "In scope": "TRUE",
            },
            {
                "DALI [CI] USUAL NAME": "DQ issue : Hostname is empty",
                "F_Excluded": "N",
                "F_FILTER_ALL": "Y",
                "In scope": "TRUE",
            },
        ]

        apply_manual_exclusions(rows, ["DQ issue : Hostname is empty"])

        for row in rows:
            self.assertEqual(row["F_Excluded"], "Y")
            self.assertEqual(row["F_FILTER_ALL"], "N")
            self.assertEqual(row["In scope"], "FALSE")


if __name__ == "__main__":
    unittest.main()
