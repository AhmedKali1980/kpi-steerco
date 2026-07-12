import logging
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from kpi_orchestrator import append_internet_exposed_stats_to_kpi_workbook

try:
    from openpyxl import Workbook, load_workbook
except ImportError:  # pragma: no cover - optional test dependency
    Workbook = None
    load_workbook = None


@unittest.skipIf(Workbook is None or load_workbook is None, "openpyxl is required for XLSX append tests")
class AppendInternetExposedStatsTests(unittest.TestCase):
    def test_append_maps_stats_columns_and_sets_enriched_values_to_na(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            kpi_path = tmp_path / "kpi_microseg.xlsx"
            internet_path = tmp_path / "internet_exposed.xlsx"

            kpi_wb = Workbook()
            stats_ws = kpi_wb.active
            stats_ws.title = "STATS"
            stats_ws.append(
                [
                    "Index",
                    "Program",
                    "Kear ID",
                    "Total Assets in Dali (in scope)",
                    "Total Assets in Dali (Enriched)",
                    "% servers with illumio installed",
                    "% servers with illumio installed (Enriched)",
                    "% servers with illumio installed Indicator Icon",
                    "% servers with illumio installed (Enriched) Indicator Icon",
                ]
            )
            stats_ws.append([1, "P1", "APP-BASE", "2", "3", "(1/2) 50,00%", "(2/3) 66,67%", 50, 66.67])
            stats_ws.auto_filter.ref = stats_ws.dimensions
            kpi_wb.save(kpi_path)
            kpi_wb.close()

            internet_wb = Workbook()
            internet_ws = internet_wb.active
            internet_ws.title = "STATS.INTEXPOSED"
            internet_ws.append(
                [
                    "Index",
                    "Program",
                    "Kear ID",
                    "Total Assets in Dali (in scope)",
                    "% servers with illumio installed",
                    "% servers with illumio installed Indicator Icon",
                ]
            )
            internet_ws.append([1, "PINT", "APP-INT", "1", "(1/1) 100,00%", 100])
            internet_wb.save(internet_path)
            internet_wb.close()

            appended = append_internet_exposed_stats_to_kpi_workbook(
                kpi_xlsx=kpi_path,
                internet_exposed_xlsx=internet_path,
                log=logging.getLogger("test"),
            )

            self.assertEqual(appended, 1)
            workbook = load_workbook(kpi_path)
            try:
                stats_ws = workbook["STATS"]
                self.assertEqual(stats_ws.max_row, 3)
                self.assertEqual(stats_ws.cell(row=3, column=1).value, 2)
                self.assertEqual(stats_ws.cell(row=3, column=2).value, "PINT")
                self.assertEqual(stats_ws.cell(row=3, column=3).value, "APP-INT")
                self.assertEqual(stats_ws.cell(row=3, column=4).value, "1")
                self.assertEqual(stats_ws.cell(row=3, column=5).value, "N/A")
                self.assertEqual(stats_ws.cell(row=3, column=6).value, "(1/1) 100,00%")
                self.assertEqual(stats_ws.cell(row=3, column=7).value, "N/A")
                self.assertEqual(stats_ws.cell(row=3, column=8).value, 100)
                self.assertEqual(stats_ws.cell(row=3, column=9).value, "N/A")
                self.assertEqual(stats_ws.auto_filter.ref, "A1:I3")
            finally:
                workbook.close()


if __name__ == "__main__":
    unittest.main()
