import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "modules"))

from internet_exposed_extract import (
    ALL_FILTERS_FIELD,
    FILTER_DEFINITIONS,
    INVENTORY_ENRICHMENT_FIELDS,
    apply_internet_exposed_filters,
    apply_inventory_enrichment,
    build_fieldnames,
    read_filters_conf,
)


class InternetExposedFilterTests(unittest.TestCase):
    def test_filter_columns_are_inserted_after_target_fields_and_all_filter_is_last(self):
        source_fields = [
            "server_os_name",
            "server_cloud_type",
            "application_dali_dsi",
            "server_status",
            "server_typology",
            "server_environment",
            "server_silo",
        ]
        fieldnames = build_fieldnames(source_fields)

        for definition in FILTER_DEFINITIONS:
            target_index = fieldnames.index(definition["field"])
            self.assertEqual(fieldnames[target_index + 1], definition["name"])
        self.assertEqual(fieldnames[-4:-1], INVENTORY_ENRICHMENT_FIELDS)
        self.assertEqual(fieldnames[-1], ALL_FILTERS_FIELD)

    def test_filters_are_case_insensitive_and_support_exact_or_contains_modes(self):
        filters = {
            "F_INTEXP.INCLUDE_server_os_name": "LINUX",
            "F_INTEXP.INCLUDE_server_cloud_type": "GEN 2",
            "F_INTEXP.EXCLUDE_application_dali_dsi": "ayvens",
            "F_INTEXP.INCLUDE_server_status": "active",
            "F_INTEXP.EXCLUDE_server_typology": "HyperVisor",
            "F_INTEXP.INCLUDE_server_environment": "prd",
            "F_INTEXP.EXCLUDE_server_silo": "oos",
        }
        rows = [
            {
                "server_os_name": "Linux",
                "server_cloud_type": "Gen 2",
                "application_dali_dsi": "Retail",
                "server_status": "Active",
                "server_typology": "Virtual Machine",
                "server_environment": "APP-PRD-EUR",
                "server_silo": "RUN",
            },
            {
                "server_os_name": "Linux",
                "server_cloud_type": "Gen 2",
                "application_dali_dsi": "Ayvens Platform",
                "server_status": "Active",
                "server_typology": "Virtual Machine",
                "server_environment": "APP-PRD-EUR",
                "server_silo": "RUN",
            },
        ]

        apply_internet_exposed_filters(rows, filters)

        self.assertEqual(rows[0][ALL_FILTERS_FIELD], "Y")
        self.assertEqual(rows[1]["F_INTEXP.EXCLUDE_application_dali_dsi"], "N")
        self.assertEqual(rows[1][ALL_FILTERS_FIELD], "N")


    def test_inventory_enrichment_only_applies_to_gen2_rows_before_all_filters(self):
        rows = [
            {"server_cloud_type": "Gen 2", "server_uid": "srv-1"},
            {"server_cloud_type": "Gen 1", "server_uid": "srv-2"},
        ]
        apply_inventory_enrichment(
            rows,
            {
                "SRV-1": {"owner_app_name": "App One", "beneficiary": "BEN", "region": "EUR"},
                "SRV-2": {"owner_app_name": "App Two", "beneficiary": "BEN2", "region": "AMER"},
            },
        )

        self.assertEqual(rows[0]["INV_owner_app_name"], "App One")
        self.assertEqual(rows[0]["INV_beneficiary"], "BEN")
        self.assertEqual(rows[0]["INV_region"], "EUR")
        self.assertEqual(rows[1]["INV_owner_app_name"], "")
        self.assertEqual(rows[1]["INV_beneficiary"], "")
        self.assertEqual(rows[1]["INV_region"], "")

    def test_read_filters_conf_supports_equal_and_comma_separators(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "filters.conf"
            path.write_text("F_A=one,two\nF_B,three,four\n", encoding="utf-8")
            filters = read_filters_conf(str(path))

        self.assertEqual(filters["F_A"], "one,two")
        self.assertEqual(filters["F_B"], "three,four")


if __name__ == "__main__":
    unittest.main()
