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
    apply_platform_account_mapping,
    distinct_inventory_accounts,
    extract_platform_tag_value,
    build_fieldnames,
    inventory_hostid_from_server_uid,
    read_filters_conf,
    write_xlsx,
    server_uid_from_inventory_hostid,
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
        self.assertEqual(fieldnames[-7:-1], INVENTORY_ENRICHMENT_FIELDS)
        self.assertEqual(fieldnames[fieldnames.index("INV_owner_app_name") + 1], "PA_owner_id")
        self.assertEqual(fieldnames[fieldnames.index("INV_beneficiary") + 1], "PA_beneficiary_id")
        self.assertEqual(fieldnames[fieldnames.index("PA_beneficiary_id") + 1], "PA_beneficiary_ENV")
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



    def test_inventory_hostid_mapping_uses_vm_uppercase_prefix(self):
        self.assertEqual(inventory_hostid_from_server_uid("aaa-bbb-ccc"), "VM_AAA-BBB-CCC")
        self.assertEqual(inventory_hostid_from_server_uid("VM_AAA-BBB-CCC"), "VM_AAA-BBB-CCC")
        self.assertEqual(server_uid_from_inventory_hostid("VM_AAA-BBB-CCC"), "AAA-BBB-CCC")

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


    def test_platform_account_mapping_adds_ids_and_beneficiary_env(self):
        rows = [
            {"INV_owner_app_name": "ACC_A", "INV_beneficiary": "ACC_B"},
            {"INV_owner_app_name": "", "INV_beneficiary": ""},
        ]
        dict_account_rows = [
            {"account": "acc_a", "id": "OWNER-1", "env": "DEV"},
            {"account": "ACC_B", "id": "BEN-1", "env": "PRD"},
        ]

        apply_platform_account_mapping(rows, dict_account_rows)

        self.assertEqual(rows[0]["PA_owner_id"], "OWNER-1")
        self.assertEqual(rows[0]["PA_beneficiary_id"], "BEN-1")
        self.assertEqual(rows[0]["PA_beneficiary_ENV"], "PRD")
        self.assertEqual(rows[1]["PA_owner_id"], "NOT_GEN2")
        self.assertEqual(rows[1]["PA_beneficiary_id"], "NOT_GEN2")
        self.assertEqual(rows[1]["PA_beneficiary_ENV"], "NOT_GEN2")

    def test_distinct_inventory_accounts_uses_owner_and_beneficiary_values(self):
        rows = [
            {"INV_owner_app_name": "ACC_A", "INV_beneficiary": "ACC_B"},
            {"INV_owner_app_name": "acc_a", "INV_beneficiary": ""},
        ]

        self.assertEqual(distinct_inventory_accounts(rows), ["ACC_A", "ACC_B"])

    def test_extract_platform_tag_value_supports_id_and_env_tags(self):
        tags = ["ENV:PRD", "ID:12345"]

        self.assertEqual(extract_platform_tag_value(tags, {"ENV"}), "PRD")
        self.assertEqual(extract_platform_tag_value(tags, {"ID", "ACCOUNT_ID"}), "12345")


    def test_dict_account_sheet_has_formatting(self):
        try:
            from openpyxl import load_workbook
        except ModuleNotFoundError:
            self.skipTest("openpyxl is not installed in this environment")

        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "internet_exposed.xlsx"
            write_xlsx(
                path,
                rows=[],
                fieldnames=["server_uid", "F_ALL_FILTERS"],
                dict_account_rows=[{"account": "ACC_A", "id": "123", "env": "PRD"}],
            )
            workbook = load_workbook(path)
            try:
                ws = workbook["DictAccount"]
                self.assertEqual([cell.value for cell in ws[1]], ["account", "id", "env"])
                self.assertEqual(ws.freeze_panes, "A2")
                self.assertEqual(ws.auto_filter.ref, ws.dimensions)
                self.assertEqual(ws["A1"].fill.fgColor.rgb, "008064A2")
                self.assertIsNotNone(ws["A2"].border.left.style)
                self.assertGreaterEqual(ws.column_dimensions["A"].width, 14)
            finally:
                workbook.close()

    def test_read_filters_conf_supports_equal_and_comma_separators(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "filters.conf"
            path.write_text("F_A=one,two\nF_B,three,four\n", encoding="utf-8")
            filters = read_filters_conf(str(path))

        self.assertEqual(filters["F_A"], "one,two")
        self.assertEqual(filters["F_B"], "three,four")


if __name__ == "__main__":
    unittest.main()
