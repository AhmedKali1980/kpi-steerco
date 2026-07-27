import csv
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class DerivedWorkloadExportTests(unittest.TestCase):
    def test_automation_gen2_unmanaged_workload_uses_interfaces_ip(self):
        rows = self._run_derived_export(
            [
                {
                    "hostname": "unmanaged-linux",
                    "interfaces": "eth0:192.163.231.75",
                    "ip_with_default_gw": "",
                    "os_id": "",
                    "managed": "false",
                    "external_data_set": "Automation GEN2",
                },
                {
                    "hostname": "unmanaged-windows",
                    "interfaces": "eth0:192.163.231.76/24",
                    "ip_with_default_gw": "",
                    "os_id": "",
                    "managed": "false",
                    "external_data_set": " automation gen2 ",
                },
            ]
        )

        self.assertEqual(rows[0]["ocs_name_from_IP"], "IP-192-163-231-75")
        self.assertEqual(rows[1]["ocs_name_from_IP"], "IP-192-163-231-76")
        self.assertEqual(rows[0]["IPLIST"], "NZ3_XXX")

    def test_other_unmanaged_workloads_remain_unchanged(self):
        rows = self._run_derived_export(
            [
                {
                    "hostname": "other-source",
                    "interfaces": "eth0:192.163.231.77",
                    "ip_with_default_gw": "",
                    "os_id": "ubuntu",
                    "managed": "false",
                    "external_data_set": "Manual",
                },
                {
                    "hostname": "missing-ip",
                    "interfaces": "eth0:not-an-ip",
                    "ip_with_default_gw": "",
                    "os_id": "ubuntu",
                    "managed": "false",
                    "external_data_set": "Automation GEN2",
                },
            ]
        )

        self.assertEqual([row["ocs_name_from_IP"] for row in rows], ["", ""])

    def test_managed_workload_still_uses_default_gateway_ip(self):
        rows = self._run_derived_export(
            [
                {
                    "hostname": "managed",
                    "interfaces": "eth0:192.163.231.79",
                    "ip_with_default_gw": "10.20.30.40",
                    "os_id": "ubuntu",
                    "managed": "true",
                    "external_data_set": "",
                }
            ]
        )

        self.assertEqual(rows[0]["ocs_name_from_IP"], "IP-10-20-30-40")

    def _run_derived_export(self, workload_rows):
        with tempfile.TemporaryDirectory() as tmpdir:
            temp = Path(tmpdir)
            stub_dir = temp / "stub"
            run_dir = temp / "run"
            stub_dir.mkdir()
            env_file = temp / ".env"
            env_file.write_text("# test\n", encoding="utf-8")

            workload_path = stub_dir / "export_wkld.csv"
            fieldnames = ["hostname", "interfaces", "ip_with_default_gw", "os_id", "managed", "external_data_set"]
            with workload_path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(workload_rows)

            with (stub_dir / "export_iplists.csv").open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=["name", "include"])
                writer.writeheader()
                writer.writerow({"name": "NZ3_XXX", "include": "192.163.231.0/24"})

            env = os.environ.copy()
            env.update({"PCE_STUB_DIR": str(stub_dir), "ENV_FILE": str(env_file)})
            subprocess.run(
                [str(ROOT / "bin" / "cron_job.sh"), str(run_dir)],
                cwd=ROOT,
                env=env,
                check=True,
                capture_output=True,
                text=True,
            )

            with (run_dir / "raw" / "export_wkld.derived.csv").open(encoding="utf-8", newline="") as handle:
                return list(csv.DictReader(handle))


if __name__ == "__main__":
    unittest.main()
