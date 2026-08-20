import logging
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from modules.s3_utils import resolve_s3_tls_verify, upload_and_verify_file


class UploadAndVerifyFileTests(unittest.TestCase):
    def test_uploads_to_prefix_and_verifies_remote_size(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            report = Path(tmpdir) / "kpi_microseg_20260101_000000.xlsx"
            report.write_bytes(b"workbook")
            client = Mock()
            client.head_object.return_value = {"ContentLength": len(b"workbook")}
            conf = {
                "S3_ENDPOINT_URL": "https://s3.example.test/",
                "S3_BUCKET": "dcd-d089",
                "S3_PREFIX": "/microseg/",
                "S3_ACCESS_KEY": "access",
                "S3_SECRET_KEY": "secret",
                "S3_REGION": "",
                "S3_VERIFY_SSL": "true",
            }

            with patch("modules.s3_utils.resolve_s3_tls_verify", return_value=True), patch(
                "modules.s3_utils._create_s3_client", return_value=client
            ) as factory:
                uri = upload_and_verify_file(report, conf, logging.getLogger("test"))

            self.assertEqual(uri, "s3://dcd-d089/microseg/kpi_microseg_20260101_000000.xlsx")
            client.upload_file.assert_called_once_with(
                str(report), "dcd-d089", "microseg/kpi_microseg_20260101_000000.xlsx"
            )
            client.head_object.assert_called_once_with(
                Bucket="dcd-d089", Key="microseg/kpi_microseg_20260101_000000.xlsx"
            )
            self.assertTrue(factory.call_args.kwargs["verify"])

    def test_rejects_head_result_with_different_size(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            report = Path(tmpdir) / "report.xlsx"
            report.write_bytes(b"local")
            client = Mock()
            client.head_object.return_value = {"ContentLength": 1}
            conf = {
                "S3_ENDPOINT_URL": "https://s3.example.test",
                "S3_BUCKET": "bucket",
                "S3_PREFIX": "microseg",
                "S3_ACCESS_KEY": "access",
                "S3_SECRET_KEY": "secret",
                "S3_VERIFY_SSL": "false",
            }

            with patch("modules.s3_utils._create_s3_client", return_value=client):
                with self.assertRaisesRegex(RuntimeError, "S3 verification failed"):
                    upload_and_verify_file(report, conf, logging.getLogger("test"))


class ResolveS3TlsVerifyTests(unittest.TestCase):
    def test_reuses_verify_ca_for_s3(self):
        with patch.dict("os.environ", {"VERIFY_CA": "/etc/company-ca.pem"}, clear=True):
            verify = resolve_s3_tls_verify("true", logging.getLogger("test"))

        self.assertEqual(verify, "/etc/company-ca.pem")

    def test_uses_same_detected_ca_bundle_as_elasticsearch(self):
        with patch.dict("os.environ", {}, clear=True), patch(
            "modules.s3_utils.get_cacert_path", return_value="/etc/shared-ca.pem"
        ):
            verify = resolve_s3_tls_verify("", logging.getLogger("test"))

        self.assertEqual(verify, "/etc/shared-ca.pem")

    def test_explicit_false_disables_verification(self):
        self.assertFalse(resolve_s3_tls_verify("false", logging.getLogger("test")))


if __name__ == "__main__":
    unittest.main()
