import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = Path(__file__).with_name("New-ManagedReleaseEvidence.py")
SPEC = importlib.util.spec_from_file_location("managed_release_evidence", SCRIPT)
EVIDENCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EVIDENCE)


class ManagedReleaseEvidenceTests(unittest.TestCase):
    def test_canonical_json_is_sorted_utf8_with_one_newline(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "evidence.json"
            EVIDENCE.canonical_json(output, {"z": "café", "a": 1})
            self.assertEqual(output.read_bytes(), b'{"a":1,"z":"caf\\u00e9"}\n')
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["z"], "café")

    def test_locked_cargo_inventory_is_large_unique_and_stable(self):
        first = EVIDENCE.cargo_packages(ROOT)
        second = EVIDENCE.cargo_packages(ROOT)
        self.assertEqual(first, second)
        self.assertGreater(len(first), 1000)
        identifiers = [package["SPDXID"] for package in first]
        self.assertEqual(len(identifiers), len(set(identifiers)))
        self.assertIn(
            ("rustdesk", "1.4.9"),
            {(package["name"], package["versionInfo"]) for package in first},
        )

    def test_wix_reciprocal_license_is_complete_and_bound_to_exact_source(self):
        license_text = (ROOT / "res" / "msi" / "WIX-LICENSE.txt").read_text(
            encoding="utf-8"
        )
        self.assertIn("Microsoft Reciprocal License (MS-RL)", license_text)
        self.assertIn("3. Conditions and Limitations", license_text)
        self.assertEqual(
            EVIDENCE.WIX_SOURCE_COMMIT,
            "ce73352b1fa1d4f9cded10a0ee410f2e786bd326",
        )


if __name__ == "__main__":
    unittest.main()
