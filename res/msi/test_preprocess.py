#!/usr/bin/env python3

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import preprocess


class DeterministicPreprocessTests(unittest.TestCase):
    def setUp(self):
        self.original_seed = preprocess.g_deterministic_seed
        self.original_version = preprocess.g_version
        self.original_build_date = preprocess.g_build_date

    def tearDown(self):
        preprocess.g_deterministic_seed = self.original_seed
        preprocess.g_version = self.original_version
        preprocess.g_build_date = self.original_build_date

    def test_deterministic_guid_is_stable_and_scoped(self):
        preprocess.g_deterministic_seed = "symplifiedit-rustdesk-x64-v1"
        first = preprocess.make_guid("auto-component/sciter.dll")
        self.assertEqual(first, preprocess.make_guid("auto-component/sciter.dll"))
        self.assertNotEqual(first, preprocess.make_guid("upgrade/1"))

    def test_deterministic_metadata_does_not_require_candidate_execution(self):
        args = SimpleNamespace(
            deterministic_seed="symplifiedit-rustdesk-x64-v1",
            version="1.4.9",
            revision_version=1,
            build_date="2026-09-10 12:34",
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            self.assertTrue(
                preprocess.init_global_vars(Path(temp_dir), "RustDesk", args)
            )
        self.assertEqual(preprocess.g_version, "1.4.9.1")
        self.assertEqual(preprocess.g_build_date, "2026-09-10 12:34")

    def test_deterministic_mode_requires_complete_canonical_metadata(self):
        cases = (
            ("bad seed", "1.4.9", "2026-09-10 12:34"),
            ("symplifiedit-rustdesk-x64-v1", "", "2026-09-10 12:34"),
            ("symplifiedit-rustdesk-x64-v1", "1.4.9", ""),
        )
        for seed, version, build_date in cases:
            with self.subTest(seed=seed, version=version, build_date=build_date):
                args = SimpleNamespace(
                    deterministic_seed=seed,
                    version=version,
                    revision_version=1,
                    build_date=build_date,
                )
                with tempfile.TemporaryDirectory() as temp_dir:
                    with self.assertRaises(ValueError):
                        preprocess.init_global_vars(Path(temp_dir), "RustDesk", args)

    def test_auto_components_are_sorted_and_repeatable(self):
        preprocess.g_deterministic_seed = "symplifiedit-rustdesk-x64-v1"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "z").mkdir()
            (root / "z" / "second.dll").write_bytes(b"second")
            (root / "first.dll").write_bytes(b"first")
            (root / "RustDesk.exe").write_bytes(b"main")

            first = ["start\n", "end\n"]
            second = ["start\n", "end\n"]
            preprocess.insert_components_between_tags(first, 0, "RustDesk", root)
            preprocess.insert_components_between_tags(second, 0, "RustDesk", root)

        self.assertEqual(first, second)
        generated = "".join(first)
        self.assertLess(generated.index("first.dll"), generated.index("second.dll"))
        self.assertNotIn("RustDesk.exe", generated)
        self.assertNotIn(str(root), generated)
        self.assertIn('Source="$(var.BuildDir)/first.dll"', generated)


if __name__ == "__main__":
    unittest.main()
