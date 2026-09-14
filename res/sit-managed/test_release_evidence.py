import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = Path(__file__).with_name("New-ManagedReleaseEvidence.py")
SPEC = importlib.util.spec_from_file_location("managed_release_evidence", SCRIPT)
EVIDENCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EVIDENCE)
VCPKG_SCRIPT = Path(__file__).with_name("New-ManagedVcpkgEvidence.py")
VCPKG_SPEC = importlib.util.spec_from_file_location(
    "managed_vcpkg_evidence", VCPKG_SCRIPT
)
VCPKG_EVIDENCE = importlib.util.module_from_spec(VCPKG_SPEC)
VCPKG_SPEC.loader.exec_module(VCPKG_EVIDENCE)


class ManagedReleaseEvidenceTests(unittest.TestCase):
    @mock.patch.object(VCPKG_EVIDENCE.subprocess, "run")
    def test_vcpkg_package_info_accepts_only_its_exact_json_exit_contract(
        self, mocked_run
    ):
        mocked_run.return_value = mock.Mock(
            returncode=1,
            stdout=b'{"results":{}}\n',
            stderr=b"",
        )
        self.assertEqual(
            VCPKG_EVIDENCE.run(["vcpkg", "x-package-info"], (0, 1)),
            {"results": {}},
        )
        mocked_run.return_value.stderr = b"unexpected error"
        with self.assertRaisesRegex(ValueError, "exact exit contract"):
            VCPKG_EVIDENCE.run(["vcpkg", "x-package-info"], (0, 1))

    def write_vcpkg_package(
        self,
        installed_root,
        name,
        version,
        port_version,
        license_expression,
        abi_character,
    ):
        spec = f"{name}:{VCPKG_EVIDENCE.VCPKG_TRIPLET}"
        share = (
            Path(installed_root)
            / VCPKG_EVIDENCE.VCPKG_TRIPLET
            / "share"
            / name
        )
        share.mkdir(parents=True)
        abi = abi_character * 64
        version_info = version + (f"#{port_version}" if port_version else "")
        document = {
            "spdxVersion": "SPDX-2.2",
            "packages": [
                {
                    "SPDXID": "SPDXRef-port",
                    "name": name,
                    "versionInfo": version_info,
                    "downloadLocation": f"git+https://example.test/{name}@tree",
                    "homepage": f"https://example.test/{name}",
                    "licenseConcluded": license_expression,
                },
                {
                    "SPDXID": "SPDXRef-binary",
                    "name": spec,
                    "versionInfo": abi,
                    "licenseConcluded": license_expression,
                },
                {
                    "SPDXID": "SPDXRef-resource-0",
                    "name": f"{name}-source",
                    "downloadLocation": f"https://example.test/{name}.tar.gz",
                    "checksums": [
                        {"algorithm": "SHA256", "checksumValue": "d" * 64}
                    ],
                },
            ],
        }
        (share / "vcpkg.spdx.json").write_text(
            json.dumps(document), encoding="utf-8"
        )
        (share / "copyright").write_text(
            f"Copyright and license for {name}\n", encoding="utf-8"
        )
        return spec, {
            "version-string": version,
            "port-version": port_version,
            "triplet": VCPKG_EVIDENCE.VCPKG_TRIPLET,
            "abi": abi,
            "features": [],
        }

    def write_metadata(self, directory, extra_packages=None, extra_dependencies=None):
        packages = [
            {
                "id": "root",
                "name": "rustdesk",
                "version": "1.4.9",
                "source": None,
                "manifest_path": str(ROOT / "Cargo.toml"),
                "license": None,
                "license_file": None,
            },
            {
                "id": "default-net",
                "name": "default_net",
                "version": "0.1.0",
                "source": (
                    "git+https://github.com/rustdesk-org/default_net"
                    "#78f8f70cd85151a3a2c4a3230d80d5272703c02e"
                ),
                "manifest_path": "/cargo/git/default_net/Cargo.toml",
                "license": None,
                "license_file": None,
            },
            {
                "id": "hbb",
                "name": "hbb_common",
                "version": "0.1.0",
                "source": None,
                "manifest_path": str(ROOT / "libs" / "hbb_common" / "Cargo.toml"),
                "license": None,
                "license_file": None,
            },
            {
                "id": "hwcodec",
                "name": "hwcodec",
                "version": "0.7.1",
                "source": (
                    "git+https://github.com/rustdesk-org/hwcodec"
                    "#778df1f99597722473b29443bac22ae6c23946fe"
                ),
                "manifest_path": "/cargo/git/hwcodec/Cargo.toml",
                "license": None,
                "license_file": None,
            },
            {
                "id": "impersonate",
                "name": "impersonate_system",
                "version": "0.1.0",
                "source": (
                    "git+https://github.com/rustdesk-org/impersonate-system"
                    "#2f429010a5a10b1fe5eceb553c6672fd53d20167"
                ),
                "manifest_path": "/cargo/git/impersonate-system/Cargo.toml",
                "license": None,
                "license_file": None,
            },
            {
                "id": "anyhow",
                "name": "anyhow",
                "version": "1.0.98",
                "source": "registry+https://github.com/rust-lang/crates.io-index",
                "manifest_path": "/cargo/registry/anyhow/Cargo.toml",
                "license": "MIT OR Apache-2.0",
                "license_file": None,
            },
        ]
        packages.extend(extra_packages or [])
        dependencies = [
            {"pkg": "default-net", "dep_kinds": [{"kind": None}]},
            {"pkg": "hbb", "dep_kinds": [{"kind": None}]},
            {"pkg": "hwcodec", "dep_kinds": [{"kind": None}]},
            {"pkg": "impersonate", "dep_kinds": [{"kind": None}]},
            {"pkg": "anyhow", "dep_kinds": [{"kind": None}]},
        ]
        dependencies.extend(extra_dependencies or [])
        nodes = [
            {
                "id": "root",
                "features": list(EVIDENCE.CARGO_FEATURES),
                "deps": dependencies,
            }
        ]
        nodes.extend(
            {"id": package["id"], "features": [], "deps": []}
            for package in packages
            if package["id"] != "root"
        )
        metadata = {
            "version": 1,
            "packages": packages,
            "resolve": {"root": "root", "nodes": nodes},
        }
        output = Path(directory) / "cargo-metadata.json"
        output.write_text(json.dumps(metadata), encoding="utf-8")
        return output

    def test_canonical_json_is_sorted_utf8_with_one_newline(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "evidence.json"
            EVIDENCE.canonical_json(output, {"z": "café", "a": 1})
            self.assertEqual(output.read_bytes(), b'{"a":1,"z":"caf\\u00e9"}\n')
            self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["z"], "café")

    def test_exact_windows_graph_has_reviewed_licenses_and_relationships(self):
        with tempfile.TemporaryDirectory() as directory:
            metadata = self.write_metadata(directory)
            packages, relationships, extracted, unresolved, root = (
                EVIDENCE.cargo_evidence(
                    ROOT,
                    metadata,
                    "f32424baa60a0d31e75b0aee6582efc9ddf88d0b",
                )
            )
        self.assertEqual(len(packages), 6)
        identifiers = [package["SPDXID"] for package in packages]
        self.assertEqual(len(identifiers), len(set(identifiers)))
        by_name = {package["name"]: package for package in packages}
        self.assertEqual(root, by_name["rustdesk"])
        self.assertEqual(by_name["rustdesk"]["licenseDeclared"], "AGPL-3.0-only")
        self.assertEqual(by_name["anyhow"]["licenseDeclared"], "MIT OR Apache-2.0")
        self.assertEqual(by_name["anyhow"]["licenseConcluded"], "MIT OR Apache-2.0")
        self.assertEqual(by_name["default_net"]["licenseDeclared"], "NOASSERTION")
        self.assertEqual(by_name["hbb_common"]["licenseDeclared"], "NOASSERTION")
        self.assertEqual(set(unresolved), set(EVIDENCE.UNRESOLVED_CARGO_PACKAGES))
        self.assertEqual(extracted, [])
        self.assertEqual(len(relationships), 5)

    def test_unexpected_missing_license_fails_closed(self):
        package = {
            "id": "unlicensed",
            "name": "serde",
            "version": "0.9.15",
            "source": "registry+https://github.com/rust-lang/crates.io-index",
            "manifest_path": "/cargo/registry/serde/Cargo.toml",
            "license": None,
            "license_file": None,
        }
        dependency = {"pkg": "unlicensed", "dep_kinds": [{"kind": None}]}
        with tempfile.TemporaryDirectory() as directory:
            metadata = self.write_metadata(directory, [package], [dependency])
            with self.assertRaisesRegex(ValueError, "lacks reviewed license evidence"):
                EVIDENCE.cargo_evidence(
                    ROOT,
                    metadata,
                    "f32424baa60a0d31e75b0aee6582efc9ddf88d0b",
                )

    def test_exact_legacy_cargo_license_is_normalized_to_spdx_or(self):
        for raw, expected in EVIDENCE.CARGO_LICENSE_NORMALIZATIONS.items():
            with self.subTest(raw=raw):
                package = {"name": "legacy", "license": raw}
                self.assertEqual(
                    EVIDENCE.cargo_license(package, "registry+test", {}),
                    expected,
                )

    def test_cargo_license_preflight_reports_every_invalid_expression(self):
        packages = [
            {
                "id": "invalid-one",
                "name": "invalid-one",
                "version": "1.0.0",
                "source": "registry+https://github.com/rust-lang/crates.io-index",
                "manifest_path": "/cargo/registry/invalid-one/Cargo.toml",
                "license": "MIT/unknown",
                "license_file": None,
            },
            {
                "id": "invalid-two",
                "name": "invalid-two",
                "version": "1.0.0",
                "source": "registry+https://github.com/rust-lang/crates.io-index",
                "manifest_path": "/cargo/registry/invalid-two/Cargo.toml",
                "license": "MIT@unknown",
                "license_file": None,
            },
        ]
        dependencies = [
            {"pkg": package["id"], "dep_kinds": [{"kind": None}]}
            for package in packages
        ]
        with tempfile.TemporaryDirectory() as directory:
            metadata = self.write_metadata(directory, packages, dependencies)
            with self.assertRaisesRegex(ValueError, "Cargo license evidence validation") as raised:
                EVIDENCE.cargo_evidence(
                    ROOT,
                    metadata,
                    "f32424baa60a0d31e75b0aee6582efc9ddf88d0b",
                )
        self.assertIn("invalid-one", str(raised.exception))
        self.assertIn("invalid-two", str(raised.exception))

    def test_vcpkg_inventory_preserves_only_exact_unresolved_licenses(self):
        with tempfile.TemporaryDirectory() as directory:
            installed = Path(directory) / "installed"
            listed = {}
            information = {}
            for item in (
                ("ffmpeg", "7.1", 1, "LicenseRef-vcpkg-null", "a"),
                ("ffnvcodec", "12.1.14.0", 0, "NOASSERTION", "b"),
                ("libyuv", "1857", 0, "LicenseRef-vcpkg-null", "c"),
                ("aom", "3.12.1", 0, "BSD-2-Clause", "d"),
            ):
                spec, package = self.write_vcpkg_package(installed, *item)
                listed[spec] = {}
                information[spec] = package
            records, unresolved = VCPKG_EVIDENCE.normalize_installed(
                installed, listed, {"results": information}
            )
            native_path = Path(directory) / "native-dependencies.json"
            native_path.write_text(
                json.dumps(
                    {
                        "schema": 1,
                        "vcpkg_commit": EVIDENCE.VCPKG_COMMIT,
                        "triplet": EVIDENCE.VCPKG_TRIPLET,
                        "packages": records,
                        "unresolved_licenses": [
                            {
                                "name": key[0],
                                "version": key[1],
                                "port_version": key[2],
                                "license": unresolved[key],
                            }
                            for key in sorted(unresolved)
                        ],
                    }
                ),
                encoding="utf-8",
            )
            spdx_packages, relationships, notices = EVIDENCE.native_evidence(
                native_path, {"SPDXID": "SPDXRef-root"}
            )
        self.assertEqual(len(records), 4)
        self.assertEqual(
            set(unresolved), set(VCPKG_EVIDENCE.UNRESOLVED_VCPKG_PACKAGES)
        )
        aom = next(record for record in records if record["name"] == "aom")
        self.assertEqual(aom["license_concluded"], "BSD-2-Clause")
        self.assertEqual(len(aom["resources"]), 1)
        self.assertEqual(len(spdx_packages), 4)
        self.assertGreaterEqual(len(relationships), 4)
        self.assertEqual(len(notices), 4)
        self.assertEqual(
            next(item for item in spdx_packages if item["name"] == "ffmpeg")[
                "licenseDeclared"
            ],
            "NOASSERTION",
        )

    def test_unexpected_vcpkg_missing_license_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            installed = Path(directory) / "installed"
            listed = {}
            information = {}
            for item in (
                ("ffmpeg", "7.1", 1, "LicenseRef-vcpkg-null", "a"),
                ("ffnvcodec", "12.1.14.0", 0, "NOASSERTION", "b"),
                ("libyuv", "1857", 0, "LicenseRef-vcpkg-null", "c"),
                ("aom", "3.12.1", 0, "NOASSERTION", "d"),
                ("pkgconf", "2.5.1", 0, "NONE", "e"),
            ):
                spec, package = self.write_vcpkg_package(installed, *item)
                listed[spec] = {}
                information[spec] = package
            with self.assertRaisesRegex(
                ValueError, "vcpkg license evidence validation failed"
            ) as raised:
                VCPKG_EVIDENCE.normalize_installed(
                    installed, listed, {"results": information}
                )
        self.assertIn("aom:x64-windows-static", str(raised.exception))
        self.assertIn("pkgconf:x64-windows-static", str(raised.exception))

    @unittest.skipUnless(
        os.environ.get("SIT_REQUIRE_CARGO_METADATA") == "1",
        "exact Cargo metadata integration is required only in protected CI",
    )
    def test_repository_windows_graph_has_only_exact_unresolved_licenses(self):
        with tempfile.TemporaryDirectory() as directory:
            metadata = Path(directory) / "cargo-metadata.json"
            with metadata.open("wb") as output:
                subprocess.run(
                    [
                        "cargo",
                        "metadata",
                        "--locked",
                        "--format-version",
                        "1",
                        "--filter-platform",
                        EVIDENCE.CARGO_TARGET,
                        "--features",
                        ",".join(EVIDENCE.CARGO_FEATURES),
                    ],
                    cwd=ROOT,
                    check=True,
                    stdout=output,
                )
            packages, _, _, unresolved, _ = EVIDENCE.cargo_evidence(
                ROOT,
                metadata,
                "f32424baa60a0d31e75b0aee6582efc9ddf88d0b",
            )
        self.assertGreater(len(packages), 100)
        self.assertEqual(set(unresolved), set(EVIDENCE.UNRESOLVED_CARGO_PACKAGES))

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

    def test_hbb_common_absent_license_is_explicitly_noassertion(self):
        hbb_root = ROOT / "libs" / "hbb_common"
        self.assertEqual(EVIDENCE.hbb_common_legal_files(hbb_root), [])
        self.assertIn(
            ("hbb_common", "0.1.0", "path:libs/hbb_common"),
            EVIDENCE.UNRESOLVED_CARGO_PACKAGES,
        )


if __name__ == "__main__":
    unittest.main()
