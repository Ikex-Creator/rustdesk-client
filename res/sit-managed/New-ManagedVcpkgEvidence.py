#!/usr/bin/env python3

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


VCPKG_COMMIT = "120deac3062162151622ca4860575a33844ba10b"
VCPKG_TRIPLET = "x64-windows-static"
# libyuv (BSD-3-Clause) and pkgconf (ISC) carry real license strings in the
# res/vcpkg overlay ports; nothing in the Windows graph is unresolved.
UNRESOLVED_VCPKG_PACKAGES = {}
BUILD_ONLY_VCPKG_PACKAGES = {
    "pkgconf",
    "vcpkg-cmake",
    "vcpkg-cmake-config",
    "vcpkg-cmake-get-vars",
    "vcpkg-msbuild",
    "vcpkg-pkgconfig-get-modules",
    "vcpkg-tool-meson",
}


def parser():
    value = argparse.ArgumentParser(
        description="Create deterministic installed-vcpkg release evidence."
    )
    value.add_argument("--vcpkg-root", required=True)
    value.add_argument("--installed-root", required=True)
    value.add_argument("--output", required=True)
    return value


def run(arguments, accepted_returncodes=(0,)):
    result = subprocess.run(
        arguments,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode not in accepted_returncodes or (
        result.returncode != 0 and result.stderr
    ):
        raise ValueError("vcpkg JSON command failed its exact exit contract")
    if len(result.stdout) < 2 or len(result.stdout) > 16777216:
        raise ValueError("vcpkg JSON output is outside its size bound")
    return json.loads(result.stdout.decode("utf-8-sig"))


def run_git(root, *arguments):
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout.decode("utf-8").strip()


def canonical_json(path, value):
    path.write_text(
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n",
        encoding="utf-8",
        newline="\n",
    )


def normalized_text(path, maximum_bytes=1048576):
    unresolved = Path(path)
    if unresolved.is_symlink():
        raise ValueError(f"vcpkg legal evidence is a symlink: {unresolved}")
    resolved = unresolved.resolve(strict=True)
    if not resolved.is_file() or not 1 <= resolved.stat().st_size <= maximum_bytes:
        raise ValueError(f"vcpkg legal evidence is outside its size bound: {resolved}")
    return resolved.read_text(encoding="utf-8-sig").replace("\r\n", "\n").replace(
        "\r", "\n"
    )


def normalized_resources(document):
    resources = []
    for package in document.get("packages", []):
        if package.get("SPDXID") in {"SPDXRef-port", "SPDXRef-binary"}:
            continue
        checksums = sorted(
            (
                {
                    "algorithm": checksum.get("algorithm"),
                    "checksumValue": checksum.get("checksumValue"),
                }
                for checksum in package.get("checksums", [])
            ),
            key=lambda item: (item["algorithm"] or "", item["checksumValue"] or ""),
        )
        resources.append(
            {
                "name": package.get("name"),
                "versionInfo": package.get("versionInfo", "NOASSERTION"),
                "downloadLocation": package.get("downloadLocation", "NOASSERTION"),
                "checksums": checksums,
            }
        )
    return sorted(
        resources,
        key=lambda item: (
            item["name"] or "",
            item["versionInfo"],
            item["downloadLocation"],
        ),
    )


def normalize_installed(installed_root, listed, installed_information):
    if not isinstance(listed, dict) or not listed:
        raise ValueError("The installed vcpkg list is empty or invalid")
    results = installed_information.get("results")
    if not isinstance(results, dict) or set(results) != set(listed):
        raise ValueError("The installed vcpkg package inventory drifted")
    if not 1 <= len(results) <= 128:
        raise ValueError("The installed vcpkg package count is outside its bound")

    records = []
    unresolved = {}
    license_errors = []
    for spec in sorted(results):
        information = results[spec]
        name, separator, triplet = spec.partition(":")
        if (
            separator != ":"
            or triplet != VCPKG_TRIPLET
            or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,127}", name)
            or information.get("triplet") != VCPKG_TRIPLET
        ):
            raise ValueError(f"Installed vcpkg package identity is invalid: {spec}")
        if name.startswith("vcpkg-") and name not in BUILD_ONLY_VCPKG_PACKAGES:
            raise ValueError(f"Unclassified vcpkg host tool is installed: {spec}")
        version = information.get("version-string")
        port_version = information.get("port-version")
        abi = information.get("abi")
        if (
            not isinstance(version, str)
            or not version
            or not isinstance(port_version, int)
            or port_version < 0
            or not isinstance(abi, str)
            or not re.fullmatch(r"[0-9a-f]{64}", abi)
        ):
            raise ValueError(f"Installed vcpkg package metadata is invalid: {spec}")
        features = information.get("features", [])
        dependencies = information.get("dependencies", [])
        if (
            not isinstance(features, list)
            or any(not isinstance(feature, str) for feature in features)
            or len(features) != len(set(features))
            or not isinstance(dependencies, list)
            or any(dependency not in results for dependency in dependencies)
        ):
            raise ValueError(f"Installed vcpkg dependency graph is invalid: {spec}")

        share_root = installed_root / triplet / "share" / name
        spdx_path = share_root / "vcpkg.spdx.json"
        document = json.loads(normalized_text(spdx_path, 16777216))
        if document.get("spdxVersion") != "SPDX-2.2":
            raise ValueError(f"Installed vcpkg SPDX schema is invalid: {spec}")
        packages = document.get("packages", [])
        ports = [item for item in packages if item.get("SPDXID") == "SPDXRef-port"]
        binaries = [
            item for item in packages if item.get("SPDXID") == "SPDXRef-binary"
        ]
        expected_version = version + (f"#{port_version}" if port_version else "")
        if (
            len(ports) != 1
            or len(binaries) != 1
            or ports[0].get("name") != name
            or ports[0].get("versionInfo") != expected_version
            or binaries[0].get("name") != spec
            or binaries[0].get("versionInfo") != abi
            or ports[0].get("licenseConcluded")
            != binaries[0].get("licenseConcluded")
        ):
            raise ValueError(f"Installed vcpkg SPDX identity is invalid: {spec}")
        license_expression = ports[0].get("licenseConcluded")
        unresolved_key = (name, version, port_version)
        if license_expression in {
            "NOASSERTION",
            "NONE",
            "LicenseRef-vcpkg-null",
        }:
            if UNRESOLVED_VCPKG_PACKAGES.get(unresolved_key) != license_expression:
                license_errors.append(
                    "vcpkg package lacks reviewed license evidence: "
                    f"{spec} {expected_version} {license_expression}"
                )
            else:
                unresolved[unresolved_key] = license_expression
        elif unresolved_key in UNRESOLVED_VCPKG_PACKAGES:
            license_errors.append(
                "The expected unresolved vcpkg license changed: "
                f"{spec} {expected_version} {license_expression!r}"
            )
        elif (
            not isinstance(license_expression, str)
            or not license_expression
            or "LicenseRef-vcpkg-null" in license_expression
        ):
            license_errors.append(
                "Installed vcpkg license expression is invalid: "
                f"{spec} {expected_version} {license_expression!r}"
            )

        copyright_text = normalized_text(share_root / "copyright")
        copyright_sha256 = hashlib.sha256(copyright_text.encode("utf-8")).hexdigest()
        records.append(
            {
                "name": name,
                "version": version,
                "port_version": port_version,
                "triplet": triplet,
                "abi": abi,
                "features": sorted(features),
                "dependencies": sorted(dependencies),
                "dependency_scope": (
                    "build" if name in BUILD_ONLY_VCPKG_PACKAGES else "runtime"
                ),
                "download_location": ports[0].get(
                    "downloadLocation", "NOASSERTION"
                ),
                "homepage": ports[0].get("homepage"),
                "license_concluded": license_expression,
                "copyright_sha256": copyright_sha256,
                "copyright_text": copyright_text,
                "resources": normalized_resources(document),
            }
        )

    if license_errors:
        raise ValueError(
            "vcpkg license evidence validation failed:\n" + "\n".join(license_errors)
        )
    if set(unresolved) != set(UNRESOLVED_VCPKG_PACKAGES):
        raise ValueError("The exact unresolved vcpkg license boundary drifted")
    return records, unresolved


def main():
    args = parser().parse_args()
    vcpkg_root = Path(args.vcpkg_root).resolve(strict=True)
    installed_root = Path(args.installed_root).resolve(strict=True)
    output = Path(args.output)
    if output.exists() or not output.parent.is_dir():
        raise ValueError("vcpkg evidence output must be one new file")
    if run_git(vcpkg_root, "rev-parse", "HEAD") != VCPKG_COMMIT:
        raise ValueError("The vcpkg source commit is not exact")
    executable = (vcpkg_root / "vcpkg.exe").resolve(strict=True)
    base_arguments = [
        str(executable),
        f"--x-install-root={installed_root}",
        "--classic",
    ]
    listed = run([str(executable), "list", "--x-json", *base_arguments[1:]])
    specs = sorted(listed)
    # x-package-info emits valid installed JSON but returns 1 at this exact
    # pinned tool commit. Accept that documented implementation behavior only
    # with empty stderr; the exact result-key comparison below still catches a
    # missing requested package.
    installed_information = run(
        [
            str(executable),
            "x-package-info",
            *specs,
            "--x-installed",
            "--x-json",
            *base_arguments[1:],
        ],
        (0, 1),
    )
    packages, unresolved = normalize_installed(
        installed_root, listed, installed_information
    )
    canonical_json(
        output,
        {
            "schema": 1,
            "vcpkg_commit": VCPKG_COMMIT,
            "triplet": VCPKG_TRIPLET,
            "packages": packages,
            "unresolved_licenses": [
                {
                    "name": key[0],
                    "version": key[1],
                    "port_version": key[2],
                    "license": unresolved[key],
                }
                for key in sorted(unresolved)
            ],
        },
    )
    print("MANAGED_VCPKG_EVIDENCE=PASS")


if __name__ == "__main__":
    main()
