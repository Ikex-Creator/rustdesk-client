#!/usr/bin/env python3

import argparse
import datetime
import hashlib
import html
import json
import re
import subprocess
import tomllib
from pathlib import Path
from urllib.parse import quote


UPSTREAM_COMMIT = "6c578292e8ebbbec708b76986ba8c4bc7c509747"
SCITER_COMMIT = "f33df075d9eb2f8d252cb88f1b2c8096e56197ed"
SCITER_SHA256 = "4d97528e157c55ef1fabe9e37a9697116ab66660d7da6163f90a3a7abf80dd56"
SUBSCRIBER_EKU = "1.3.6.1.4.1.311.97.162372899.954041822.66046227.837397283"
WIX_SOURCE_COMMIT = "ce73352b1fa1d4f9cded10a0ee410f2e786bd326"
HBB_COMMON_REPOSITORY = "https://github.com/Ikex-Creator/hbb_common"
CARGO_TARGET = "x86_64-pc-windows-msvc"
CARGO_FEATURES = ("inline", "vram", "hwcodec")
CARGO_LICENSE_NORMALIZATIONS = {
    "Apache-2.0/MIT": "Apache-2.0 OR MIT",
    "MIT/Apache-2.0": "MIT OR Apache-2.0",
}
VCPKG_COMMIT = "120deac3062162151622ca4860575a33844ba10b"
VCPKG_TRIPLET = "x64-windows-static"
UNRESOLVED_VCPKG_PACKAGES = {
    ("ffmpeg", "7.1", 1, "LicenseRef-vcpkg-null"),
    ("ffnvcodec", "12.1.14.0", 0, "NOASSERTION"),
    ("libyuv", "1857", 0, "LicenseRef-vcpkg-null"),
}
UNRESOLVED_CARGO_PACKAGES = {
    (
        "hbb_common",
        "0.1.0",
        "path:libs/hbb_common",
    ): HBB_COMMON_REPOSITORY + "/tree/{hbb_common_commit}",
    (
        "hwcodec",
        "0.7.1",
        "git+https://github.com/rustdesk-org/hwcodec"
        "#778df1f99597722473b29443bac22ae6c23946fe",
    ): (
        "https://github.com/rustdesk-org/hwcodec/tree/"
        "778df1f99597722473b29443bac22ae6c23946fe"
    ),
    (
        "impersonate_system",
        "0.1.0",
        "git+https://github.com/rustdesk-org/impersonate-system"
        "#2f429010a5a10b1fe5eceb553c6672fd53d20167",
    ): (
        "https://github.com/rustdesk-org/impersonate-system/tree/"
        "2f429010a5a10b1fe5eceb553c6672fd53d20167"
    ),
}


def parser():
    value = argparse.ArgumentParser(description="Create deterministic release evidence.")
    value.add_argument("--repository-root", required=True)
    value.add_argument("--source-commit", required=True)
    value.add_argument("--hbb-common-commit", required=True)
    value.add_argument("--generation", required=True)
    value.add_argument("--source-date-epoch", required=True)
    value.add_argument("--run-url", required=True)
    value.add_argument("--candidate-verification", required=True)
    value.add_argument("--builder-information", required=True)
    value.add_argument("--native-dependencies", required=True)
    value.add_argument("--source-archive", required=True)
    value.add_argument("--sciter-license", required=True)
    value.add_argument("--cargo-metadata", required=True)
    value.add_argument("--output-root", required=True)
    return value


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def file_record(path):
    return {
        "bytes": path.stat().st_size,
        "sha256": sha256(path),
    }


def run_git(root, *arguments):
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout


def canonical_json(path, value):
    path.write_text(
        json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        + "\n",
        encoding="utf-8",
        newline="\n",
    )


def spdx_id(name, version, source):
    identity = f"{name}\0{version}\0{source}".encode("utf-8")
    return "SPDXRef-Package-" + hashlib.sha256(identity).hexdigest()[:24]


def cargo_lock_packages(root):
    lock_path = root / "Cargo.lock"
    document = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    packages = {}
    for package in document.get("package", []):
        key = (
            package["name"],
            package["version"],
            package.get("source"),
        )
        if key in packages:
            raise ValueError(f"Cargo.lock contains a duplicate package: {key}")
        packages[key] = package
    if not packages:
        raise ValueError("The root Cargo.lock has no packages")
    return packages


def normalized_cargo_source(root, package):
    source = package.get("source")
    if source:
        return source
    manifest = Path(package["manifest_path"]).resolve(strict=True)
    try:
        relative = manifest.parent.relative_to(root)
    except ValueError as error:
        raise ValueError("A path Cargo package is outside the exact source tree") from error
    return "path:" + (relative.as_posix() if relative.parts else ".")


def cargo_download_location(name, version, source):
    if source in {
        "registry+https://github.com/rust-lang/crates.io-index",
        "registry+https://index.crates.io/",
    }:
        return f"https://crates.io/crates/{quote(name, safe='')}/{version}/download"
    if source.startswith("git+https://"):
        return source
    return "NOASSERTION"


def cargo_license(package, source, extracted):
    declared = package.get("license")
    if declared:
        declared = declared.strip()
        declared = CARGO_LICENSE_NORMALIZATIONS.get(declared, declared)
        if (
            len(declared) > 512
            or "\n" in declared
            or "\r" in declared
            or not re.fullmatch(r"[A-Za-z0-9.+()\- ]+", declared)
        ):
            raise ValueError(
                f"Cargo package {package['name']} has a non-canonical license expression"
            )
        return declared

    license_file = package.get("license_file")
    if license_file:
        unresolved_path = Path(license_file)
        if unresolved_path.is_symlink():
            raise ValueError(f"Cargo package {package['name']} license file is a symlink")
        path = unresolved_path.resolve(strict=True)
        if (
            not path.is_file()
            or path.stat().st_size < 1
            or path.stat().st_size > 1048576
        ):
            raise ValueError(f"Cargo package {package['name']} has an invalid license file")
        raw = path.read_bytes()
        try:
            license_text = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError(
                f"Cargo package {package['name']} license file is not UTF-8"
            ) from error
        digest = hashlib.sha256(raw).hexdigest()
        identifier = "LicenseRef-CargoFile-" + digest[:24]
        extracted[identifier] = {
            "licenseId": identifier,
            "extractedText": license_text,
            "name": f"Cargo package license file SHA-256 {digest}",
        }
        return identifier

    if source.startswith("path:") and source != "path:libs/hbb_common":
        return "AGPL-3.0-only"
    return None


def cargo_evidence(root, metadata_path, hbb_common_commit):
    if metadata_path.stat().st_size < 1 or metadata_path.stat().st_size > 67108864:
        raise ValueError("Cargo metadata is outside its size bound")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if metadata.get("version") != 1:
        raise ValueError("Cargo metadata schema is not exact")
    resolve = metadata.get("resolve") or {}
    root_id = resolve.get("root")
    package_by_id = {package["id"]: package for package in metadata.get("packages", [])}
    node_by_id = {node["id"]: node for node in resolve.get("nodes", [])}
    if (
        not root_id
        or len(package_by_id) != len(metadata.get("packages", []))
        or len(node_by_id) != len(resolve.get("nodes", []))
        or root_id not in package_by_id
        or root_id not in node_by_id
    ):
        raise ValueError("Cargo metadata package graph is incomplete")
    root_package = package_by_id[root_id]
    if root_package.get("name") != "rustdesk" or root_package.get("version") != "1.4.9":
        raise ValueError("Cargo metadata root package identity drifted")
    root_features = set(node_by_id[root_id].get("features", []))
    if not set(CARGO_FEATURES).issubset(root_features):
        raise ValueError("Cargo metadata lost an exact managed build feature")

    reachable = {root_id}
    pending = [root_id]
    edges = set()
    while pending:
        parent_id = pending.pop()
        for dependency in node_by_id[parent_id].get("deps", []):
            kinds = dependency.get("dep_kinds") or [{}]
            non_dev = [kind for kind in kinds if kind.get("kind") != "dev"]
            if not non_dev:
                continue
            dependency_id = dependency["pkg"]
            if dependency_id not in package_by_id or dependency_id not in node_by_id:
                raise ValueError("Cargo metadata dependency graph is incomplete")
            relationship = (
                "BUILD_DEPENDENCY_OF"
                if all(kind.get("kind") == "build" for kind in non_dev)
                else "DEPENDS_ON"
            )
            edges.add((parent_id, dependency_id, relationship))
            if dependency_id not in reachable:
                reachable.add(dependency_id)
                pending.append(dependency_id)

    locked = cargo_lock_packages(root)
    extracted = {}
    unresolved = {}
    records_by_id = {}
    for package_id in sorted(reachable):
        package = package_by_id[package_id]
        source = normalized_cargo_source(root, package)
        lock_source = package.get("source")
        lock_key = (package["name"], package["version"], lock_source)
        locked_package = locked.get(lock_key)
        if locked_package is None:
            raise ValueError(f"Cargo metadata package is not locked: {lock_key}")
        unresolved_key = (package["name"], package["version"], source)
        unresolved_location = UNRESOLVED_CARGO_PACKAGES.get(unresolved_key)
        if unresolved_location:
            license_expression = "NOASSERTION"
            unresolved[unresolved_key] = unresolved_location.format(
                hbb_common_commit=hbb_common_commit
            )
        else:
            license_expression = cargo_license(package, source, extracted)
            if not license_expression:
                raise ValueError(
                    "Cargo package lacks reviewed license evidence: "
                    + " ".join(unresolved_key)
                )
        identifier = spdx_id(package["name"], package["version"], source)
        checksum = locked_package.get("checksum", "")
        record = {
            "SPDXID": identifier,
            "name": package["name"],
            "versionInfo": package["version"],
            "downloadLocation": (
                unresolved[unresolved_key]
                if unresolved_location
                else cargo_download_location(
                    package["name"], package["version"], source
                )
            ),
            "filesAnalyzed": False,
            "licenseConcluded": license_expression,
            "licenseDeclared": license_expression,
            "copyrightText": "NOASSERTION",
            "checksums": (
                [{"algorithm": "SHA256", "checksumValue": checksum}]
                if re.fullmatch(r"[0-9a-f]{64}", checksum)
                else []
            ),
        }
        raw_declared = package.get("license")
        if raw_declared and raw_declared.strip() != license_expression:
            record["licenseComments"] = (
                f"Cargo declared {raw_declared.strip()!r}; normalized by the exact "
                f"reviewed mapping to {license_expression!r}."
            )
        if source.startswith("registry+"):
            record["externalRefs"] = [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": (
                        f"pkg:cargo/{quote(package['name'], safe='')}@{package['version']}"
                    ),
                }
            ]
        records_by_id[package_id] = record

    if set(unresolved) != set(UNRESOLVED_CARGO_PACKAGES):
        raise ValueError("The exact unresolved Cargo license boundary drifted")

    relationships = []
    for parent_id, dependency_id, relationship in sorted(edges):
        parent_spdx = records_by_id[parent_id]["SPDXID"]
        dependency_spdx = records_by_id[dependency_id]["SPDXID"]
        if relationship == "BUILD_DEPENDENCY_OF":
            relationships.append(
                {
                    "spdxElementId": dependency_spdx,
                    "relationshipType": relationship,
                    "relatedSpdxElement": parent_spdx,
                }
            )
        else:
            relationships.append(
                {
                    "spdxElementId": parent_spdx,
                    "relationshipType": relationship,
                    "relatedSpdxElement": dependency_spdx,
                }
            )
    packages = sorted(
        records_by_id.values(),
        key=lambda package: (
            package["name"],
            package["versionInfo"],
            package["SPDXID"],
        ),
    )
    relationships.sort(
        key=lambda item: (
            item["spdxElementId"],
            item["relationshipType"],
            item["relatedSpdxElement"],
        )
    )
    extracted_licenses = [extracted[key] for key in sorted(extracted)]
    return (
        packages,
        relationships,
        extracted_licenses,
        unresolved,
        records_by_id[root_id],
    )


def native_evidence(path, root_package):
    if path.stat().st_size < 1 or path.stat().st_size > 67108864:
        raise ValueError("Native dependency evidence is outside its size bound")
    document = json.loads(path.read_text(encoding="utf-8"))
    if (
        document.get("schema") != 1
        or document.get("vcpkg_commit") != VCPKG_COMMIT
        or document.get("triplet") != VCPKG_TRIPLET
    ):
        raise ValueError("Native dependency evidence identity drifted")
    unresolved = {
        (
            item.get("name"),
            item.get("version"),
            item.get("port_version"),
            item.get("license"),
        )
        for item in document.get("unresolved_licenses", [])
    }
    if unresolved != UNRESOLVED_VCPKG_PACKAGES:
        raise ValueError("The exact unresolved native license boundary drifted")
    packages = document.get("packages")
    if not isinstance(packages, list) or not 1 <= len(packages) <= 128:
        raise ValueError("Native dependency package inventory is invalid")

    records = []
    records_by_spec = {}
    relationships = []
    notices = []
    for package in packages:
        name = package.get("name")
        version = package.get("version")
        port_version = package.get("port_version")
        triplet = package.get("triplet")
        abi = package.get("abi")
        dependencies = package.get("dependencies")
        copyright_text = package.get("copyright_text")
        if (
            not isinstance(name, str)
            or not isinstance(version, str)
            or not isinstance(port_version, int)
            or triplet != VCPKG_TRIPLET
            or not isinstance(abi, str)
            or not re.fullmatch(r"[0-9a-f]{64}", abi)
            or not isinstance(dependencies, list)
            or not isinstance(copyright_text, str)
            or not copyright_text
        ):
            raise ValueError("Native dependency package record is invalid")
        spec = f"{name}:{triplet}"
        if spec in records_by_spec:
            raise ValueError(f"Native dependency package is duplicated: {spec}")
        version_info = version + (f"#{port_version}" if port_version else "")
        raw_license = package.get("license_concluded")
        license_expression = (
            "NOASSERTION"
            if (name, version, port_version, raw_license)
            in UNRESOLVED_VCPKG_PACKAGES
            else raw_license
        )
        if not isinstance(license_expression, str) or not license_expression:
            raise ValueError(f"Native dependency license is invalid: {spec}")
        identifier = spdx_id(name, version_info, f"vcpkg:{triplet}:{abi}")
        record = {
            "SPDXID": identifier,
            "name": name,
            "versionInfo": version_info,
            "downloadLocation": package.get("download_location", "NOASSERTION"),
            "filesAnalyzed": False,
            "licenseConcluded": license_expression,
            "licenseDeclared": license_expression,
            "copyrightText": "NOASSERTION",
            "attributionTexts": [copyright_text],
            "comment": (
                f"Static native dependency built by vcpkg {VCPKG_COMMIT}; "
                f"triplet {triplet}; ABI {abi}."
            ),
        }
        records.append(record)
        records_by_spec[spec] = (record, dependencies)
        notices.append(
            {
                "name": name,
                "version": version_info,
                "license": license_expression,
                "raw_license": raw_license,
                "download_location": package.get(
                    "download_location", "NOASSERTION"
                ),
                "copyright_text": copyright_text,
            }
        )

    if set(records_by_spec) != {
        f"{package['name']}:{VCPKG_TRIPLET}" for package in packages
    }:
        raise ValueError("Native dependency package specifications drifted")
    for spec, (record, dependencies) in sorted(records_by_spec.items()):
        relationships.append(
            {
                "spdxElementId": root_package["SPDXID"],
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": record["SPDXID"],
            }
        )
        for dependency in sorted(dependencies):
            if dependency not in records_by_spec:
                raise ValueError(f"Native dependency edge is not closed: {spec}")
            relationships.append(
                {
                    "spdxElementId": record["SPDXID"],
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": records_by_spec[dependency][0]["SPDXID"],
                }
            )
    relationships.sort(
        key=lambda item: (
            item["spdxElementId"],
            item["relationshipType"],
            item["relatedSpdxElement"],
        )
    )
    return (
        sorted(records, key=lambda item: (item["name"], item["versionInfo"])),
        relationships,
        notices,
    )


def hbb_common_legal_files(root):
    entries = run_git(root, "ls-tree", "-r", "--name-only", "HEAD").decode(
        "utf-8"
    ).splitlines()
    return sorted(
        entry
        for entry in entries
        if re.fullmatch(
            r"(?:licen[cs]e|copying|notice)(?:[-_.].+)?",
            Path(entry).name,
            flags=re.IGNORECASE,
        )
    )


def main():
    args = parser().parse_args()
    root = Path(args.repository_root).resolve(strict=True)
    output = Path(args.output_root)
    if output.exists() or not output.parent.is_dir():
        raise ValueError("Evidence output root must be one new directory")
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_commit):
        raise ValueError("Invalid source commit")
    if not re.fullmatch(r"[0-9a-f]{40}", args.hbb_common_commit):
        raise ValueError("Invalid hbb_common commit")
    if not re.fullmatch(r"[0-9a-f]{32}", args.generation):
        raise ValueError("Invalid generation")
    if not re.fullmatch(r"[1-9][0-9]{0,11}", args.source_date_epoch):
        raise ValueError("Invalid source epoch")
    epoch = int(args.source_date_epoch)
    created = datetime.datetime.fromtimestamp(
        epoch, datetime.timezone.utc
    ).replace(microsecond=0)
    if run_git(root, "rev-parse", "HEAD").decode().strip() != args.source_commit:
        raise ValueError("Evidence checkout is not the exact source commit")
    if run_git(root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ValueError("Evidence checkout is not clean")
    submodule_lines = run_git(root, "submodule", "status", "--recursive").decode(
        "utf-8"
    ).splitlines()
    if len(submodule_lines) != 1 or not submodule_lines[0].startswith(
        f" {args.hbb_common_commit} libs/hbb_common "
    ):
        raise ValueError("Evidence submodule identity is not exact")
    hbb_root = root / "libs" / "hbb_common"
    hbb_legal = hbb_common_legal_files(hbb_root)
    if hbb_legal:
        raise ValueError(
            "hbb_common legal files changed and require explicit evidence review: "
            + ", ".join(hbb_legal)
        )

    candidate_path = Path(args.candidate_verification).resolve(strict=True)
    builder_path = Path(args.builder_information).resolve(strict=True)
    native_path = Path(args.native_dependencies).resolve(strict=True)
    source_archive = Path(args.source_archive).resolve(strict=True)
    sciter_license = Path(args.sciter_license).resolve(strict=True)
    cargo_metadata = Path(args.cargo_metadata).resolve(strict=True)
    if (
        sciter_license.stat().st_size != 2701
        or sha256(sciter_license)
        != "a52733cc90fb112a730b67bbbe6fc1102fad644753af9bd584cab8ba0da3db49"
    ):
        raise ValueError("Pinned Sciter license is not exact")
    candidate = json.loads(candidate_path.read_text(encoding="utf-8-sig"))
    builder = json.loads(builder_path.read_text(encoding="utf-8-sig"))
    if (
        candidate.get("source_commit") != args.source_commit
        or candidate.get("hbb_common_commit") != args.hbb_common_commit
        or candidate.get("generation") != args.generation
        or candidate.get("upstream_commit") != UPSTREAM_COMMIT
        or candidate.get("subscriber_eku") != SUBSCRIBER_EKU
        or builder.get("source_commit") != args.source_commit
        or builder.get("hbb_common_commit") != args.hbb_common_commit
    ):
        raise ValueError("Candidate or builder evidence identity drifted")

    wix_license_path = root / "res" / "msi" / "WIX-LICENSE.txt"
    wix_license = wix_license_path.read_text(encoding="utf-8")
    sciter_text = html.unescape(sciter_license.read_text(encoding="utf-8"))

    output.mkdir()
    (
        packages,
        relationships,
        cargo_licenses,
        unresolved_cargo,
        root_package,
    ) = cargo_evidence(root, cargo_metadata, args.hbb_common_commit)
    native_packages, native_relationships, native_notices = native_evidence(
        native_path, root_package
    )
    packages.extend(native_packages)
    packages.extend(
        [
            {
                "SPDXID": "SPDXRef-Package-SciterEngine",
                "name": "Sciter Engine",
                "versionInfo": SCITER_COMMIT,
                "downloadLocation": (
                    "https://github.com/c-smile/sciter-sdk/tree/" + SCITER_COMMIT
                ),
                "filesAnalyzed": False,
                "licenseConcluded": "LicenseRef-Sciter-EULA",
                "licenseDeclared": "LicenseRef-Sciter-EULA",
                "copyrightText": "Copyright Terra Informatica Software, Inc.",
                "checksums": [
                    {"algorithm": "SHA256", "checksumValue": SCITER_SHA256}
                ],
            },
            {
                "SPDXID": "SPDXRef-Package-WiXToolset",
                "name": "WiX Toolset and derived UI source",
                "versionInfo": "4.0.5",
                "downloadLocation": (
                    "https://github.com/wixtoolset/wix/tree/" + WIX_SOURCE_COMMIT
                ),
                "filesAnalyzed": False,
                "licenseConcluded": "MS-RL",
                "licenseDeclared": "MS-RL",
                "copyrightText": "Copyright (c) .NET Foundation and contributors.",
            },
        ]
    )
    spdx = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "SymplifiedIT managed RustDesk 1.4.9.1",
        "documentNamespace": (
            "https://github.com/Ikex-Creator/rustdesk-client/releases/"
            f"sit-rustdesk-1.4.9.1/spdx/{args.source_commit}"
        ),
        "creationInfo": {
            "created": created.isoformat().replace("+00:00", "Z"),
            "creators": ["Tool: SymplifiedIT-New-ManagedReleaseEvidence-2"],
        },
        "packages": packages,
        "documentDescribes": [root_package["SPDXID"]],
        "relationships": relationships
        + native_relationships
        + [
            {
                "spdxElementId": root_package["SPDXID"],
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": "SPDXRef-Package-SciterEngine",
            },
            {
                "spdxElementId": "SPDXRef-Package-WiXToolset",
                "relationshipType": "BUILD_DEPENDENCY_OF",
                "relatedSpdxElement": root_package["SPDXID"],
            },
        ],
        "hasExtractedLicensingInfos": [
            {
                "licenseId": "LicenseRef-Sciter-EULA",
                "extractedText": sciter_text,
                "name": "Sciter end user license agreement",
            }
        ]
        + cargo_licenses,
    }
    sbom_path = output / "sbom.spdx.json"
    canonical_json(sbom_path, spdx)

    root_license = (root / "LICENCE").read_text(encoding="utf-8")
    notices = [
        "SymplifiedIT managed RustDesk 1.4.9.1 notices",
        f"Source commit: {args.source_commit}",
        f"hbb_common commit: {args.hbb_common_commit}",
        "",
        "RustDesk license (LICENCE)",
        "=" * 80,
        root_license.rstrip(),
        "",
        "Exact unresolved Cargo dependency license status",
        "=" * 80,
        *(
            line
            for (name, version, source), location in sorted(unresolved_cargo.items())
            for line in (
                f"{name} {version}",
                f"Cargo source: {source}",
                f"Source: {location}",
                "SPDX licenseDeclared: NOASSERTION",
                "SPDX licenseConcluded: NOASSERTION",
                "",
            )
        ),
        "No license scope is inferred from a parent or neighboring repository; "
        "independent legal review is required before publication.",
        "",
        f"WiX Toolset license; derived UI source from {WIX_SOURCE_COMMIT}",
        "=" * 80,
        wix_license.rstrip(),
        "",
        f"Sciter EULA from c-smile/sciter-sdk@{SCITER_COMMIT}/license.htm",
        "=" * 80,
        sciter_text.rstrip(),
        "",
        "Locked Rust dependency inventory",
        "=" * 80,
    ]
    notices.extend(
        f"{item['name']} {item['versionInfo']} | {item['licenseDeclared']} | "
        f"{item['downloadLocation']}"
        for item in packages
        if item["name"] not in {"Sciter Engine", "WiX Toolset and derived UI source"}
    )
    notices.extend(
        (
            "",
            f"vcpkg {item['name']} {item['version']}",
            "=" * 80,
            f"SPDX license: {item['license']}",
            f"vcpkg source license value: {item['raw_license']}",
            f"Source: {item['download_location']}",
            item["copyright_text"].rstrip(),
        )
        for item in native_notices
    )
    notices = [line for item in notices for line in (item if isinstance(item, tuple) else (item,))]
    notices_path = output / "notices.txt"
    notices_path.write_text("\n".join(notices) + "\n", encoding="utf-8", newline="\n")

    build_information = {
        "schema": 1,
        "release": "sit-rustdesk-1.4.9.1",
        "upstream_version": "1.4.9",
        "fork_revision": 1,
        "source_commit": args.source_commit,
        "upstream_commit": UPSTREAM_COMMIT,
        "hbb_common_commit": args.hbb_common_commit,
        "generation": args.generation,
        "source_date_epoch": args.source_date_epoch,
        "workflow_run": args.run_url,
        "reproducibility": {
            "isolated_windows_executable_builds": 2,
            "byte_identical_unsigned_executable": True,
            "isolated_windows_msi_builds": 2,
            "byte_identical_unsigned_msi": True,
        },
        "builder": builder,
        "signed_candidate": candidate,
        "submodules": [
            {"path": "libs/hbb_common", "commit": args.hbb_common_commit}
        ],
        "corresponding_source": {
            "name": source_archive.name,
            **file_record(source_archive),
        },
        "sbom": {"name": sbom_path.name, **file_record(sbom_path)},
        "notices": {"name": notices_path.name, **file_record(notices_path)},
        "native_dependencies": {
            "name": native_path.name,
            **file_record(native_path),
        },
    }
    canonical_json(output / "build-information.json", build_information)

    expected = ["build-information.json", "notices.txt", "sbom.spdx.json"]
    if sorted(path.name for path in output.iterdir()) != expected:
        raise ValueError("Release evidence inventory is not exact")
    print("MANAGED_RELEASE_EVIDENCE=PASS")


if __name__ == "__main__":
    main()
