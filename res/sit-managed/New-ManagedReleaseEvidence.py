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


UPSTREAM_COMMIT = "6c578292e8ebbbec708b76986ba8c4bc7c509747"
SCITER_COMMIT = "f33df075d9eb2f8d252cb88f1b2c8096e56197ed"
SCITER_SHA256 = "4d97528e157c55ef1fabe9e37a9697116ab66660d7da6163f90a3a7abf80dd56"
SUBSCRIBER_EKU = "1.3.6.1.4.1.311.97.162372899.954041822.66046227.837397283"
WIX_SOURCE_COMMIT = "ce73352b1fa1d4f9cded10a0ee410f2e786bd326"


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
    value.add_argument("--source-archive", required=True)
    value.add_argument("--sciter-license", required=True)
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


def cargo_packages(root):
    tracked = run_git(root, "ls-files", "--recurse-submodules", "-z").decode(
        "utf-8"
    ).split("\0")
    lock_paths = sorted(path for path in tracked if path.endswith("Cargo.lock"))
    if not lock_paths:
        raise ValueError("No tracked Cargo lock file exists")
    packages = {}
    for relative in lock_paths:
        document = tomllib.loads((root / relative).read_text(encoding="utf-8"))
        for package in document.get("package", []):
            name = package["name"]
            version = package["version"]
            source = package.get("source", "NOASSERTION")
            checksum = package.get("checksum", "")
            key = (name, version, source, checksum)
            packages[key] = {
                "SPDXID": spdx_id(name, version, source),
                "name": name,
                "versionInfo": version,
                "downloadLocation": source,
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
                "checksums": (
                    [{"algorithm": "SHA256", "checksumValue": checksum}]
                    if re.fullmatch(r"[0-9a-f]{64}", checksum)
                    else []
                ),
            }
    return [packages[key] for key in sorted(packages)]


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

    candidate_path = Path(args.candidate_verification).resolve(strict=True)
    builder_path = Path(args.builder_information).resolve(strict=True)
    source_archive = Path(args.source_archive).resolve(strict=True)
    sciter_license = Path(args.sciter_license).resolve(strict=True)
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
    packages = cargo_packages(root)
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
            "creators": ["Tool: SymplifiedIT-New-ManagedReleaseEvidence-1"],
        },
        "packages": packages,
        "hasExtractedLicensingInfos": [
            {
                "licenseId": "LicenseRef-Sciter-EULA",
                "extractedText": sciter_text,
                "name": "Sciter end user license agreement",
            }
        ],
    }
    sbom_path = output / "sbom.spdx.json"
    canonical_json(sbom_path, spdx)

    root_license = (root / "LICENCE").read_text(encoding="utf-8")
    hbb_license = (root / "libs" / "hbb_common" / "LICENCE").read_text(
        encoding="utf-8"
    )
    notices = [
        "SymplifiedIT managed RustDesk 1.4.9.1 notices",
        f"Source commit: {args.source_commit}",
        f"hbb_common commit: {args.hbb_common_commit}",
        "",
        "RustDesk license (LICENCE)",
        "=" * 80,
        root_license.rstrip(),
        "",
        "hbb_common license (libs/hbb_common/LICENCE)",
        "=" * 80,
        hbb_license.rstrip(),
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
        f"{item['name']} {item['versionInfo']} | {item['downloadLocation']}"
        for item in packages
        if item["name"] not in {"Sciter Engine", "WiX Toolset and derived UI source"}
    )
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
    }
    canonical_json(output / "build-information.json", build_information)

    expected = ["build-information.json", "notices.txt", "sbom.spdx.json"]
    if sorted(path.name for path in output.iterdir()) != expected:
        raise ValueError("Release evidence inventory is not exact")
    print("MANAGED_RELEASE_EVIDENCE=PASS")


if __name__ == "__main__":
    main()
