# SymplifiedIT managed RustDesk client

This public fork is the complete corresponding source for the SymplifiedIT
managed RustDesk OSS client. It is based on RustDesk `1.4.9` at upstream commit
`6c578292e8ebbbec708b76986ba8c4bc7c509747` and remains licensed under the GNU
Affero General Public License version 3 as provided in [LICENCE](LICENCE).

The first managed release line is `sit-rustdesk-1.4.9.1`. Its bounded functional
changes are:

- an exact Windows-only `--capabilities-json` command;
- an exact Windows-only `--password-stdin` command using 32 raw bytes from an
  inherited pipe and no password argument, file, environment variable, or named
  product endpoint;
- a dedicated authenticated main-IPC sensitive frame with zeroized user-space
  buffers and a durable-store ACK; and
- rejection of the legacy permanent-password management form on Windows.

The existing Windows main-IPC executable and identity authentication in
`src/ipc/auth.rs` is unchanged. The fork does not include RustDesk Server Pro,
does not add an endpoint-management plane, and does not contain SymplifiedIT MSP
backend or endpoint-agent source.

## Source and build identity

Every production build must use a clean checkout of the release tag and its
recursive submodules. The `libs/hbb_common` gitlink is authoritative; its public
fork contains the small durable-storage change required by this client.

The build must set `SIT_RUSTDESK_FORK_COMMIT` to the exact 40-character lowercase
commit being compiled. `--capabilities-json` fails closed with exit 70 if that
identity was not embedded. CI checks out and builds the exact event commit rather
than a synthetic pull-request merge commit.

Pull requests targeting managed release branches run the focused Windows
security suite and the repository's standard host CI. The upstream full Flutter
matrix remains available manually and runs for pull requests targeting `master`;
it is intentionally not fanned out across unrelated mobile, macOS, ARM, and
32-bit jobs for a Windows-only managed release.

The full Windows toolchain, dependency inventory, commands, unsigned hashes,
SBOM, and reproducibility results are published as immutable assets alongside
each release. No Azure, OIDC, or signing credential is available during source
compilation or unsigned MSI packaging. Microsoft Artifact Signing occurs only
after two clean builders produce byte-identical unsigned output.

The protected manual candidate workflow is
`.github/workflows/sit-managed-release.yml`. It accepts only the exact protected
`release/sit-rustdesk-1.4.9` ref and current workflow/source SHA. Two isolated
Windows builders must produce byte-identical unsigned managed executables. A
private no-checkout signer is called by immutable Msp commit to sign exactly
`rustdesk-client.exe`; two separate packagers then build byte-identical unsigned
MSIs containing that signed executable before the same signer signs exactly
`rustdesk-client.msi`. The public caller has no Azure secret surface. Its two
OIDC-capable jobs contain only the immutable reusable-workflow calls; all source,
build, packaging, comparison, verification, SBOM, notices, and corresponding-
source work is credential-free.

Release builds derive RustDesk's embedded build date, generated MSI identities,
file timestamps, and archive timestamps from the source commit epoch. They pin
Rust 1.75.0, vcpkg, LLVM, NuGet, Microsoft signing payloads, and Sciter by exact
commit/length/SHA-256. The Sciter EULA is bundled in `notices.txt`, and the
Sciter About-dialog attribution required by that EULA is part of the reviewed
source. The workflow stops at an expiring publishable candidate artifact; it
does not create a tag, publish a GitHub release, finalize an MSP manifest, run a
pilot, or deploy production.

The corresponding-source archive includes the complete Microsoft Reciprocal
License used by the two reviewed WiX UI-derived source files. Release notices
and the SPDX document identify those files' exact upstream commit and the WiX
4.0.5 packaging toolchain in addition to RustDesk, hbb_common, the exact
non-development dependency graph for the shipped Windows target and feature
set, and Sciter. The graph is resolved by the same pinned Rust/Cargo toolchain
and root `Cargo.lock` used by both isolated builders. Cargo package license
declarations and bounded license-file text are retained; generation fails closed
if any dependency outside the exact reviewed unresolved set lacks license
evidence. Each builder also emits byte-identical normalized evidence for its
exact installed static vcpkg graph from vcpkg's per-port SPDX documents,
selected features, dependency edges, ABI identities, source resources, and
installed copyright files. That evidence is retained as
`native-dependencies.json` and folded into the release SBOM and notices.

The managed Windows build enables only the `inline` Cargo feature. The upstream
`hwcodec`/`vram` features (and with them the `rustdesk-org/hwcodec` crate and
the vcpkg FFmpeg/ffnvcodec/AMF/libmfx graph, whose overlay FFmpeg port ships a
GPL-2.0 copyright file) are deliberately not built; video encoding uses the
BSD-licensed libvpx/aom/libyuv software codecs. The Windows portable
"run as SYSTEM" bootstrap is stubbed to fail closed, so the unlicensed
`rustdesk-org/impersonate-system` crate is not linked. `libs/hbb_common` reads
the default-interface MAC through the MIT crates.io `default-net` crate that the
root crate already used, so the unlicensed `rustdesk-org/default_net` git crate
is gone.

The exact `hbb_common` submodule commit contains no standalone license file or
Cargo license declaration. Release evidence records its exact source URL and
commit with SPDX `licenseDeclared` and `licenseConcluded` set to `NOASSERTION`;
it does not infer license scope from a parent or neighboring repository. That is
the only permitted unresolved Cargo package license record.

Owner decision (2026-09-17): the SymplifiedIT owner accepts distribution of the
exact `hbb_common` commit on the recorded provenance that upstream RustDesk
extracted it from its own AGPL-3.0 tree (RustDesk commit
`c44803f5b09cd865fc36073ef7d8d65b71efda57`, byte-identical source blobs) and
that every upstream RustDesk release ships the same crate under AGPL-3.0. The
managed fork therefore distributes `hbb_common` under AGPL-3.0 with complete
corresponding source, while the SBOM keeps the honest `NOASSERTION` record
until the rights holder publishes a standalone license file. This is a recorded
business decision, not a legal opinion; revisit it if RustDesk discussion
`#15801` receives an authoritative answer.

The exact native graph has no unresolved license records: the `res/vcpkg`
overlay ports for libyuv `1857` and build-only pkgconf `2.5.1` declare
`BSD-3-Clause` and `ISC`, matching the retained upstream copyright files. The
evidence generator fails closed if any installed native package lacks a license
expression. The vcpkg labels and retained copyright files are evidence, not
legal authorization.

## Security contract

`--password-stdin` accepts only an inherited pipe containing exactly 32 bytes
from `ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789`, immediately
followed by EOF. It rejects console/file stdin, short/long input, invalid bytes,
extra arguments, stalled writers, missing installation/elevation, disabled
settings, IPC failure, NACK, and durable-storage failure with fixed silent exit
codes. Password-bearing user-space buffers use `zeroize` and are never formatted
or logged.

See the release assets for the supported-Windows integration report, canary scan,
unattended-session proof, notices, and complete dependency/SBOM inventory.
