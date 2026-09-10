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
