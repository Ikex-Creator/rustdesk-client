# SymplifiedIT managed Windows CLI contract

The managed Windows executable exposes one bounded capability document through
`--capabilities-json`. Callers must require the exact protected fork commit and
the advertised contract before using either sensitive command.

`--password-stdin` is the privileged endpoint-provisioning command. It accepts
exactly 32 password bytes followed by EOF from an inherited anonymous pipe and
sets the installed endpoint's permanent password through acknowledged local
IPC. It does not accept another argument.

`--connect-password-stdin <peer-id>` is the technician connection command. The
peer ID is non-secret and is the only argument. The credential is exactly 32
bytes followed by EOF from an inherited anonymous pipe; a disk handle, missing
EOF, invalid alphabet, short/long frame, or delayed frame is rejected. The
installed executable keeps the credential in a process-local, peer-bound,
single-use slot for at most 30 seconds, hashes it into the RustDesk challenge
flow, and zeroizes the plaintext. It does not forward the request to an existing
UI process because that would require a second credential transport.

On Windows, legacy `--password <secret>`, `--password=<secret>`, and URI query
password forms are rejected before normal initialization regardless of their
argument position. A launcher must never place a credential in argv, an
environment variable, a URI, or a file. It must verify the installed executable
and its release identity first, create an anonymous pipe with only the read end
inherited by the child, write the exact frame, close its write end to signal
EOF, and treat every nonzero process result as a failed launch.
