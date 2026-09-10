use std::{
    ffi::OsString,
    fmt,
    io::{self, Write},
    time::{Duration, Instant},
};

use zeroize::Zeroize;

pub(crate) const PASSWORD_LEN: usize = 32;
pub(crate) const PASSWORD_ALPHABET: &[u8] =
    b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
pub(crate) const SENSITIVE_FRAME_MARKER: &[u8; 6] = b"\0SITP1";
pub(crate) const SENSITIVE_FRAME_LEN: usize = SENSITIVE_FRAME_MARKER.len() + PASSWORD_LEN;
const STDIN_TIMEOUT: Duration = Duration::from_secs(5);
const STDIN_POLL_INTERVAL: Duration = Duration::from_millis(10);

pub(crate) const EXIT_USAGE: i32 = 64;
pub(crate) const EXIT_INPUT: i32 = 65;
pub(crate) const EXIT_IPC: i32 = 69;
pub(crate) const EXIT_INTERNAL: i32 = 70;
pub(crate) const EXIT_NOT_AUTHORIZED: i32 = 77;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EarlyCommand {
    Continue,
    Capabilities,
    PasswordStdin,
    Reject,
}

pub(crate) fn classify_current_process() -> EarlyCommand {
    classify_args(std::env::args_os().skip(1))
}

fn classify_args(mut args: impl Iterator<Item = OsString>) -> EarlyCommand {
    let Some(first) = args.next() else {
        return EarlyCommand::Continue;
    };

    if first == OsString::from("--password") {
        // Do not enumerate the next argument: it may contain the legacy secret.
        return EarlyCommand::Reject;
    }
    if first == OsString::from("--password-stdin") {
        return if args.next().is_none() {
            EarlyCommand::PasswordStdin
        } else {
            EarlyCommand::Reject
        };
    }
    if first == OsString::from("--capabilities-json") {
        return if args.next().is_none() {
            EarlyCommand::Capabilities
        } else {
            EarlyCommand::Reject
        };
    }
    EarlyCommand::Continue
}

fn valid_fork_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn capabilities_line_for_commit(fork_commit: &str) -> Option<String> {
    if !valid_fork_commit(fork_commit) {
        return None;
    }
    Some(format!(
        "{{\"schema_version\":1,\"product\":\"symplifiedit-rustdesk-oss-client\",\"upstream_version\":\"1.4.9\",\"upstream_commit\":\"6c578292e8ebbbec708b76986ba8c4bc7c509747\",\"fork_commit\":\"{fork_commit}\",\"password_stdin_v1\":{{\"transport\":\"inherited_anonymous_stdin\",\"framing\":\"raw_32_bytes_eof\",\"credential_bytes\":32,\"alphabet\":\"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789\",\"legacy_password_argv\":false}}}}\n"
    ))
}

pub(crate) fn write_capabilities() -> i32 {
    let Some(line) = capabilities_line_for_commit(
        option_env!("SIT_RUSTDESK_FORK_COMMIT").unwrap_or(""),
    ) else {
        return EXIT_INTERNAL;
    };
    let stdout = io::stdout();
    let mut lock = stdout.lock();
    if lock.write_all(line.as_bytes()).is_err() || lock.flush().is_err() {
        return EXIT_INTERNAL;
    }
    0
}

pub(crate) struct SensitivePassword([u8; PASSWORD_LEN]);

impl SensitivePassword {
    fn from_exact_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != PASSWORD_LEN || !bytes.iter().all(|byte| PASSWORD_ALPHABET.contains(byte))
        {
            return None;
        }
        let mut value = [0u8; PASSWORD_LEN];
        value.copy_from_slice(bytes);
        Some(Self(value))
    }

    pub(crate) fn from_sensitive_frame(frame: &[u8]) -> Option<Self> {
        if frame.len() != SENSITIVE_FRAME_LEN || !frame.starts_with(SENSITIVE_FRAME_MARKER) {
            return None;
        }
        Self::from_exact_bytes(&frame[SENSITIVE_FRAME_MARKER.len()..])
    }

    pub(crate) fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }

    pub(crate) fn copy_to(&self, output: &mut [u8]) -> bool {
        if output.len() != PASSWORD_LEN {
            return false;
        }
        output.copy_from_slice(&self.0);
        true
    }

    pub(crate) fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Clone for SensitivePassword {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl fmt::Debug for SensitivePassword {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SensitivePassword([REDACTED])")
    }
}

impl Drop for SensitivePassword {
    fn drop(&mut self) {
        self.zeroize();
    }
}

pub(crate) struct SensitiveFrame([u8; SENSITIVE_FRAME_LEN]);

impl SensitiveFrame {
    pub(crate) fn new(password: &SensitivePassword) -> Self {
        let mut frame = [0u8; SENSITIVE_FRAME_LEN];
        frame[..SENSITIVE_FRAME_MARKER.len()].copy_from_slice(SENSITIVE_FRAME_MARKER);
        let copied = password.copy_to(&mut frame[SENSITIVE_FRAME_MARKER.len()..]);
        debug_assert!(copied);
        Self(frame)
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SensitiveFrame {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(windows)]
fn is_broken_pipe(error: &windows::core::Error) -> bool {
    use windows::{
        core::HRESULT,
        Win32::Foundation::{ERROR_BROKEN_PIPE, ERROR_NO_DATA},
    };

    error.code() == HRESULT::from_win32(ERROR_BROKEN_PIPE.0)
        || error.code() == HRESULT::from_win32(ERROR_NO_DATA.0)
}

#[cfg(windows)]
pub(crate) fn read_password_stdin() -> Result<SensitivePassword, ()> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{GetFileType, ReadFile, FILE_TYPE_PIPE},
        System::Pipes::PeekNamedPipe,
    };

    let stdin = io::stdin();
    let handle = HANDLE(stdin.as_raw_handle());
    if handle.is_invalid() || unsafe { GetFileType(handle) } != FILE_TYPE_PIPE {
        return Err(());
    }

    let deadline = Instant::now() + STDIN_TIMEOUT;
    let mut input = [0u8; PASSWORD_LEN + 1];
    let mut used = 0usize;
    loop {
        let mut available = 0u32;
        match unsafe { PeekNamedPipe(handle, None, 0, None, Some(&mut available), None) } {
            Ok(()) => {}
            Err(error) if is_broken_pipe(&error) => {
                let result = SensitivePassword::from_exact_bytes(&input[..used]).ok_or(());
                input.zeroize();
                return result;
            }
            Err(_) => {
                input.zeroize();
                return Err(());
            }
        }

        if available == 0 {
            if Instant::now() >= deadline {
                input.zeroize();
                return Err(());
            }
            std::thread::sleep(STDIN_POLL_INTERVAL);
            continue;
        }

        let remaining = input.len().saturating_sub(used);
        if remaining == 0 {
            input.zeroize();
            return Err(());
        }
        let to_read = remaining.min(available as usize);
        let mut bytes_read = 0u32;
        match unsafe {
            ReadFile(
                handle,
                Some(&mut input[used..used + to_read]),
                Some(&mut bytes_read),
                None,
            )
        } {
            Ok(()) => {
                used += bytes_read as usize;
                if used > PASSWORD_LEN {
                    input.zeroize();
                    return Err(());
                }
            }
            Err(error) if is_broken_pipe(&error) => {
                let result = SensitivePassword::from_exact_bytes(&input[..used]).ok_or(());
                input.zeroize();
                return result;
            }
            Err(_) => {
                input.zeroize();
                return Err(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
    const PASSWORD: &[u8; PASSWORD_LEN] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefgh";

    fn classify(values: &[&str]) -> EarlyCommand {
        classify_args(values.iter().map(|value| OsString::from(*value)))
    }

    #[test]
    fn managed_commands_require_exact_invocation() {
        assert_eq!(classify(&[]), EarlyCommand::Continue);
        assert_eq!(classify(&["--version"]), EarlyCommand::Continue);
        assert_eq!(classify(&["--capabilities-json"]), EarlyCommand::Capabilities);
        assert_eq!(
            classify(&["--capabilities-json", "extra"]),
            EarlyCommand::Reject
        );
        assert_eq!(classify(&["--password-stdin"]), EarlyCommand::PasswordStdin);
        assert_eq!(
            classify(&["--password-stdin", "extra"]),
            EarlyCommand::Reject
        );
        assert_eq!(classify(&["--password"]), EarlyCommand::Reject);
        assert_eq!(classify(&["--password", "secret"]), EarlyCommand::Reject);
    }

    #[test]
    fn capabilities_are_exact_canonical_and_bounded() {
        let value = capabilities_line_for_commit(COMMIT).expect("valid commit");
        assert_eq!(value.as_bytes().last(), Some(&b'\n'));
        assert_eq!(value.matches('\n').count(), 1);
        assert!(value.len() <= 1_024);
        assert_eq!(
            value,
            format!(
                "{{\"schema_version\":1,\"product\":\"symplifiedit-rustdesk-oss-client\",\"upstream_version\":\"1.4.9\",\"upstream_commit\":\"6c578292e8ebbbec708b76986ba8c4bc7c509747\",\"fork_commit\":\"{COMMIT}\",\"password_stdin_v1\":{{\"transport\":\"inherited_anonymous_stdin\",\"framing\":\"raw_32_bytes_eof\",\"credential_bytes\":32,\"alphabet\":\"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789\",\"legacy_password_argv\":false}}}}\n"
            )
        );
    }

    #[test]
    fn capabilities_reject_noncanonical_commits() {
        for value in [
            "",
            "0123456789abcdef0123456789abcdef0123456",
            "0123456789abcdef0123456789abcdef012345678",
            "0123456789abcdef0123456789abcdef0123456G",
            "0123456789ABCDEF0123456789ABCDEF01234567",
        ] {
            assert!(capabilities_line_for_commit(value).is_none());
        }
    }

    #[test]
    fn sensitive_frame_is_exact_and_debug_is_redacted() {
        let password = SensitivePassword::from_exact_bytes(PASSWORD).expect("valid password");
        let frame = SensitiveFrame::new(&password);
        assert_eq!(frame.as_bytes().len(), SENSITIVE_FRAME_LEN);
        assert_eq!(
            &frame.as_bytes()[..SENSITIVE_FRAME_MARKER.len()],
            SENSITIVE_FRAME_MARKER
        );
        assert_eq!(&frame.as_bytes()[SENSITIVE_FRAME_MARKER.len()..], PASSWORD);
        assert_eq!(format!("{password:?}"), "SensitivePassword([REDACTED])");
    }

    #[test]
    fn sensitive_input_rejects_every_shape_outside_contract() {
        assert!(SensitivePassword::from_exact_bytes(PASSWORD).is_some());
        assert!(SensitivePassword::from_exact_bytes(&PASSWORD[..PASSWORD_LEN - 1]).is_none());
        let mut long = [b'A'; PASSWORD_LEN + 1];
        assert!(SensitivePassword::from_exact_bytes(&long).is_none());
        long[0] = b'0';
        assert!(SensitivePassword::from_exact_bytes(&long[..PASSWORD_LEN]).is_none());
        for invalid in [0, b'0', b'1', b'I', b'O', b'l', b'\r', b'\n'] {
            let mut value = *PASSWORD;
            value[0] = invalid;
            assert!(SensitivePassword::from_exact_bytes(&value).is_none());
        }
    }

    #[test]
    fn sensitive_frame_rejects_wrong_marker_and_lengths() {
        let password = SensitivePassword::from_exact_bytes(PASSWORD).expect("valid password");
        let frame = SensitiveFrame::new(&password);
        assert!(SensitivePassword::from_sensitive_frame(frame.as_bytes()).is_some());
        assert!(SensitivePassword::from_sensitive_frame(&frame.as_bytes()[1..]).is_none());
        let mut wrong = frame.as_bytes().to_vec();
        wrong[0] = b'X';
        assert!(SensitivePassword::from_sensitive_frame(&wrong).is_none());
        wrong.zeroize();
    }
}
