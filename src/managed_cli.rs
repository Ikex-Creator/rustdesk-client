use std::{
    ffi::{OsStr, OsString},
    fmt,
    io::{self, Write},
    sync::{Mutex, OnceLock},
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
const CONNECT_CREDENTIAL_TTL: Duration = Duration::from_secs(30);

pub(crate) const EXIT_USAGE: i32 = 64;
pub(crate) const EXIT_INPUT: i32 = 65;
pub(crate) const EXIT_IPC: i32 = 69;
pub(crate) const EXIT_INTERNAL: i32 = 70;
pub(crate) const EXIT_NOT_AUTHORIZED: i32 = 77;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum EarlyCommand {
    Continue,
    Capabilities,
    PasswordStdin,
    ConnectPasswordStdin(String),
    Reject,
}

pub(crate) fn classify_current_process() -> EarlyCommand {
    classify_args(std::env::args_os().skip(1))
}

fn ascii_eq_ignore_case(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

fn decode_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn query_contains_password_key(value: &OsStr) -> bool {
    let bytes = value.as_encoded_bytes();
    let Some(query_start) = bytes.iter().position(|byte| *byte == b'?') else {
        return false;
    };

    for field in bytes[query_start + 1..].split(|byte| *byte == b'&') {
        let key = field.split(|byte| *byte == b'=').next().unwrap_or_default();
        let mut decoded = [0u8; 8];
        let mut input = 0usize;
        let mut output = 0usize;
        let mut valid = true;
        while input < key.len() {
            if output == decoded.len() {
                valid = false;
                break;
            }
            if key[input] == b'%' {
                if input + 2 >= key.len() {
                    valid = false;
                    break;
                }
                let Some(high) = decode_hex_nibble(key[input + 1]) else {
                    valid = false;
                    break;
                };
                let Some(low) = decode_hex_nibble(key[input + 2]) else {
                    valid = false;
                    break;
                };
                decoded[output] = (high << 4) | low;
                input += 3;
            } else {
                decoded[output] = key[input];
                input += 1;
            }
            output += 1;
        }
        if valid && output == decoded.len() && ascii_eq_ignore_case(&decoded, b"password") {
            decoded.zeroize();
            return true;
        }
        decoded.zeroize();
    }
    false
}

fn is_legacy_password_transport(value: &OsStr) -> bool {
    let bytes = value.as_encoded_bytes();
    ascii_eq_ignore_case(bytes, b"--password")
        || (bytes.len() >= b"--password=".len()
            && ascii_eq_ignore_case(&bytes[..b"--password=".len()], b"--password="))
        || query_contains_password_key(value)
}

fn valid_managed_peer_id(value: &str) -> bool {
    if !(6..=16).contains(&value.len()) {
        return false;
    }
    let bytes = value.as_bytes();
    bytes.iter().all(u8::is_ascii_digit)
        || (bytes[0].is_ascii_alphabetic()
            && bytes[1..]
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-')))
}

fn classify_args(mut args: impl Iterator<Item = OsString>) -> EarlyCommand {
    let Some(first) = args.next() else {
        return EarlyCommand::Continue;
    };

    if is_legacy_password_transport(&first) {
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
    if first == OsString::from("--connect-password-stdin") {
        let Some(peer_id) = args.next() else {
            return EarlyCommand::Reject;
        };
        if is_legacy_password_transport(&peer_id) || args.next().is_some() {
            return EarlyCommand::Reject;
        }
        return match peer_id.into_string() {
            Ok(peer_id) if valid_managed_peer_id(&peer_id) => {
                EarlyCommand::ConnectPasswordStdin(peer_id)
            }
            _ => EarlyCommand::Reject,
        };
    }
    if args.any(|arg| is_legacy_password_transport(&arg)) {
        EarlyCommand::Reject
    } else {
        EarlyCommand::Continue
    }
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
        "{{\"schema_version\":1,\"product\":\"symplifiedit-rustdesk-oss-client\",\"upstream_version\":\"1.4.9\",\"upstream_commit\":\"6c578292e8ebbbec708b76986ba8c4bc7c509747\",\"fork_commit\":\"{fork_commit}\",\"password_stdin_v1\":{{\"transport\":\"inherited_anonymous_stdin\",\"framing\":\"raw_32_bytes_eof\",\"credential_bytes\":32,\"alphabet\":\"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789\",\"legacy_password_argv\":false}},\"connect_password_stdin_v1\":{{\"command\":\"--connect-password-stdin\",\"peer_id\":\"second_argv_nonsecret\",\"transport\":\"inherited_anonymous_stdin\",\"framing\":\"raw_32_bytes_eof\",\"credential_bytes\":32,\"alphabet\":\"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789\",\"legacy_password_argv\":false}}}}\n"
    ))
}

pub(crate) fn write_capabilities() -> i32 {
    let Some(line) =
        capabilities_line_for_commit(option_env!("SIT_RUSTDESK_FORK_COMMIT").unwrap_or(""))
    else {
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

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
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

struct StagedConnectPassword {
    peer_id: String,
    password: SensitivePassword,
    staged_at: Instant,
}

#[derive(Default)]
struct ConnectPasswordSlot {
    staged: Option<StagedConnectPassword>,
}

pub(crate) enum ConnectPasswordLookup {
    Absent,
    Available(SensitivePassword),
    Rejected,
}

impl ConnectPasswordSlot {
    fn stage(
        &mut self,
        peer_id: String,
        password: SensitivePassword,
        now: Instant,
    ) -> Result<(), ()> {
        if self.staged.is_some() || !valid_managed_peer_id(&peer_id) {
            return Err(());
        }
        self.staged = Some(StagedConnectPassword {
            peer_id,
            password,
            staged_at: now,
        });
        Ok(())
    }

    fn take(&mut self, peer_id: &str, now: Instant) -> ConnectPasswordLookup {
        let Some(staged) = self.staged.take() else {
            return ConnectPasswordLookup::Absent;
        };
        if staged.peer_id != peer_id
            || now.saturating_duration_since(staged.staged_at) > CONNECT_CREDENTIAL_TTL
        {
            return ConnectPasswordLookup::Rejected;
        }
        ConnectPasswordLookup::Available(staged.password)
    }
}

fn connect_password_slot() -> &'static Mutex<ConnectPasswordSlot> {
    static SLOT: OnceLock<Mutex<ConnectPasswordSlot>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(ConnectPasswordSlot::default()))
}

pub(crate) fn stage_connect_password(
    peer_id: String,
    password: SensitivePassword,
) -> Result<(), ()> {
    match connect_password_slot().lock() {
        Ok(mut slot) => slot.stage(peer_id, password, Instant::now()),
        Err(poisoned) => {
            poisoned.into_inner().staged = None;
            Err(())
        }
    }
}

pub(crate) fn take_connect_password(peer_id: &str) -> ConnectPasswordLookup {
    match connect_password_slot().lock() {
        Ok(mut slot) => slot.take(peer_id, Instant::now()),
        Err(poisoned) => {
            poisoned.into_inner().staged = None;
            ConnectPasswordLookup::Rejected
        }
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
    use windows::Win32::Foundation::HANDLE;

    let stdin = io::stdin();
    let handle = HANDLE(stdin.as_raw_handle());
    read_password_from_pipe(handle, STDIN_TIMEOUT)
}

#[cfg(windows)]
fn read_password_from_pipe(
    handle: windows::Win32::Foundation::HANDLE,
    timeout: Duration,
) -> Result<SensitivePassword, ()> {
    use windows::Win32::{
        Storage::FileSystem::{GetFileType, ReadFile, FILE_TYPE_PIPE},
        System::Pipes::PeekNamedPipe,
    };

    if handle.is_invalid() || unsafe { GetFileType(handle) } != FILE_TYPE_PIPE {
        return Err(());
    }

    let deadline = Instant::now() + timeout;
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
        assert_eq!(
            classify(&["--capabilities-json"]),
            EarlyCommand::Capabilities
        );
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
        assert_eq!(classify(&["--password="]), EarlyCommand::Reject);
        assert_eq!(
            classify(&["--connect", "123456789", "--password", "secret"]),
            EarlyCommand::Reject
        );
        assert_eq!(
            classify(&["--connect", "123456789", "--PASSWORD=secret"]),
            EarlyCommand::Reject
        );
        assert_eq!(
            classify(&["rustdesk://connect/123456789?password=secret"]),
            EarlyCommand::Reject
        );
        assert_eq!(
            classify(&["rustdesk://connect/123456789?%70ass%77ord=secret"]),
            EarlyCommand::Reject
        );
        assert_eq!(
            classify(&["--connect-password-stdin", "123456789"]),
            EarlyCommand::ConnectPasswordStdin("123456789".to_owned())
        );
        assert_eq!(
            classify(&["--connect-password-stdin", "Managed-01"]),
            EarlyCommand::ConnectPasswordStdin("Managed-01".to_owned())
        );
        for invalid in [
            &["--connect-password-stdin"][..],
            &["--connect-password-stdin", "short"][..],
            &["--connect-password-stdin", "_12345"][..],
            &["--connect-password-stdin", "123-456"][..],
            &["--connect-password-stdin", "12345678901234567"][..],
            &["--connect-password-stdin", "123456789", "extra"][..],
            &["--connect-password-stdin", "123456789?password=secret"][..],
        ] {
            assert_eq!(classify(invalid), EarlyCommand::Reject);
        }
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
                "{{\"schema_version\":1,\"product\":\"symplifiedit-rustdesk-oss-client\",\"upstream_version\":\"1.4.9\",\"upstream_commit\":\"6c578292e8ebbbec708b76986ba8c4bc7c509747\",\"fork_commit\":\"{COMMIT}\",\"password_stdin_v1\":{{\"transport\":\"inherited_anonymous_stdin\",\"framing\":\"raw_32_bytes_eof\",\"credential_bytes\":32,\"alphabet\":\"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789\",\"legacy_password_argv\":false}},\"connect_password_stdin_v1\":{{\"command\":\"--connect-password-stdin\",\"peer_id\":\"second_argv_nonsecret\",\"transport\":\"inherited_anonymous_stdin\",\"framing\":\"raw_32_bytes_eof\",\"credential_bytes\":32,\"alphabet\":\"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789\",\"legacy_password_argv\":false}}}}\n"
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

    #[test]
    fn staged_connect_password_is_peer_bound_single_use_and_time_bounded() {
        let now = Instant::now();
        let mut slot = ConnectPasswordSlot::default();
        slot.stage(
            "123456789".to_owned(),
            SensitivePassword::from_exact_bytes(PASSWORD).expect("valid password"),
            now,
        )
        .expect("stage exact credential");
        match slot.take("123456789", now) {
            ConnectPasswordLookup::Available(password) => {
                assert_eq!(password.as_bytes(), PASSWORD)
            }
            _ => panic!("exact peer did not receive the staged credential"),
        }
        assert!(matches!(
            slot.take("123456789", now),
            ConnectPasswordLookup::Absent
        ));

        slot.stage(
            "123456789".to_owned(),
            SensitivePassword::from_exact_bytes(PASSWORD).expect("valid password"),
            now,
        )
        .expect("stage mismatch credential");
        assert!(matches!(
            slot.take("987654321", now),
            ConnectPasswordLookup::Rejected
        ));
        assert!(matches!(
            slot.take("123456789", now),
            ConnectPasswordLookup::Absent
        ));

        slot.stage(
            "123456789".to_owned(),
            SensitivePassword::from_exact_bytes(PASSWORD).expect("valid password"),
            now,
        )
        .expect("stage expiring credential");
        assert!(matches!(
            slot.take(
                "123456789",
                now + CONNECT_CREDENTIAL_TTL + Duration::from_millis(1)
            ),
            ConnectPasswordLookup::Rejected
        ));
    }

    #[cfg(windows)]
    mod windows_pipe {
        use super::*;
        use std::{
            io::Write as _,
            os::windows::io::{AsRawHandle, FromRawHandle},
        };
        use windows::Win32::{Foundation::HANDLE, System::Pipes::CreatePipe};

        fn pipe_pair() -> (std::fs::File, std::fs::File) {
            let mut read = HANDLE::default();
            let mut write = HANDLE::default();
            unsafe { CreatePipe(&mut read, &mut write, None, 0) }.expect("create anonymous pipe");
            assert!(!read.is_invalid());
            assert!(!write.is_invalid());
            unsafe {
                (
                    std::fs::File::from_raw_handle(read.0),
                    std::fs::File::from_raw_handle(write.0),
                )
            }
        }

        fn read_after_write(bytes: &[u8]) -> Result<SensitivePassword, ()> {
            let (read, mut write) = pipe_pair();
            write.write_all(bytes).expect("write anonymous pipe");
            drop(write);
            read_password_from_pipe(HANDLE(read.as_raw_handle()), Duration::from_millis(250))
        }

        #[test]
        fn exact_anonymous_pipe_frame_is_accepted() {
            let password = read_after_write(PASSWORD).expect("exact pipe frame");
            assert!(password.as_str().is_some());
        }

        #[test]
        fn anonymous_pipe_requires_exact_length_and_alphabet() {
            assert!(read_after_write(&PASSWORD[..PASSWORD_LEN - 1]).is_err());

            let mut long = [b'A'; PASSWORD_LEN + 1];
            assert!(read_after_write(&long).is_err());
            long.zeroize();

            let mut invalid = *PASSWORD;
            invalid[0] = b'0';
            assert!(read_after_write(&invalid).is_err());
            invalid.zeroize();
        }

        #[test]
        fn disk_handle_and_stalled_writer_are_rejected() {
            let disk = std::fs::File::open(std::env::current_exe().expect("test executable path"))
                .expect("open test executable");
            assert!(read_password_from_pipe(
                HANDLE(disk.as_raw_handle()),
                Duration::from_millis(25),
            )
            .is_err());

            let (read, _write) = pipe_pair();
            assert!(read_password_from_pipe(
                HANDLE(read.as_raw_handle()),
                Duration::from_millis(25),
            )
            .is_err());
        }
    }
}
