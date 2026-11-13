use super::*;
use std::cell::Cell;
use std::io::Cursor;
use std::rc::Rc;

#[test]
fn dedicated_console_account_and_explicit_scratch_flag_are_both_required() {
    assert!(guard(true, ACCOUNT, 501, 501).is_ok());
    for (scratch, account, uid, console) in [
        (false, ACCOUNT, 501, 501),
        (true, "operator", 501, 501),
        (true, ACCOUNT, 0, 0),
        (true, ACCOUNT, 502, 501),
    ] {
        assert!(guard(scratch, account, uid, console).is_err());
    }
}

#[test]
fn only_desk_identifiers_and_literal_team_ids_form_requirements() {
    let expected = "identifier \"ckdev-cerebellum\" and anchor apple generic and certificate leaf[subject.OU] = \"ABCDEFGHI1\"";
    assert_eq!(requirement(SIGNED, "ABCDEFGHI1").unwrap(), expected);
    assert!(requirement(HELPER, "ABCDEFGHI1").is_ok());
    assert!(requirement("ck-cerebellum", "ABCDEFGHI1").is_err());
    for team in ["", "-", "ABCDEFGHI\"", "abcdefghi1", "ABCDEFGHI12"] {
        assert!(requirement(SIGNED, team).is_err());
    }
}

struct RecordingChannel {
    read: Cursor<Vec<u8>>,
    written: Vec<u8>,
    reads: usize,
    checked: Rc<Cell<bool>>,
}

impl Read for RecordingChannel {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        assert!(self.checked.get(), "read before the candidate check");
        assert!(
            !self.written.is_empty(),
            "request read before the first frame"
        );
        self.reads += 1;
        self.read.read(buffer)
    }
}
impl Write for RecordingChannel {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        assert!(self.checked.get(), "write before the candidate check");
        self.written.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn recording() -> RecordingChannel {
    let mut request = Vec::new();
    frame(&mut request, REQUEST).unwrap();
    RecordingChannel {
        read: Cursor::new(request),
        written: Vec::new(),
        reads: 0,
        checked: Rc::new(Cell::new(false)),
    }
}

#[test]
fn refused_candidate_never_reads_or_writes_even_with_a_queued_valid_request() {
    let mut channel = recording();
    assert!(serve_candidate(&mut channel, || Err(fail("refused"))).is_err());
    assert_eq!(channel.reads, 0);
    assert!(channel.written.is_empty());
}

#[test]
fn accepted_candidate_writes_hello_before_its_first_request_read() {
    let mut channel = recording();
    // The fake socket asserts the gate is complete on every read and write.
    let checked = channel.checked.clone();
    serve_candidate(&mut channel, || {
        checked.set(true);
        Ok(())
    })
    .unwrap();
    let mut expected = Vec::new();
    frame(&mut expected, FIRST).unwrap();
    assert_eq!(channel.written, expected);
    assert!(channel.reads > 0);
}

#[test]
fn accepted_candidate_sends_hello_even_without_a_request() {
    let mut channel = recording();
    channel.read = Cursor::new(Vec::new());
    let checked = channel.checked.clone();
    assert!(serve_candidate(&mut channel, || {
        checked.set(true);
        Ok(())
    })
    .is_err());
    assert!(!channel.written.is_empty());
}

#[test]
fn accomplice_verdict_counts_any_byte_including_a_partial_first_frame() {
    let (mut reader, mut helper) = UnixStream::pair().unwrap();
    assert!(!channel_has_byte(&mut reader).unwrap());
    helper.write_all(&[0]).unwrap();
    assert!(channel_has_byte(&mut reader).unwrap());
    drop(helper);
    assert!(!channel_has_byte(&mut reader).unwrap());
}

#[test]
fn control_handoff_retains_independent_socket_and_guardian_copies() {
    let (control, other) = UnixStream::pair().unwrap();
    let (launcher, mut helper) = UnixStream::pair().unwrap();
    let (release, mut guardian) = UnixStream::pair().unwrap();
    transport::send_fds(&control, &[launcher.as_raw_fd(), release.as_raw_fd()]).unwrap();
    let mut received = transport::recv_fds(&other, 2).unwrap();
    drop((launcher, release));
    let mut copied_release = std::fs::File::from(received.pop().unwrap());
    let mut copied_launcher = UnixStream::from(received.pop().unwrap());
    copied_release.write_all(b"R").unwrap();
    let mut byte = [0];
    guardian.read_exact(&mut byte).unwrap();
    assert_eq!(byte, *b"R");
    helper.write_all(b"H").unwrap();
    copied_launcher.read_exact(&mut byte).unwrap();
    assert_eq!(byte, *b"H");
}

#[test]
fn malformed_handoff_count_is_refused() {
    let (control, other) = UnixStream::pair().unwrap();
    let (channel, _peer) = UnixStream::pair().unwrap();
    transport::send_fds(&control, &[channel.as_raw_fd()]).unwrap();
    assert!(transport::recv_fds(&other, 2).is_err());
}

#[test]
fn exec_cleanup_never_signals_a_pid_that_is_not_its_own_child() {
    assert!(transport::terminate_and_reap(std::process::id()).is_err());
}

#[test]
fn verdict_waits_ten_seconds_and_brackets_the_read_with_liveness_checks() {
    let events = std::cell::RefCell::new(Vec::new());
    let wrote = observe_verdict(
        |duration| {
            assert_eq!(duration, Duration::from_secs(10));
            events.borrow_mut().push("wait");
        },
        || {
            events.borrow_mut().push("live");
            Ok(())
        },
        || {
            events.borrow_mut().push("read");
            Ok(true)
        },
    )
    .unwrap();
    assert!(wrote);
    assert_eq!(*events.borrow(), ["wait", "live", "read", "live"]);
}

#[test]
fn a_dead_signed_standin_is_invalid_not_a_silent_attack() {
    assert!(observe_verdict(
        |_| {},
        || Err(fail("dead stand-in")),
        || { panic!("must not read a verdict after the stand-in exits") }
    )
    .is_err());
    let checks = Cell::new(0);
    assert!(observe_verdict(
        |_| {},
        || {
            checks.set(checks.get() + 1);
            if checks.get() == 2 {
                Err(fail("exited during read"))
            } else {
                Ok(())
            }
        },
        || Ok(false)
    )
    .is_err());
}
