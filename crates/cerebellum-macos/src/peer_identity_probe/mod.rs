//! A manual experiment, not an admission mechanism for production helpers.
//! All three executable copies are desk-only; no privacy framework is invoked.

mod transport;

use crate::{
    bundle_code_satisfies_requirement, bundle_code_signing_identity, code_satisfies_requirement,
    code_signing_identity, process_start_time, spawn_barred_socket, BarredChild, ProcessGeneration,
    ProcessStartTime, RequirementCheck,
};
use std::error::Error;
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const FLAG: &str = "--scratch-peer-identity";
const ACCOUNT: &str = "ck-peer-probe";
const SIGNED: &str = "ckdev-cerebellum";
const HELPER: &str = "ckdev-cerebellum-peer-helper";
const UNSIGNED: &str = "ckdev-peer-attacker";
const WAIT: Duration = Duration::from_secs(10);
const TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST: &[u8] = br#"{"op":"status","scope":{}}"#;
const FIRST: &[u8] = br#"{"kind":"hello","probe":"peer-identity"}"#;

fn fail(message: impl Into<String>) -> Box<dyn Error> {
    io::Error::other(message.into()).into()
}

fn guard(scratch: bool, account: &str, uid: u32, console_uid: u32) -> Result<()> {
    if !scratch || account != ACCOUNT || uid == 0 || uid != console_uid {
        return Err(fail(format!(
            "requires {FLAG} in the dedicated {ACCOUNT} GUI login"
        )));
    }
    Ok(())
}

fn requirement(identifier: &str, team: &str) -> Result<String> {
    if ![SIGNED, HELPER].contains(&identifier)
        || team.len() != 10
        || !team
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    {
        return Err(fail("invalid desk identifier or Apple team id"));
    }
    Ok(format!("identifier \"{identifier}\" and anchor apple generic and certificate leaf[subject.OU] = \"{team}\""))
}

fn check_pid(pid: u32, required: &str) -> Result<ProcessGeneration> {
    let ProcessStartTime::Started(start_time_micros) = process_start_time(pid) else {
        return Err(fail("live process start time unavailable"));
    };
    if code_satisfies_requirement(pid, required, TIMEOUT).map_err(|e| fail(format!("{e:?}")))?
        != RequirementCheck::Satisfied
        || process_start_time(pid) != ProcessStartTime::Started(start_time_micros)
    {
        return Err(fail(
            "mapped image does not satisfy the expected signing requirement",
        ));
    }
    Ok(ProcessGeneration {
        pid,
        start_time_micros,
    })
}

fn own_team(identifier: &str) -> Result<String> {
    let identity = code_signing_identity(std::process::id(), TIMEOUT)
        .map_err(|e| fail(format!("own signature unavailable: {e:?}")))?;
    let team = identity
        .team_id
        .filter(|_| identity.signed && !identity.ad_hoc)
        .ok_or_else(|| fail("a valid team certificate signature is required"))?;
    check_pid(std::process::id(), &requirement(identifier, &team)?)?;
    Ok(team)
}

fn frame(stream: &mut impl Write, body: &[u8]) -> io::Result<()> {
    stream.write_all(&(body.len() as u32).to_be_bytes())?;
    stream.write_all(body)
}

/// Check first, then immediately emit the first frame. Even the first read is
/// behind the candidate check, so an attack byte cannot be mistaken for a
/// request-parser decision.
fn serve_candidate(
    stream: &mut (impl Read + Write),
    check: impl FnOnce() -> Result<()>,
) -> Result<()> {
    check()?;
    frame(stream, FIRST)?;
    let mut header = [0; 4];
    stream.read_exact(&mut header)?;
    let size = u32::from_be_bytes(header) as usize;
    if size > 256 * 1024 {
        return Err(fail("oversize probe request"));
    }
    let mut body = vec![0; size];
    stream.read_exact(&mut body)?;
    if body != REQUEST {
        return Err(fail("unexpected probe request"));
    }
    Ok(())
}

fn helper() -> Result<()> {
    let team = own_team(HELPER)?;
    let required = requirement(SIGNED, &team)?;
    // SAFETY: spawn_barred_socket gives the helper sole ownership of fd 3.
    let mut channel = unsafe { UnixStream::from_raw_fd(3) };
    channel.set_read_timeout(Some(TIMEOUT))?;
    channel.set_write_timeout(Some(TIMEOUT))?;
    let token = transport::peer_token(&channel)?;
    serve_candidate(
        &mut channel,
        || match crate::code_signing::audit_token_satisfies_requirement(token, &required) {
            Ok(RequirementCheck::Satisfied) => Ok(()),
            other => Err(fail(format!("LOCAL_PEERTOKEN refused: {other:?}"))),
        },
    )
}

fn spawn_helper(path: &Path, team: &str) -> Result<(BarredChild, UnixStream)> {
    let (child, channel) = spawn_barred_socket(path, &[FLAG.into(), "--helper".into()])
        .map_err(|e| fail(format!("helper spawn failed: {e:?}")))?;
    // Failure drops the barred handle, killing the mapped image unreleased.
    check_pid(child.generation().pid, &requirement(HELPER, team)?)?;
    Ok((child, channel))
}

fn sibling(name: &str) -> Result<PathBuf> {
    let executable = std::env::current_exe()?;
    Ok(executable
        .parent()
        .ok_or_else(|| fail("no executable directory"))?
        .join(name))
}

fn command(path: &Path, mode: &str) -> Command {
    let mut command = Command::new(path);
    command.args([FLAG, mode]).env_clear().stderr(Stdio::null());
    command
}

struct ReapedChild(Child);
impl Drop for ReapedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn read_marker(stream: &mut UnixStream, expected: u8) -> Result<()> {
    let mut byte = [0];
    stream.read_exact(&mut byte)?;
    if byte[0] != expected {
        return Err(fail("invalid coordination marker"));
    }
    Ok(())
}

fn observe_verdict(
    wait: impl FnOnce(Duration),
    mut live: impl FnMut() -> Result<()>,
    read: impl FnOnce() -> Result<bool>,
) -> Result<bool> {
    wait(WAIT);
    live()?;
    let wrote = read()?;
    live()?;
    Ok(wrote)
}

fn channel_has_byte(channel: &mut UnixStream) -> Result<bool> {
    channel.set_nonblocking(true)?;
    match channel.read(&mut [0]) {
        Ok(0) => Ok(false),
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Main entry for every role. The OS account and console owner are checked
/// before signatures, descriptor adoption, child creation, or scratch writes.
pub fn run() -> Result<()> {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let account = Command::new("/usr/bin/id")
        .arg("-un")
        .env_clear()
        .output()?;
    if !account.status.success() {
        return Err(fail("OS account lookup failed"));
    }
    let uid = transport::uid()?;
    guard(
        args.first().is_some_and(|a| a == FLAG),
        std::str::from_utf8(&account.stdout)?.trim(),
        uid,
        std::fs::metadata("/dev/console")?.uid(),
    )?;
    let mode = args.get(1).and_then(|a| a.to_str()).unwrap_or("");
    match mode {
        "--helper" => helper(),
        "--exec-attack" | "--write-attack" | "--unsigned-control" => {
            unsigned_worker(mode, &args[2..])
        }
        "--signed-wait" | "--version" => signed_wait(mode, &args[2..]),
        "--legitimate" => {
            legitimate(&own_team(SIGNED)?)?;
            std::io::stdout().write_all(b"legitimate-first-frame\n")?;
            Ok(())
        }
        "--run" => rig(),
        _ => Err(fail(
            "unknown probe mode; use --scratch-peer-identity --run",
        )),
    }
}

fn signed_wait(mode: &str, cleanup: &[OsString]) -> Result<()> {
    own_team(SIGNED)?;
    // SAFETY: the rig supplies a separate coordination socket as stdin.
    let mut control = unsafe { UnixStream::from_raw_fd(0) };
    control.set_read_timeout(Some(Duration::from_secs(60)))?;
    if mode == "--version" {
        read_marker(&mut control, b'G')?;
        // This is deliberately a signed write to the attack socket, not an
        // authentication exchange. Stay alive after stdout has been flushed.
        std::io::stdout().write_all(b"ckdev-cerebellum peer-identity stand-in\n")?;
        std::io::stdout().flush()?;
    }
    control.write_all(b"R")?;
    let outcome = (|| loop {
        let mut byte = [0];
        control.read_exact(&mut byte)?;
        match byte[0] {
            b'P' => control.write_all(b"A")?,
            b'Q' => return Ok(()),
            _ => return Err(fail("invalid signed-wait coordination marker")),
        }
    })();
    if mode == "--signed-wait" {
        let helper = parse_pid(cleanup.first())?;
        let guardian = parse_pid(cleanup.get(1))?;
        transport::reap(guardian)?;
        transport::terminate_and_reap(helper)?;
    }
    outcome
}

fn parse_pid(value: Option<&OsString>) -> Result<u32> {
    let pid: u32 = value
        .and_then(|s| s.to_str())
        .ok_or_else(|| fail("missing pid"))?
        .parse()?;
    if pid == 0 || pid > i32::MAX as u32 {
        return Err(fail("invalid pid"));
    }
    Ok(pid)
}

fn require_unsigned() -> Result<()> {
    let identity = code_signing_identity(std::process::id(), TIMEOUT)
        .map_err(|e| fail(format!("unsigned identity: {e:?}")))?;
    if identity.team_id.is_some() || (identity.signed && !identity.ad_hoc) {
        return Err(fail(
            "attack launcher must be unsigned or linker/ad-hoc signed",
        ));
    }
    Ok(())
}

fn unsigned_worker(mode: &str, args: &[OsString]) -> Result<()> {
    require_unsigned()?;
    let team = args
        .first()
        .and_then(|s| s.to_str())
        .ok_or_else(|| fail("missing team"))?;
    let (child, mut channel) = spawn_helper(&sibling(HELPER)?, team)?;
    let helper_pid = child.generation().pid;
    let guardian_pid = child.desk_probe_guardian_pid();
    let release = child
        .desk_probe_release_command()
        .map_err(|e| fail(format!("{e:?}")))?;
    frame(&mut channel, REQUEST)?;
    // SAFETY: Command supplied the attack worker's independent control on stdin.
    let mut control = unsafe { UnixStream::from_raw_fd(0) };
    control.set_read_timeout(Some(Duration::from_secs(60)))?;
    let mut signed_writer = None;
    let mut readiness = None;
    if mode == "--write-attack" {
        let (parent, writer) = UnixStream::pair()?;
        signed_writer = Some(ReapedChild(
            command(&sibling(SIGNED)?, "--version")
                .stdin(Stdio::from(OwnedFd::from(writer)))
                .stdout(Stdio::from(OwnedFd::from(channel.try_clone()?)))
                .spawn()?,
        ));
        readiness = Some(parent);
    }
    let writer_pid = signed_writer
        .as_ref()
        .map_or(std::process::id(), |c| c.0.id());
    let mut fds = vec![channel.as_raw_fd(), release.as_raw_fd()];
    if let Some(ready) = &readiness {
        fds.push(ready.as_raw_fd());
    }
    transport::send_fds(&control, &fds)?;
    for pid in [helper_pid, guardian_pid, writer_pid] {
        control.write_all(&pid.to_be_bytes())?;
    }
    drop(release);
    drop(readiness);
    if mode == "--exec-attack" {
        // The unsigned accomplice must finish adopting its copies before exec
        // begins. After this marker it touches only the separate control pipe
        // until the full verdict wait has elapsed.
        read_marker(&mut control, b'G')?;
        // Keep the launcher's original endpoint across exec; the accomplice
        // already holds its copy. The signed image never touches this endpoint.
        transport::inheritable(channel.as_raw_fd(), true)?;
        let error = command(&sibling(SIGNED)?, "--signed-wait")
            .args([helper_pid.to_string(), guardian_pid.to_string()])
            .stdout(Stdio::null())
            .exec();
        return Err(error.into());
    }
    if mode == "--unsigned-control" {
        control.write_all(b"R")?;
    }
    // After the signed writer is allowed to start, the unsigned owner does
    // nothing with its launcher end until the accomplice has read the verdict.
    let outcome = read_marker(&mut control, b'Q');
    drop(channel);
    // The accomplice already commanded the guardian, so the original owner's
    // terminal cleanup can report a closed command pipe after reaping both.
    let _ = child.terminate_and_reap();
    if let Some(mut writer) = signed_writer {
        if !writer.0.wait()?.success() {
            return Err(fail("signed writer failed"));
        }
    }
    outcome
}

fn read_metadata(control: &mut UnixStream) -> Result<[u32; 3]> {
    let mut values = [0; 3];
    for value in &mut values {
        let mut bytes = [0; 4];
        control.read_exact(&mut bytes)?;
        *value = u32::from_be_bytes(bytes);
    }
    Ok(values)
}

fn attack(mode: &str, team: &str) -> Result<bool> {
    let (mut control, worker_control) = UnixStream::pair()?;
    control.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut worker = ReapedChild(
        command(&sibling(UNSIGNED)?, mode)
            .arg(team)
            .stdin(Stdio::from(OwnedFd::from(worker_control)))
            .stdout(Stdio::null())
            .spawn()?,
    );
    let mut fds = transport::recv_fds(&control, if mode == "--write-attack" { 3 } else { 2 })?;
    let [_helper_pid, _guardian_pid, signed_pid] = read_metadata(&mut control)?;
    let mut ready = if mode == "--write-attack" {
        let mut socket = UnixStream::from(fds.pop().ok_or_else(|| fail("no ready fd"))?);
        socket.set_read_timeout(Some(TIMEOUT))?;
        socket.write_all(b"G")?;
        socket
    } else {
        control.try_clone()?
    };
    let release = fds.pop().ok_or_else(|| fail("no release fd"))?;
    let mut channel = UnixStream::from(fds.pop().ok_or_else(|| fail("no channel fd"))?);
    if mode == "--exec-attack" {
        control.write_all(b"G")?;
    }
    read_marker(&mut ready, b'R')?;
    let required = requirement(SIGNED, team)?;
    let signed_generation = if mode != "--unsigned-control" {
        Some(check_pid(signed_pid, &required)?)
    } else {
        None
    };
    if signed_generation.is_some() {
        ready.write_all(b"P")?;
        read_marker(&mut ready, b'A')?;
    }
    // The readiness marker is sent by the exec'd image, or after the signed
    // stdout write. Only this accomplice now commands the guardian to resume.
    std::fs::File::from(release).write_all(b"R")?;
    // No read, write, or socket query on this copy occurs before the 10 s wait.
    let wrote = observe_verdict(
        std::thread::sleep,
        || {
            if let Some(generation) = signed_generation {
                if check_pid(signed_pid, &required)? != generation {
                    return Err(fail(
                        "INVALID signed stand-in exited or changed during verdict",
                    ));
                }
                ready.write_all(b"P")?;
                read_marker(&mut ready, b'A')?;
            }
            Ok(())
        },
        || channel_has_byte(&mut channel),
    )?;
    if mode == "--write-attack" {
        ready.write_all(b"Q")?;
    }
    control.write_all(b"Q")?;
    if !worker.0.wait()?.success() {
        return Err(fail("attack worker failed"));
    }
    Ok(wrote)
}

fn legitimate(team: &str) -> Result<()> {
    let (child, mut channel) = spawn_helper(&sibling(HELPER)?, team)?;
    let child = child.release().map_err(|e| fail(format!("{e:?}")))?;
    channel.set_read_timeout(Some(TIMEOUT))?;
    let mut expected = Vec::new();
    frame(&mut expected, FIRST)?;
    let mut actual = vec![0; expected.len()];
    channel.read_exact(&mut actual)?;
    if actual != expected {
        return Err(fail("legitimate control did not read the first frame"));
    }
    frame(&mut channel, REQUEST)?;
    child.wait().map_err(|e| fail(format!("{e:?}")))?;
    Ok(())
}

fn swapped_helper(team: &str) -> Result<()> {
    let directory = sibling(&format!("peer-swap-{}", std::process::id()))?;
    std::fs::create_dir(&directory)?;
    struct Remove(PathBuf);
    impl Drop for Remove {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _remove = Remove(directory.clone());
    let path = directory.join(HELPER);
    std::fs::copy(sibling(HELPER)?, &path)?;
    let required = requirement(HELPER, team)?;
    if bundle_code_satisfies_requirement(&path, &required, TIMEOUT)
        .map_err(|e| fail(format!("{e:?}")))?
        != RequirementCheck::Satisfied
    {
        return Err(fail(
            "swap control's initial helper was not signed as expected",
        ));
    }
    // Replace the verified file before exec. The mapped-image check, not that
    // earlier path check, must refuse it. No request is sent in this control.
    let replacement = directory.join("replacement");
    std::fs::copy(sibling(UNSIGNED)?, &replacement)?;
    std::fs::rename(replacement, &path)?;
    let (child, mut channel) = spawn_barred_socket(&path, &[FLAG.into(), "--helper".into()])
        .map_err(|e| fail(format!("{e:?}")))?;
    if check_pid(child.generation().pid, &required).is_ok() {
        return Err(fail("swapped helper unexpectedly verified"));
    }
    child
        .terminate_and_reap()
        .map_err(|e| fail(format!("{e:?}")))?;
    if channel_has_byte(&mut channel)? {
        return Err(fail("swapped helper wrote a byte"));
    }
    Ok(())
}

fn rig() -> Result<()> {
    // No signed accomplice may hold a channel copy: otherwise an attack pass
    // could be explained by that additional authorized holder.
    require_unsigned()?;
    let signed_path = sibling(SIGNED)?;
    let identity = bundle_code_signing_identity(&signed_path, TIMEOUT)
        .map_err(|e| fail(format!("signed stand-in unavailable: {e:?}")))?;
    let team = identity
        .team_id
        .filter(|_| identity.signed && !identity.ad_hoc)
        .ok_or_else(|| fail("the stand-in requires a team certificate signature"))?;
    if bundle_code_satisfies_requirement(&signed_path, &requirement(SIGNED, &team)?, TIMEOUT)
        .map_err(|e| fail(format!("{e:?}")))?
        != RequirementCheck::Satisfied
    {
        return Err(fail(
            "stand-in does not have the expected signing identifier",
        ));
    }
    let control = command(&signed_path, "--legitimate").output()?;
    if !control.status.success() || control.stdout != b"legitimate-first-frame\n" {
        return Err(fail("FAIL control-legitimate first-frame=missing"));
    }
    println!("PASS control-legitimate first-frame=received");
    if attack("--unsigned-control", &team)? {
        return Err(fail("FAIL control-unsigned helper-byte=yes"));
    }
    println!("PASS control-unsigned helper-byte=no wait=10s");
    swapped_helper(&team)?;
    println!("PASS control-swapped-helper released=no request-sent=no");
    for (mode, label) in [
        ("--exec-attack", "attack-exec"),
        ("--write-attack", "attack-version-write"),
    ] {
        if attack(mode, &team)? {
            // A byte, including any part of hello, ends the experiment. There
            // is no alternative identity check or fallback launch path.
            return Err(fail(format!(
                "FAIL {label} helper-byte=yes; candidate rejected; no fallback"
            )));
        }
        println!("PASS {label} helper-byte=no wait=10s signed-alive=yes");
    }
    println!("PASS peer-identity candidate: both attacks silent; both controls passed");
    Ok(())
}

#[cfg(test)]
mod tests;
