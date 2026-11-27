use crate::relay::{establish_session, relay, RelayEnd};
use cerebellum_bridge_protocol::{ParentAttestation, CEREBELLUM_REQUIREMENT};
use cerebellum_macos::{parent_satisfies_chrome_requirement, peer_satisfies_requirement};
use std::ffi::c_int;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::Duration;

const SIGNATURE_TIMEOUT: Duration = Duration::from_secs(3);

extern "C" {
    fn getpeereid(socket: c_int, uid: *mut u32, gid: *mut u32) -> c_int;
    fn geteuid() -> u32;
}

pub(crate) fn run() -> io::Result<()> {
    let ended = session();
    #[cfg(feature = "chrome-for-testing-parent-probe")]
    record_probe_exit(&match &ended {
        Ok(end) => end.to_string(),
        Err(error) => format!("session setup failed: {error}"),
    });
    ended?.into_result()
}

fn session() -> io::Result<RelayEnd> {
    let origin = crate::extension_origin(std::env::args_os())?;
    let (socket, epoch) = establish_session(
        origin,
        check_parent,
        || {
            let path = cortexkit_paths::cortexkit_run_dir()
                .map_err(io::Error::other)?
                .join("cerebellum/user-browser.sock");
            UnixStream::connect(path)
        },
        check_server,
    )?;
    Ok(relay(socket, epoch, io::stdin(), &mut io::stdout().lock()))
}

/// Name of the exit record, beside the bridge socket in the private
/// `cerebellum` run directory. The live probe reads this same file name from
/// its scratch tree (`user_browser_probe.rs`, `HOST_EXIT_LOG`).
#[cfg(feature = "chrome-for-testing-parent-probe")]
const PROBE_EXIT_LOG: &str = "native-host-exit.log";

/// Development probe builds only: append why this host process ended, because
/// a shipped host is silent (stdout carries native-messaging frames, and Chrome
/// discards stderr) and the probe otherwise cannot tell which side closed the
/// port. The probe runs with a scratch XDG_DATA_HOME, so this lands in its
/// scratch directory next to the scratch socket. Failures are ignored: the
/// record is evidence for a person, never part of the relay.
#[cfg(feature = "chrome-for-testing-parent-probe")]
fn record_probe_exit(reason: &str) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let Ok(run) = cortexkit_paths::cortexkit_run_dir() else {
        return;
    };
    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(run.join("cerebellum").join(PROBE_EXIT_LOG))
    else {
        return;
    };
    let _ = writeln!(file, "native host pid {}: {reason}", std::process::id());
}

fn check_parent() -> io::Result<ParentAttestation> {
    match parent_satisfies_chrome_requirement(SIGNATURE_TIMEOUT) {
        Ok(parent) => Ok(ParentAttestation {
            team_id: Some("EQHXZ8M8AV".into()),
            probe_cdhash: None,
            pid: parent.pid,
            start_time_micros: parent.start_time_micros,
        }),
        Err(error) => {
            #[cfg(feature = "chrome-for-testing-parent-probe")]
            {
                let _ = error;
                let parent =
                    cerebellum_macos::parent_satisfies_chrome_for_testing_probe_requirement(
                        SIGNATURE_TIMEOUT,
                    )
                    .map_err(io::Error::other)?;
                Ok(ParentAttestation {
                    team_id: None,
                    probe_cdhash: Some("8f2a5ce4af6d1cd71fe66113dd809e4d106c3106".into()),
                    pid: parent.pid,
                    start_time_micros: parent.start_time_micros,
                })
            }
            #[cfg(not(feature = "chrome-for-testing-parent-probe"))]
            {
                Err(io::Error::other(error))
            }
        }
    }
}

fn check_server(socket: &UnixStream) -> io::Result<()> {
    let (mut uid, mut gid) = (0, 0);
    // SAFETY: the descriptor is live and the output pointers name writable u32s.
    if unsafe { getpeereid(socket.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: geteuid has no arguments or borrowed memory.
    if uid != unsafe { geteuid() } {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "server uid",
        ));
    }
    peer_satisfies_requirement(socket, CEREBELLUM_REQUIREMENT, SIGNATURE_TIMEOUT)
        .map_err(io::Error::other)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::net::UnixListener;

    #[test]
    fn unsigned_stand_in_server_receives_no_frames_with_the_real_peer_check() {
        let directory =
            std::env::temp_dir().join(format!("ck-native-host-server-{}", std::process::id()));
        cerebellum_core::private_fs::create_dir(&directory).unwrap();
        let path = directory.join("socket");
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut bytes = Vec::new();
            socket.read_to_end(&mut bytes).unwrap();
            bytes
        });
        // Only the Chrome-parent gate is supplied by the fixture. The actual
        // kernel peer pid, uid and signing requirement checks remain in place.
        let result = establish_session(
            "chrome-extension://abcdefghijklmnopabcdefghijklmnop/".into(),
            || {
                Ok(ParentAttestation {
                    team_id: Some("EQHXZ8M8AV".into()),
                    probe_cdhash: None,
                    pid: 1,
                    start_time_micros: 1,
                })
            },
            || UnixStream::connect(&path),
            check_server,
        );
        assert!(result.is_err());
        assert!(server.join().unwrap().is_empty());
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&directory).unwrap();
    }
}
