use crate::relay::{establish_session, relay};
use cerebellum_bridge_protocol::windows::{
    attest_parent, current_user_sid, observe_server_peer, VerifyingKey,
};
use cerebellum_bridge_protocol::{classify_bridge_gate, windows_pipe_name};
use std::ffi::OsString;
use std::io;
use std::sync::mpsc;
use std::time::{Duration, Instant};

mod pipe;
#[cfg(feature = "bridge-test-identities")]
mod test_hooks;

const CHECK_TIMEOUT: Duration = Duration::from_secs(1);
const CONNECT_TIMEOUT: Duration = Duration::from_millis(500);

pub(super) fn build_key() -> io::Result<VerifyingKey> {
    classify_bridge_gate(
        option_env!("CEREBELLUM_WINDOWS_USER_BROWSER_REVIEW_REVISION"),
        option_env!("CEREBELLUM_BRIDGE_PEER_PUBLIC_KEY"),
    )
    .ok_or_else(crate::unbound_gate)
}

pub(super) fn run(key: VerifyingKey) -> io::Result<()> {
    let origin = crate::extension_origin(std::env::args_os())?;
    let (parent, name, deadline) = check_on_worker(move || {
        #[cfg(feature = "bridge-test-identities")]
        test_hooks::checkpoint("step-1")?;
        let name = pipe_name()?;
        let parent = attest_parent(&key)?;
        Ok((parent, name, Instant::now() + CONNECT_TIMEOUT))
    })?;
    let (stream, epoch) = establish_session(
        origin,
        || Ok(parent.attestation().clone()),
        || pipe::connect(&name, deadline, || parent.check_before_connect()),
        |connection: &PipeConnection| {
            let handle = connection.handle()?;
            let timestamp = connection.timestamp();
            check_on_worker(move || {
                #[cfg(feature = "bridge-test-identities")]
                test_hooks::checkpoint("step-2")?;
                let peer =
                    observe_server_peer(handle.as_ref(), timestamp).map_err(io::Error::other)?;
                drop(handle);
                peer.verify_cerebellum(&key)
            })
        },
    )?;
    drop(parent);
    relay(stream, epoch, io::stdin(), &mut io::stdout().lock()).into_result()
}

fn pipe_name() -> io::Result<OsString> {
    #[cfg(feature = "bridge-test-identities")]
    if let Some(name) = test_hooks::pipe_override()? {
        return Ok(name);
    }
    Ok(windows_pipe_name(&current_user_sid()?).into())
}

fn check_on_worker<T: Send + 'static>(
    check: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> io::Result<T> {
    let (result, wait) = mpsc::sync_channel(1);
    let deadline = Instant::now() + CHECK_TIMEOUT;
    std::thread::Builder::new()
        .name("native-messaging-identity".into())
        .spawn(move || {
            let _ = result.send(check());
        })?;
    // The worker owns its handles, but cannot connect or send frames. A late
    // verdict has no receiver and does not delay exit from main.
    let result = wait
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|error| match error {
            mpsc::RecvTimeoutError::Timeout => io::Error::new(
                io::ErrorKind::TimedOut,
                "native messaging identity check timed out",
            ),
            mpsc::RecvTimeoutError::Disconnected => {
                io::Error::other("native messaging identity check stopped")
            }
        })?;
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "native messaging identity check timed out",
        ));
    }
    result
}

#[cfg(all(test, feature = "bridge-test-identities"))]
pub(crate) use pipe::test_pair;
use pipe::PipeConnection;
