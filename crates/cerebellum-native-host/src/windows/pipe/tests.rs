use super::*;

fn busy() -> io::Result<()> {
    Err(io::Error::from_raw_os_error(ERROR_PIPE_BUSY as i32))
}

#[test]
fn a_freed_pipe_is_not_opened_after_the_parent_exits() {
    let alive = Cell::new(true);
    let opens = Cell::new(0);
    let waits = Cell::new(0);
    let error = connect_with(
        Instant::now() + Duration::from_millis(500),
        || {
            if alive.get() {
                Ok(())
            } else {
                Err(io::Error::other("parent exited"))
            }
        },
        || {
            opens.set(opens.get() + 1);
            if alive.get() {
                busy()
            } else {
                Ok(())
            }
        },
        |_| {
            waits.set(waits.get() + 1);
            alive.set(false);
            Ok(())
        },
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "parent exited");
    assert_eq!((opens.get(), waits.get()), (1, 1));
}

#[test]
fn busy_retries_do_not_restart_the_connect_deadline() {
    let waits = Cell::new(0);
    let opens = Cell::new(0);
    let began = Instant::now();
    let error = connect_with(
        began + Duration::from_millis(500),
        || Ok(()),
        || {
            opens.set(opens.get() + 1);
            busy()
        },
        |remaining| {
            let seen = waits.get();
            waits.set(seen + 1);
            if seen == 0 {
                assert!(remaining.get() <= 500);
                std::thread::sleep(Duration::from_millis(300));
            } else {
                assert!(remaining.get() <= 200, "retry reset the wait: {remaining}");
                // Model an instance becoming free just after the deadline.
                std::thread::sleep(Duration::from_millis(u64::from(remaining.get()) + 2));
            }
            Ok(())
        },
    )
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!((opens.get(), waits.get()), (2, 2));
}

#[cfg(feature = "bridge-test-identities")]
#[test]
fn a_real_busy_pipe_times_out_without_sending_bytes() {
    let (name, (_holder, mut peer)) = test_pipe(1024);
    let began = Instant::now();
    let check_count = Cell::new(0);
    let Err(error) = connect(&name, began + Duration::from_millis(500), || {
        check_count.set(check_count.get() + 1);
        Ok(())
    }) else {
        panic!("connected to a busy pipe");
    };
    assert_eq!(error.kind(), io::ErrorKind::TimedOut, "{error}");
    assert!(began.elapsed() < Duration::from_secs(1));
    assert_eq!(check_count.get(), 1);
    peer.set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    assert_eq!(
        peer.read(&mut [0]).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
}

#[cfg(feature = "bridge-test-identities")]
#[test]
fn each_end_reads_the_real_pipe_peer_before_image_verification() {
    use cerebellum_bridge_protocol::windows::{observe_client_peer, observe_server_peer};
    let (host, peer) = test_pair(1024);
    let observed_connect = cerebellum_windows::system_time_100ns();
    observe_server_peer(host.handle().unwrap().as_ref(), host.timestamp()).unwrap();
    observe_client_peer(peer.handle().unwrap().as_ref(), observed_connect).unwrap();
}
