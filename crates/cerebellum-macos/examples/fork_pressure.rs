//! Does the launch barrier survive being used from a heavily threaded process?
//!
//! The module runs a multithreaded async runtime, and `spawn_barred` forks.
//! `fork()` clones only the calling thread, so any lock another thread held at
//! that instant stays locked forever in the child — and the child then calls
//! `posix_spawn`, which is not guaranteed safe in that state. A test binary is
//! threaded too, which is why this shows up as a load-dependent flake rather
//! than a clean failure.

use std::ffi::OsString;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

fn main() {
    let threads: usize = std::env::args()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .unwrap_or(64);
    let attempts: usize = std::env::args()
        .nth(2)
        .and_then(|value| value.parse().ok())
        .unwrap_or(200);

    // Touch the macOS frameworks BEFORE forking when asked. This is the
    // difference between the two runs that matters: plain Rust threads churning
    // allocations never reproduced the failure, while the full suite — where
    // launch tests share a process with window-server and accessibility work —
    // does. CoreFoundation and its neighbours register fork handlers and keep
    // mach port state, and a child that forks after that state exists is in a
    // different position from one that forks before it.
    let warm = std::env::args().any(|argument| argument == "--warm-frameworks");
    if warm {
        let permitted = cerebellum_macos::screen_capture_is_permitted();
        let windows = cerebellum_macos::enumerate_windows(Duration::from_secs(5));
        let trusted = cerebellum_macos::accessibility_is_permitted();
        println!(
            "frameworks warmed: capture_permitted={permitted} windows={} accessibility={trusted}",
            windows.map(|list| list.len()).unwrap_or(0)
        );
    }

    let stop = Arc::new(AtomicBool::new(false));
    let churn = Arc::new(AtomicU64::new(0));
    let mut workers = Vec::new();
    let framework_churn = std::env::args().any(|argument| argument == "--framework-churn");
    for _ in 0..threads {
        let stop = Arc::clone(&stop);
        let churn = Arc::clone(&churn);
        workers.push(std::thread::spawn(move || {
            // Two kinds of pressure, because they are not the same experiment.
            // Allocation churn holds and releases allocator locks, which is what
            // a busy runtime does. Framework churn keeps window-server and
            // accessibility calls IN FLIGHT while the fork happens, which is the
            // condition the full suite creates and the isolated launch tests
            // never do — and prior warming alone did not reproduce anything.
            while !stop.load(Ordering::Relaxed) {
                if framework_churn {
                    let _ = cerebellum_macos::enumerate_windows(Duration::from_secs(2));
                    let _ = cerebellum_macos::screen_capture_is_permitted();
                    churn.fetch_add(1, Ordering::Relaxed);
                } else {
                    let mut v: Vec<String> = Vec::with_capacity(64);
                    for i in 0..64 {
                        v.push(format!("allocation-{i}"));
                    }
                    churn.fetch_add(v.len() as u64, Ordering::Relaxed);
                    drop(v);
                }
            }
        }));
    }

    let shell = PathBuf::from("/bin/sh");
    let args: Vec<OsString> = vec![OsString::from("-c"), OsString::from("exit 0")];
    let mut failures = 0usize;
    let mut kinds: Vec<String> = Vec::new();
    for attempt in 0..attempts {
        let (command_child, _command_parent) = UnixStream::pair().expect("command pair");
        let (_response_parent, response_child) = UnixStream::pair().expect("response pair");
        match cerebellum_macos::spawn_barred(
            &shell,
            &args,
            &[],
            command_child.as_raw_fd(),
            response_child.as_raw_fd(),
        ) {
            Ok(child) => {
                let _ = child.terminate_and_reap();
            }
            Err(error) => {
                failures += 1;
                let text = format!("{error:?}");
                if !kinds.contains(&text) {
                    kinds.push(text.clone());
                }
                if failures <= 3 {
                    eprintln!("attempt {attempt}: {text}");
                }
            }
        }
    }
    stop.store(true, Ordering::Relaxed);
    for worker in workers {
        let _ = worker.join();
    }
    println!("threads={threads} attempts={attempts} failures={failures}");
    println!("distinct failure kinds: {kinds:?}");
    println!(
        "VERDICT: {}",
        if failures == 0 {
            "no failure under thread pressure"
        } else {
            "FORK-UNDER-THREADS REPRODUCES THE FAILURE"
        }
    );
}
