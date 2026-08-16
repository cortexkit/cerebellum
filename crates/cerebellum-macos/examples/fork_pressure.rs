//! Does the launch barrier remain fork-safe in a heavily threaded process?
//!
//! The module runs a multithreaded async runtime. The target must be spawned by
//! that ordinary process before it forks the guardian; the guardian's child-side
//! body may use only async-signal-safe calls. Framework churn and concurrent
//! launch attempts keep the unsafe pre-exec window under pressure.

#[cfg(target_os = "macos")]
use std::ffi::OsString;
#[cfg(target_os = "macos")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "macos")]
use std::os::unix::net::UnixStream;
#[cfg(target_os = "macos")]
use std::path::PathBuf;
#[cfg(target_os = "macos")]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
#[cfg(target_os = "macos")]
use std::sync::Arc;
#[cfg(target_os = "macos")]
use std::time::Duration;

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("this probe stresses the macOS launch barrier under fork pressure and has nothing to run here");
}

#[cfg(target_os = "macos")]
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
    // Launch from SEVERAL threads at once when asked. The suite does this and
    // the earlier runs of this probe did not: libtest runs tests on parallel
    // threads, and more than one launch test creates a guardian, so the real
    // condition is concurrent forks from one process rather than a loop on a
    // single thread. `fork()` clones only the calling thread, so every guardian
    // child must remain safe even while another thread holds a framework lock.
    let concurrent_forkers: usize = std::env::args()
        .position(|argument| argument == "--forkers")
        .and_then(|at| std::env::args().nth(at + 1))
        .and_then(|value| value.parse().ok())
        .unwrap_or(1);

    if concurrent_forkers > 1 {
        let failures = Arc::new(AtomicU64::new(0));
        let each = attempts / concurrent_forkers;
        let mut forkers = Vec::new();
        for _ in 0..concurrent_forkers {
            let shell = shell.clone();
            let args = args.clone();
            let failures = Arc::clone(&failures);
            forkers.push(std::thread::spawn(move || {
                for _ in 0..each {
                    let (command_child, _command_parent) =
                        UnixStream::pair().expect("command pair");
                    let (_response_parent, response_child) =
                        UnixStream::pair().expect("response pair");
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
                            failures.fetch_add(1, Ordering::Relaxed);
                            eprintln!("concurrent fork failed: {error:?}");
                        }
                    }
                }
            }));
        }
        for forker in forkers {
            let _ = forker.join();
        }
        stop.store(true, Ordering::Relaxed);
        for worker in workers {
            let _ = worker.join();
        }
        let failed = failures.load(Ordering::Relaxed);
        println!(
            "forkers={concurrent_forkers} threads={threads} attempts={} failures={failed}",
            each * concurrent_forkers
        );
        println!(
            "VERDICT: {}",
            if failed == 0 {
                "no failure under concurrent forking"
            } else {
                "CONCURRENT FORKING REPRODUCES THE FAILURE"
            }
        );
        return;
    }

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
