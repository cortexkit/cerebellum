//! What does the browser liveness check read for a capture-style Chrome?
//!
//! `browser.capture_login` asks, on every poll of its handoff, whether the
//! capture browser has exited, and an answer of "exited" ends the handoff at
//! once. This probe launches Chrome the way the capture does (the same
//! `browser_launch_arguments`, through the same suspended spawn and release),
//! then prints, for a few seconds, the raw start-time reading the liveness
//! check is built on next to the generation recorded at spawn. Run it from a
//! binary signed with hardened runtime and from an unhardened control copy
//! (see `docs/hardened-runtime.md`) to see whether hardening changes the read.
//!
//! `PROBE_HEADLESS=1` adds `--headless=new` so no window opens; without it a
//! visible window opens, so run that only with the operator's permission.
//! `PROBE_SECONDS` sets how long to watch (default 8).
//!
//! ```text
//! PROBE_HEADLESS=1 cargo run -p cerebellum --example capture_liveness_probe
//! ```

#[cfg(target_os = "macos")]
use std::ffi::OsString;
#[cfg(target_os = "macos")]
use std::io::{Read, Write};
#[cfg(target_os = "macos")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "macos")]
use std::os::unix::net::UnixStream;
#[cfg(target_os = "macos")]
use std::path::PathBuf;
#[cfg(target_os = "macos")]
use std::time::{Duration, Instant};

#[cfg(target_os = "macos")]
fn send(pipe: &mut UnixStream, value: serde_json::Value) {
    let mut bytes = serde_json::to_vec(&value).expect("json");
    bytes.push(0);
    pipe.write_all(&bytes).expect("write");
}

#[cfg(target_os = "macos")]
fn recv(pipe: &mut UnixStream, want: u64, buffer: &mut Vec<u8>) -> serde_json::Value {
    loop {
        if let Some(at) = buffer.iter().position(|byte| *byte == 0) {
            let frame: Vec<u8> = buffer.drain(..=at).collect();
            let value: serde_json::Value =
                serde_json::from_slice(&frame[..frame.len() - 1]).expect("frame json");
            if value.get("id").and_then(serde_json::Value::as_u64) == Some(want) {
                return value;
            }
            continue;
        }
        let mut chunk = [0u8; 65536];
        let read = pipe.read(&mut chunk).expect("read");
        assert!(read > 0, "pipe closed awaiting {want}");
        buffer.extend_from_slice(&chunk[..read]);
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("this probe reads macOS process start times and has nothing to run here");
}

#[cfg(target_os = "macos")]
fn main() {
    let chrome = PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
    if !chrome.is_file() {
        println!("skipped: no Chrome at {}", chrome.display());
        return;
    }
    let headless = std::env::var("PROBE_HEADLESS").is_ok_and(|value| value == "1");
    let seconds = std::env::var("PROBE_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(8);
    let profile = std::env::temp_dir().join(format!("ck-liveness-probe-{}", std::process::id()));
    std::fs::create_dir_all(&profile).expect("profile dir");
    let mut arguments = cerebellum::browser_launch_service::browser_launch_arguments(
        &profile,
        &profile.join("crash-dumps"),
    );
    if headless {
        arguments.push(OsString::from("--headless=new"));
    }

    let (command_child, mut command_parent) = UnixStream::pair().expect("command pair");
    let (mut response_parent, response_child) = UnixStream::pair().expect("response pair");
    let barred = cerebellum_macos::spawn_barred(
        &chrome,
        &arguments,
        &[],
        command_child.as_raw_fd(),
        response_child.as_raw_fd(),
    )
    .expect("spawn barred");
    let recorded = barred.generation();
    println!(
        "self pid={} recorded generation pid={} start_time_micros={}",
        std::process::id(),
        recorded.pid,
        recorded.start_time_micros
    );
    println!(
        "while barred: {:?}",
        cerebellum_macos::process_start_time(recorded.pid)
    );
    let released = barred.release().expect("release");
    drop(command_child);
    drop(response_child);
    println!(
        "after release: {:?} (released generation pid={} start={})",
        cerebellum_macos::process_start_time(recorded.pid),
        released.generation().pid,
        released.generation().start_time_micros
    );

    let mut buffer = Vec::new();
    send(
        &mut command_parent,
        serde_json::json!({"id":1,"method":"Browser.getVersion"}),
    );
    let version = recv(&mut response_parent, 1, &mut buffer);
    println!("browser: {}", version["result"]["product"]);
    send(
        &mut command_parent,
        serde_json::json!({"id":2,"method":"Target.createTarget","params":{"url":"https://example.com/"}}),
    );
    let _ = recv(&mut response_parent, 2, &mut buffer);

    let started = Instant::now();
    let mut mismatches = 0;
    let mut reads = 0;
    while started.elapsed() < Duration::from_secs(seconds) {
        let reading = cerebellum_macos::process_start_time(recorded.pid);
        let verdict = match reading {
            cerebellum_macos::ProcessStartTime::Started(start)
                if start == recorded.start_time_micros =>
            {
                "live"
            }
            cerebellum_macos::ProcessStartTime::Started(_)
            | cerebellum_macos::ProcessStartTime::NoSuchProcess => "gone",
            _ => "unreadable",
        };
        if verdict != "live" {
            mismatches += 1;
        }
        reads += 1;
        println!(
            "t={:>5}ms reading={reading:?} -> {verdict}",
            started.elapsed().as_millis()
        );
        std::thread::sleep(Duration::from_millis(500));
    }
    println!("VERDICT: {mismatches} of {reads} reads did not say live");
    let _ = released.terminate_and_reap();
    let _ = std::fs::remove_dir_all(&profile);
}
