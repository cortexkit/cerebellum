//! Check that the frontmost-application reading stays fresh on the host it
//! runs on.
//!
//! A workspace reading taken in a process with no run loop can go stale after
//! its first answer. This reads the frontmost pid for twenty seconds while
//! something else switches applications, and prints every change beside the
//! AppleScript answer at that moment.
//!
//! Run: `cargo run -p cerebellum-macos --example observed_stage_cost`

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("macOS only");
}

#[cfg(target_os = "macos")]
fn main() {
    use cerebellum_macos::frontmost_process_id;
    use std::time::Instant;

    println!(
        "accessibility_is_permitted (AXIsProcessTrusted) = {}",
        cerebellum_macos::accessibility_is_permitted()
    );
    println!("frontmost pid for 20 s (switch apps now); a stale reader prints one line:");
    let started = Instant::now();
    let mut last = None;
    while started.elapsed() < std::time::Duration::from_secs(20) {
        let now = frontmost_process_id();
        if now.is_none() {
            println!(
                "  focus read refused: {:?}",
                cerebellum_macos::focused_application_pid()
            );
            break;
        }
        if now != last {
            let script = std::process::Command::new("/usr/bin/osascript")
                .args([
                    "-e",
                    "tell application \"System Events\" to get unix id of first process whose frontmost is true",
                ])
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
            println!(
                "  {:>6} ms  workspace={now:?}  applescript={script:?}",
                started.elapsed().as_millis()
            );
            last = now;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}
