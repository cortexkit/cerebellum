//! Read the production development-build identity and signature checks for a PID.
//!
//! Run on the host where the app runs:
//! `cargo run --locked -p cerebellum --example development_build_probe -- 30601`
//!
//! This probe neither drives the app nor requests consent. It uses an ephemeral
//! management plane with in-memory grant stores, not the live config or journal.
//! In signature errors, `error` is the Debug representation; `detail` is the raw
//! detail for `Failed` errors and null for other kinds. The probe does not check an
//! invoking agent's identity or authority to drive development builds.

#[cfg(target_os = "macos")]
fn main() -> std::process::ExitCode {
    use std::sync::Arc;

    use cerebellum::computer_capability::development_build_snapshot;
    use cerebellum::management::{ManagementPlane, PlatformResolver};

    let mut args = std::env::args().skip(1);
    let pid = args
        .next()
        .and_then(|argument| argument.parse::<u32>().ok())
        .filter(|pid| *pid > 0 && *pid <= i32::MAX as u32);
    let Some(pid) = pid.filter(|_| args.next().is_none()) else {
        eprintln!("usage: development_build_probe <positive-pid>");
        return std::process::ExitCode::from(2);
    };

    let management = ManagementPlane::new(Arc::new(PlatformResolver::new()));
    let Some(grant) = management.process_for_pid(pid) else {
        eprintln!(
            "process_for_pid({pid}) returned None: the production resolver could not find \
             start-time evidence, could not enumerate windows, or found no window owned by that PID"
        );
        return std::process::ExitCode::FAILURE;
    };
    let snapshot = development_build_snapshot(&management, &grant);
    println!("{}", serde_json::to_string_pretty(&snapshot).unwrap());
    std::process::ExitCode::SUCCESS
}

#[cfg(not(target_os = "macos"))]
fn main() -> std::process::ExitCode {
    eprintln!("development_build_probe requires macOS");
    std::process::ExitCode::from(2)
}
