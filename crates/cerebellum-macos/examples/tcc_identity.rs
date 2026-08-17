//! Report which executable macOS holds responsible for this process's TCC
//! permissions, and what each permission currently answers.
//!
//! WHY THIS EXISTS. A TCC grant attaches to the RESPONSIBLE PROCESS, which is
//! rarely the binary you ran: for a module it is the daemon that launched it,
//! and over SSH it is somewhere in the ssh daemon chain. Adding the wrong
//! executable in System Settings looks identical to adding the right one --
//! the entry appears, the toggle is on, and every call still fails. This
//! prints the name to add.
//!
//! It also separates two states that the permission APIs report identically
//! but which need opposite remedies:
//!
//!   - The grant is missing or attached to the wrong executable. Fix the grant.
//!   - The grant is correct but a long-lived responsible process cached a
//!     "not trusted" answer before it was made. Restart that process.
//!
//! The discriminator is not in this output: run the probe, then check whether
//! tccd logged a request at all.
//!
//!   log show --predicate 'subsystem == "com.apple.TCC"' --last 1m | grep -i accessibility
//!
//! A logged denial means the grant is wrong. NOTHING LOGGED means the answer
//! came from a cache and never reached tccd, so the grant may be perfectly
//! fine and the process holding the stale view is what needs replacing.
//!
//! ```sh
//! cargo run -p cerebellum-macos --example tcc_identity
//! ```

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("this probe reports macOS TCC attribution and has nothing to report here");
}

#[cfg(target_os = "macos")]
fn main() {
    match cerebellum_macos::responsible_process() {
        Some(path) => {
            println!("responsible executable: {path}");
            println!("  ^ this is the path to add in System Settings, not the binary you ran");
        }
        None => println!(
            "responsible executable: UNKNOWN -- macOS did not report one, so no grant can be \
             attributed with confidence"
        ),
    }

    println!(
        "accessibility:  {}",
        answer(cerebellum_macos::accessibility_is_permitted())
    );
    println!(
        "screen capture: {}",
        answer(cerebellum_macos::screen_capture_is_permitted())
    );

    // Reported because an application launched under a locked screen never
    // realises its windows, which reads downstream exactly like a permission
    // failure and has cost this project three misdiagnoses.
    match cerebellum_macos::screen_is_locked() {
        Some(true) => println!(
            "screen:         LOCKED -- an app launched now has no windows, so an empty \
             accessibility tree here means nothing"
        ),
        Some(false) => println!("screen:         unlocked"),
        None => println!("screen:         unknown"),
    }
}

#[cfg(target_os = "macos")]
fn answer(permitted: bool) -> &'static str {
    if permitted {
        "granted"
    } else {
        "DENIED (or cached as denied -- see the module comment)"
    }
}
