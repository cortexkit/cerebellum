//! Resolve an application name on a live Windows machine through the same
//! path `computer.open_target` uses.
//!
//! This lives in the computer crate rather than the seam so it can call the
//! production resolver. A probe that reimplemented the decision -- counting
//! instances, deciding ambiguity, gating on session -- would be a second copy
//! of a rule, and a second copy is exactly what drifts while the tests on the
//! first stay green. The reading is printed in full beside the decision so an
//! operator can check one against the other without the source open.
//!
//! Usage: `live_resolve <executable-basename>`
//!
//! Expected on the console session: one Notepad -> Resolved; two -> Ambiguous
//! with both pids and window counts; a name not running -> NotRunning. From a
//! service session the same command must refuse by provenance, because the
//! service desktop's window list is true and describes nothing the operator
//! can see.

#[cfg(target_os = "windows")]
fn main() {
    use cerebellum_computer::platform::{windows::resolve_target, TargetResolution};
    use cerebellum_windows::{
        current_session_provenance, enumerate_top_level_windows, TopLevelWindowOwner,
        WindowListCompleteness,
    };

    let Some(identity) = std::env::args().nth(1) else {
        eprintln!("usage: live_resolve <executable-basename>");
        std::process::exit(2);
    };
    let identity = identity.to_lowercase();
    // `--all` prints every owner, matching or not. Needed when a name does
    // not resolve and the question is what the reading DID see -- a UWP app's
    // window is attributed to some process, and this shows which.
    let print_all = std::env::args().any(|arg| arg == "--all");

    println!("session: {:?}", current_session_provenance());

    // The raw reading, so the decision below can be checked against it.
    match enumerate_top_level_windows() {
        Ok(reading) => {
            let mut named = 0;
            for window in &reading.windows {
                match window {
                    TopLevelWindowOwner::Named {
                        pid,
                        executable_basename,
                    } => {
                        named += 1;
                        if executable_basename == &identity {
                            println!(
                                "  window owned by pid {pid} ({executable_basename}) <- matches"
                            );
                        } else if print_all {
                            println!("  window owned by pid {pid} ({executable_basename})");
                        }
                    }
                    TopLevelWindowOwner::Unreadable(reason) => {
                        println!("  window with unreadable owner: {reason:?}");
                    }
                }
            }
            println!(
                "reading: {} windows, {} with named owners, completeness {:?}",
                reading.windows.len(),
                named,
                reading.completeness
            );
            if let WindowListCompleteness::Partial { unreadable_owners } = reading.completeness {
                println!(
                    "  ({unreadable_owners} owners unreadable, so an absence below is not a claim)"
                );
            }
        }
        Err(error) => println!("reading failed: {error:?}"),
    }

    match resolve_target(&identity) {
        TargetResolution::Resolved(grant) => println!(
            "decision: Resolved pid={} generation={}",
            grant.pid, grant.process_generation_evidence
        ),
        TargetResolution::Ambiguous(candidates) => {
            let parts: Vec<String> = candidates
                .iter()
                .map(|c| format!("pid {} ({} windows)", c.pid, c.window_count))
                .collect();
            println!("decision: Ambiguous -- {}", parts.join("; "));
        }
        TargetResolution::NotRunning => println!("decision: NotRunning"),
        TargetResolution::Unreadable => {
            println!("decision: Unreadable (the module could not look; from a service session this is the provenance refusal)")
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("this probe resolves a Windows application name and does nothing elsewhere");
}
