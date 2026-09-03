//! Print this session's top-level window owners and what `decide` would
//! conclude for a name given on the command line.
//!
//! Usage: `live_resolve <executable-basename>`
//!
//! Run it from an interactive session to see a real desktop. From session 0
//! `EnumWindows` succeeds against the SERVICE desktop; the reading carries
//! session provenance so that outcome is a provenance refusal rather than
//! "that application is not running".
//!
//! This probe prints one `decision:` line for the operator. It does not claim
//! live outcomes: those are measured on the machine that runs it.

#[cfg(target_os = "windows")]
fn main() {
    use std::collections::BTreeMap;

    use cerebellum_windows::{
        current_session_provenance, enumerate_top_level_windows, process_start_time,
        ProcessStartTime, SessionProvenance, TopLevelWindowOwner, WindowListCompleteness,
        WindowOwnerUnreadable,
    };

    let identity = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: live_resolve <executable-basename>");
        std::process::exit(2);
    });
    let identity = identity.to_lowercase();

    let session = current_session_provenance();
    println!("session: {session:?}");

    let reading = match enumerate_top_level_windows() {
        Ok(reading) => reading,
        Err(error) => {
            println!("reading: enumeration failed: {error:?}");
            println!("decision: Unreadable");
            std::process::exit(1);
        }
    };

    println!("reading session: {:?}", reading.session);
    println!("window_count: {}", reading.windows.len());
    match reading.completeness {
        WindowListCompleteness::Complete => println!("completeness: Complete"),
        WindowListCompleteness::Partial { unreadable_owners } => {
            println!("completeness: Partial unreadable_owners={unreadable_owners}");
        }
    }
    for window in &reading.windows {
        match window {
            TopLevelWindowOwner::Named {
                pid,
                executable_basename,
            } => println!("window: pid={pid} {executable_basename}"),
            TopLevelWindowOwner::Unreadable(reason) => match reason {
                WindowOwnerUnreadable::ProcessIdUnreadable { last_error } => {
                    println!(
                        "window: pid=? UNREADABLE ProcessIdUnreadable last_error={last_error}"
                    );
                }
                WindowOwnerUnreadable::NoSuchProcess { pid } => {
                    println!("window: pid={pid} UNREADABLE NoSuchProcess");
                }
                WindowOwnerUnreadable::AccessDenied { pid } => {
                    println!("window: pid={pid} UNREADABLE AccessDenied");
                }
                WindowOwnerUnreadable::Unclassified { pid, last_error } => {
                    println!("window: pid={pid} UNREADABLE Unclassified last_error={last_error}");
                }
            },
        }
    }

    println!("identity: {identity}");

    match reading.session {
        SessionProvenance::Console { .. } => {}
        other => {
            println!("decision: provenance refusal {other:?}");
            return;
        }
    }

    // Production resolution calls `TargetResolution::decide` in
    // cerebellum-computer. This seam crate cannot depend on that crate, so the
    // probe prints the same four outcomes from the same inputs: named
    // `(pid, basename)` pairs and `process_start_time` as generation evidence.
    let mut counts: BTreeMap<u32, usize> = BTreeMap::new();
    for window in &reading.windows {
        if let TopLevelWindowOwner::Named {
            pid,
            executable_basename,
        } = window
        {
            if executable_basename == &identity {
                *counts.entry(*pid).or_default() += 1;
            }
        }
    }
    let mut instances = counts.into_iter();
    let Some((pid, window_count)) = instances.next() else {
        println!("decision: NotRunning");
        return;
    };
    let rest: Vec<(u32, usize)> = instances.collect();
    if !rest.is_empty() {
        let mut parts = vec![format!("pid={pid} windows={window_count}")];
        parts.extend(
            rest.into_iter()
                .map(|(pid, window_count)| format!("pid={pid} windows={window_count}")),
        );
        println!("decision: Ambiguous candidates: {}", parts.join("; "));
        return;
    }
    match process_start_time(pid) {
        ProcessStartTime::Started(generation) => {
            println!("decision: Resolved pid={pid} generation={generation}");
        }
        other => {
            println!("decision: NotRunning (start time {other:?} for pid={pid})");
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("this probe enumerates Windows top-level window owners and does nothing elsewhere");
}
