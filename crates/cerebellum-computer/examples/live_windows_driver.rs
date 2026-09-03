//! Drive the Windows platform driver against a live process.
//!
//! The seam crate has its own live probes, and its unit tests prove the
//! driver's decisions over constructed readings. What neither reaches is the
//! layer between: the driver calling the seam for real, mapping the neutral
//! `press` intent to the platform's `Invoke`, and reporting through the
//! neutral result types the computer plane consumes. That is what a wiring
//! slice can get subtly wrong while every test stays green, so it is measured
//! here rather than assumed.
//!
//! Usage: `live_windows_driver <pid> [automation_id]`
//!
//! With an automation id, the probe resolves that element through the driver
//! and dispatches `press`, then re-reads to report whether the element is
//! still present. Run it from an interactive session; from a service session
//! the driver must refuse by session rather than read an empty tree.

#[cfg(target_os = "windows")]
fn main() {
    use cerebellum_computer::platform::{
        windows::WindowsPlatformDriver, AccessibilityElementName, AccessibilityTreeRequest,
        AttendancePreconditionRequest, ElementResolutionRequest, PlatformDriver, ProcessGrant,
        SemanticDispatchRequest, SEMANTIC_PRESS_ACTION,
    };
    use cerebellum_windows::{current_session_provenance, process_start_time, ProcessStartTime};

    let mut args = std::env::args().skip(1);
    let Some(pid) = args.next().and_then(|raw| raw.parse::<u32>().ok()) else {
        eprintln!("usage: live_windows_driver <pid> [automation_id]");
        std::process::exit(2);
    };
    let automation_id = args.next();

    println!("session: {:?}", current_session_provenance());
    let evidence = match process_start_time(pid) {
        ProcessStartTime::Started(ticks) => ticks.to_string(),
        other => {
            println!("cannot mint a grant: process start time is {other:?}");
            std::process::exit(1);
        }
    };
    let target = ProcessGrant {
        pid,
        bundle_identity: format!("pid:{pid}"),
        process_generation_evidence: evidence.clone(),
    };
    println!("grant: pid={pid} generation={evidence}");

    let mut driver = WindowsPlatformDriver::default();

    match driver.verify_attendance(AttendancePreconditionRequest {
        conversation_id: "live-windows-driver-probe".to_owned(),
        target: target.clone(),
        maximum_lease_age_ms: 60_000,
    }) {
        Ok(result) => println!("verify_attendance: {result:?}"),
        Err(error) => println!("verify_attendance refused: {error}"),
    }

    let tree = match driver.read_accessibility_tree(AccessibilityTreeRequest {
        target: target.clone(),
        settle_interval_ms: 500,
    }) {
        Ok(tree) => tree,
        Err(error) => {
            println!("read_accessibility_tree refused: {error}");
            std::process::exit(1);
        }
    };
    println!(
        "tree: root={:?} children={} unreadable_subtrees={} degenerate={:?}",
        tree.root_identifier, tree.child_count, tree.unreadable_subtrees, tree.degenerate_reason
    );

    let Some(automation_id) = automation_id else {
        println!("VERDICT: read through the driver; no element requested");
        return;
    };
    let Some(root) = tree.root_identifier.clone() else {
        println!("VERDICT: the driver returned no root identifier, so nothing can be resolved");
        std::process::exit(1);
    };

    let resolved = match driver.resolve_element(ElementResolutionRequest {
        root_identifier: root.clone(),
        element_name: AccessibilityElementName::Identifier(automation_id.clone()),
    }) {
        Ok(resolved) => resolved,
        Err(error) => {
            println!("resolve_element refused: {error}");
            std::process::exit(1);
        }
    };
    println!("resolved: {resolved:?}");

    match driver.dispatch_semantic(SemanticDispatchRequest {
        element: resolved,
        action: SEMANTIC_PRESS_ACTION.to_owned(),
    }) {
        Ok(result) => println!("dispatch_semantic: {result:?}"),
        Err(error) => {
            println!("dispatch_semantic refused: {error}");
            std::process::exit(1);
        }
    }

    std::thread::sleep(std::time::Duration::from_millis(500));
    match driver.read_accessibility_tree(AccessibilityTreeRequest {
        target,
        settle_interval_ms: 500,
    }) {
        Ok(after) => {
            println!("after: children={}", after.child_count);
            let still_there = after.root_identifier.and_then(|root| {
                driver
                    .resolve_element(ElementResolutionRequest {
                        root_identifier: root,
                        element_name: AccessibilityElementName::Identifier(automation_id.clone()),
                    })
                    .ok()
            });
            if still_there.is_none() {
                println!("VERDICT: {automation_id:?} is gone after press, so the driver delivered an observable effect");
            } else {
                println!("VERDICT: {automation_id:?} is still present; this key does not produce an observable this probe can read");
            }
        }
        Err(error) => {
            println!("after: read refused: {error} (a control that closes its process ends here)")
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("this probe drives the Windows platform driver and does nothing elsewhere");
}
