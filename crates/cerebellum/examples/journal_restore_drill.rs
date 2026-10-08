//! Put a captured audit journal back and read what startup does to it.
//!
//! The restore contract for `cerebellum/audit-journal` says: restore the tree
//! whole; reservations open at capture are the crash-orphan shape, and
//! startup reconciliation settles them. Until this ran, that claim rested on
//! unit tests over constructed journals. This drives the PRODUCTION open path
//! -- the same storage, config, and reconcile that `production_audit` uses --
//! over a real captured `journal/` directory, with the recovery step exposed
//! so each outcome is printed rather than swallowed into `Ok(())`.
//!
//! Point it at a scratch copy, never at the live tree: reconciliation WRITES
//! (it finalizes orphans), and a drill that mutates the operator's journal is
//! not a drill.
//!
//!     XDG_DATA_HOME=/tmp/drill cargo run -p cerebellum --example journal_restore_drill
//!
//! where /tmp/drill/cortexkit/cerebellum/journal/ holds the captured files.
//! The probe refuses to run when the resolved path is under the real data
//! home, so a forgotten variable cannot turn it into a mutation of the
//! operator's records.
//!
//! Exit 0 when reconciliation completed and left zero active reservations;
//! exit 1 with the reason otherwise. Prints status before, every recovery
//! outcome, and status after, so "nothing was open" and "everything settled"
//! read differently.
//!
//! A real capture of a healthy desk usually holds NO open reservation, which
//! makes the reconcile arm vacuous: zero outcomes proves nothing was open, not
//! that an orphan settles. `--orphan actuation` or `--orphan capture` makes
//! one the way production would: reserve and commit through the audit API
//! over the scratch file, then exit WITHOUT finalizing -- the crash shape.
//! The next plain run reopens that file in a fresh process and reconciles
//! it, which is the round-trip the in-memory unit tests cannot take.

use std::process::ExitCode;

/// The computer audit only exists where a computer plane does. On other hosts
/// the example still has to build (the Linux lint phase compiles every
/// target), so it compiles to a main that says why there is nothing to run.
#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn main() -> ExitCode {
    eprintln!("this drill reconciles the computer-plane audit journal, which only exists on macOS and Windows");
    ExitCode::from(1)
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
use cerebellum_computer::audit::{
    ActuationElementIdentity, ActuationIntent, ComputerAudit, ComputerCapability,
    ComputerPlaneDescriptor, ObservationState, TypedCaptureDispatch,
};
#[cfg(any(target_os = "macos", target_os = "windows"))]
use cerebellum_computer::capture_custody::{
    CaptureCustody, CustodyBounds, InMemoryCustodyStorage, InMemoryGrantAuthority,
};
#[cfg(any(target_os = "macos", target_os = "windows"))]
use cerebellum_computer::grounding::ContainmentRung;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use cerebellum_computer::platform::{AccessibilityElementName, ProcessGrant};
#[cfg(any(target_os = "macos", target_os = "windows"))]
use cerebellum_core::identity::SessionKind;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use cerebellum_core::journal::{
    journal_data_path, FilesystemJournalStorage, JournalConfig, JournalIdentity,
};

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn main() -> ExitCode {
    let orphan = match std::env::args().nth(1).as_deref() {
        None => None,
        Some("--orphan") => match std::env::args().nth(2).as_deref() {
            Some("actuation") => Some("actuation"),
            Some("capture") => Some("capture"),
            other => {
                eprintln!("--orphan takes `actuation` or `capture`, got {other:?}");
                return ExitCode::from(1);
            }
        },
        Some(other) => {
            eprintln!("unknown argument {other:?}; usage: [--orphan actuation|capture]");
            return ExitCode::from(1);
        }
    };
    let path = match journal_data_path("computer.json") {
        Ok(path) => path,
        Err(error) => {
            eprintln!("journal path did not resolve: {error:?}");
            return ExitCode::from(1);
        }
    };

    // The real data home is whatever the ladder resolves with no override. If
    // the drill's path is under it, the caller forgot XDG_DATA_HOME and this
    // would reconcile -- and write -- the live journal.
    let override_present = std::env::var_os("XDG_DATA_HOME").is_some();
    if !override_present {
        eprintln!(
            "REFUSING: XDG_DATA_HOME is unset, so {} is the operator's live journal. \
             Copy the captured tree under a scratch data home and point the variable at it.",
            path.display()
        );
        return ExitCode::from(1);
    }
    if !path.is_file() {
        eprintln!(
            "REFUSING: no journal at {} -- the captured tree was not placed where the \
             ladder resolves (data_home/cortexkit/cerebellum/journal/computer.json)",
            path.display()
        );
        return ExitCode::from(1);
    }
    println!("journal: {}", path.display());
    println!(
        "bytes on disk before: {}",
        std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0)
    );

    let severity = match cerebellum_computer::platform::severity::load_severity_taxonomy() {
        Ok(severity) => severity,
        Err(error) => {
            eprintln!("severity taxonomy did not load: {error:?}");
            return ExitCode::from(1);
        }
    };
    let storage = match FilesystemJournalStorage::prepare(&path) {
        Ok(storage) => storage,
        Err(error) => {
            eprintln!("storage refused the captured file: {error:?}");
            return ExitCode::from(1);
        }
    };
    let custody = match CaptureCustody::new(
        CustodyBounds {
            maximum_verification_duration_ms: 5_000,
            maximum_pin_lifetime_ms: 30_000,
            maximum_concurrently_pinned_artifacts: 8,
            maximum_total_pinned_artifact_bytes: 64 * 1024 * 1024,
            maximum_custody_attachment_bytes: 16 * 1024 * 1024,
        },
        InMemoryGrantAuthority::default(),
        InMemoryCustodyStorage::new(),
    ) {
        Ok(custody) => custody,
        Err(_) => {
            eprintln!("capture custody did not construct");
            return ExitCode::from(1);
        }
    };
    // Same retention and entry bounds as production_audit, so a captured
    // journal larger than production would accept is refused here too.
    let mut audit = match ComputerAudit::new(
        cerebellum_computer::audit::redaction::ExcludeApplicationText,
        severity,
        JournalConfig {
            journal_retention_bytes: 8 * 1024 * 1024,
            journal_max_entry_bytes: 64 * 1024,
        },
        storage,
        custody,
    ) {
        Ok(audit) => audit,
        Err(error) => {
            eprintln!("audit did not bind over the captured journal: {error:?}");
            return ExitCode::from(1);
        }
    };

    let before = audit.journal().status();
    println!(
        "before: entries={} active_reservations={} retained_bytes={} sequences={:?}..{:?}",
        before.entry_count,
        before.active_reservation_count,
        before.retained_bytes,
        before.oldest_retained_sequence,
        before.newest_retained_sequence
    );

    if let Some(kind) = orphan {
        // Reserve and commit exactly as dispatch does, then return without
        // finalize. commit_state saves before the in-memory state moves, so
        // the open reservation is on disk when this process exits -- the
        // state a crash between intent and outcome leaves behind.
        let identity = JournalIdentity {
            witness: cerebellum_core::dispatch_witness::DispatchWitness::detached(),
            principal: "drill".into(),
            conversation_key: "journal-restore-drill".into(),
            agent_project_id: "drill".into(),
            session_kind: SessionKind::Primary,
            origin: Default::default(),
            computer_order: None,
        };
        let sequence = match kind {
            "actuation" => {
                let descriptor = ComputerPlaneDescriptor::new(
                    ComputerCapability::Click,
                    ContainmentRung::SemanticElement,
                    ObservationState::HumanObserved,
                );
                let handle = match audit.reserve(identity, descriptor.clone()) {
                    Ok(handle) => handle,
                    Err(error) => {
                        eprintln!("reserve refused: {error:?}");
                        return ExitCode::from(1);
                    }
                };
                let intent = ActuationIntent {
                    element: Some(ActuationElementIdentity {
                        matched_by: AccessibilityElementName::Identifier("drill-target".into()),
                        alternate_name: None,
                    }),
                    action: "press".into(),
                    grant_identity: ProcessGrant {
                        pid: 1,
                        bundle_identity: "drill.no-such-app".into(),
                        process_generation_evidence: "drill-generation".into(),
                    },
                };
                if let Err(error) = audit.commit_actuation_intent(handle, &descriptor, &intent) {
                    eprintln!("commit_actuation_intent refused: {error:?}");
                    return ExitCode::from(1);
                }
                handle.sequence()
            }
            _ => {
                let descriptor = ComputerPlaneDescriptor::new(
                    ComputerCapability::Screenshot,
                    ContainmentRung::PidStructural,
                    ObservationState::HumanUnobserved,
                );
                let handle = match audit.reserve(identity, descriptor) {
                    Ok(handle) => handle,
                    Err(error) => {
                        eprintln!("reserve refused: {error:?}");
                        return ExitCode::from(1);
                    }
                };
                let dispatch = TypedCaptureDispatch::new(
                    ComputerCapability::Screenshot,
                    ContainmentRung::PidStructural,
                    ObservationState::HumanUnobserved,
                )
                .dispatch_material(b"computer.screenshot".to_vec());
                if let Err(error) =
                    audit.commit_dispatched(handle, &dispatch, b"drill-lease".to_vec(), None)
                {
                    eprintln!("commit_dispatched refused: {error:?}");
                    return ExitCode::from(1);
                }
                handle.sequence()
            }
        };
        let open = audit.journal().status();
        println!(
            "orphan {kind} committed at sequence {sequence}; exiting without finalize \
             (active_reservations now {}, bytes on disk {})",
            open.active_reservation_count,
            std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0)
        );
        return ExitCode::SUCCESS;
    }

    // The recovery step, run on its own first so every outcome is visible.
    // startup_reconcile below runs it again (idempotent: nothing is left to
    // recover) and then does the custody and terminal-feed work.
    let outcomes = audit.recover_active();
    println!("recovery outcomes: {}", outcomes.len());

    if let Err(error) = audit.startup_reconcile(0) {
        eprintln!("startup_reconcile FAILED: {error:?}");
        return ExitCode::from(1);
    }

    // The core outcome is the same for every capability (a dispatched
    // reservation with no terminal finalizes); the PLANE decides from the
    // descriptor persisted in the entry whether that means settled (a capture
    // -- dispatch was the read) or unknown (an actuation -- dispatch does not
    // prove the effect). Printing the core layer alone showed both as
    // finalized and read as a defect for ten minutes. Read the plane record.
    for outcome in &outcomes {
        let id = outcome.action_obligation_id;
        match audit.read_computer_audit_record(id) {
            Ok(record) => println!(
                "  obligation {id}: {:?} classified {:?} -> plane terminal {:?} (settled: {})",
                record.descriptor.capability,
                outcome.classification,
                record.terminal_kind,
                record
                    .terminal_kind
                    .map(|kind| kind.is_settled())
                    .unwrap_or(false)
            ),
            Err(error) => println!("  obligation {id}: plane record unreadable: {error:?}"),
        }
    }
    let after = audit.journal().status();
    println!(
        "after:  entries={} active_reservations={} retained_bytes={} sequences={:?}..{:?}",
        after.entry_count,
        after.active_reservation_count,
        after.retained_bytes,
        after.oldest_retained_sequence,
        after.newest_retained_sequence
    );
    println!(
        "bytes on disk after:  {}",
        std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0)
    );

    if after.active_reservation_count != 0 {
        eprintln!(
            "reconciliation left {} reservation(s) active",
            after.active_reservation_count
        );
        return ExitCode::from(1);
    }
    println!("reconciled: zero active reservations over the restored journal");
    ExitCode::SUCCESS
}
