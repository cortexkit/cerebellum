//! Restore the browser tree from a capture and prove the recovery path end to
//! end: the registry refuses the restored root with a remedy, the rebind heals
//! it without touching a record, and launch-journal recovery over the restored
//! attestations signals nothing it should not.
//!
//! The registry pins its managed root by canonical path, inode and birth time,
//! so ANY restore recreates the root and every launch refuses with
//! `profile_registry_managed_root_inode_changed` (or, for a capture whose
//! registry was written before those facts were recorded,
//! `profile_registry_managed_root_identity_predates_facts`). Until the rebind
//! operation existed that refusal had no recovery; this drill is the proof
//! that it now does, on a real captured tree rather than a constructed one.
//!
//! Point it at a scratch copy, never the live tree: the rebind WRITES.
//!
//!     XDG_DATA_HOME=/tmp/drill cargo run -p cerebellum --example launch_restore_drill
//!
//! with the captured `cerebellum/browser/` and `cerebellum/journal/` placed
//! under `/tmp/drill/cortexkit/`. Refuses to run without the override so a
//! forgotten variable cannot rebind the operator's live registry.
//!
//! Three arms, each printed with its evidence:
//!   1. REFUSAL  -- every recorded durable project refuses with the identity
//!      reason, and the launch-time remedy names the rebind operation.
//!   2. REBIND   -- the production primitive heals the root; every record
//!      resolves afterwards and is byte-equal to what the file held before;
//!      the provenance record exists with the identities it names.
//!   3. RECOVERY -- launch-journal recovery runs over the restored journal
//!      with an OBSERVE-ONLY process control: any attestation whose process
//!      generation matches a live process is reported, never signalled. A
//!      captured journal from a quiet desk holds no active attempt, and the
//!      arm says so rather than claiming a recovery it did not perform.
//!
//! Exit 0 only when all three arms hold; exit 1 with the arm and reason.

use std::process::ExitCode;

use cerebellum::browser_launch::{
    recover_browser_launches, AuthorizedLaunchIntent, BrowserProcessGeneration,
    DurableLaunchJournal, OrphanBrowserProcessControl, OrphanProcessControlFailure,
    OrphanProfileCustody, OrphanProfileCustodyFailure,
};
use cerebellum::browser_launch_service::{launch_journal_config, production_profile_lifecycle};
use cerebellum::profile::{
    untrustworthy_registry_reason_code, untrustworthy_registry_remedy, DurableResolution,
    RebindProvenance, RegistryError, UntrustworthyRegistryReason, PROFILE_ROOT_REBINDS_FILE,
};
use serde_json::Value;

/// Reports what production would do to a process and does none of it. The
/// drill's job is to show the decision, not to take it: a restored journal
/// naming a pid that some unrelated process now holds is exactly the input a
/// wrong reaper would kill on, so this control turns "would terminate" into a
/// printed line and a failure the drill can read.
struct ObserveOnly {
    would_terminate: Vec<BrowserProcessGeneration>,
}

impl OrphanBrowserProcessControl for ObserveOnly {
    fn observed_start_time_micros(
        &mut self,
        pid: u32,
    ) -> Result<Option<u64>, OrphanProcessControlFailure> {
        // Same two answers production's control gives: a running process
        // reports its start time, an absent one reports None, and anything
        // the kernel would not say is a failure rather than a guess.
        #[cfg(target_os = "macos")]
        {
            match cerebellum_macos::process_start_time(pid) {
                cerebellum_macos::ProcessStartTime::Started(start) => Ok(Some(start)),
                cerebellum_macos::ProcessStartTime::NoSuchProcess => Ok(None),
                _ => Err(OrphanProcessControlFailure),
            }
        }
        #[cfg(target_os = "linux")]
        {
            match cerebellum_linux::process_start_time(pid) {
                cerebellum_linux::ProcessStartTime::Started(start) => Ok(Some(start)),
                cerebellum_linux::ProcessStartTime::NoSuchProcess => Ok(None),
                _ => Err(OrphanProcessControlFailure),
            }
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = pid;
            Err(OrphanProcessControlFailure)
        }
    }

    fn terminate_and_reap(
        &mut self,
        generation: BrowserProcessGeneration,
    ) -> Result<(), OrphanProcessControlFailure> {
        self.would_terminate.push(generation);
        // Refusing termination makes production recovery report a
        // termination failure, which this drill uses to show that a matching
        // live process exists, without sending it a signal. Recovery then
        // leaves the record active and retains its custody.
        Err(OrphanProcessControlFailure)
    }
}

/// Releasing or retaining custody edits files under the restored root, so the
/// drill records those actions without modifying the restored tree.
struct ReportOnlyCustody {
    releases: Vec<String>,
    retains: Vec<String>,
}

impl OrphanProfileCustody for ReportOnlyCustody {
    fn release(
        &mut self,
        intent: &AuthorizedLaunchIntent,
    ) -> Result<(), OrphanProfileCustodyFailure> {
        self.releases.push(intent.launch_attempt_id.clone());
        Ok(())
    }

    fn retain(
        &mut self,
        intent: &AuthorizedLaunchIntent,
    ) -> Result<(), OrphanProfileCustodyFailure> {
        self.retains.push(intent.launch_attempt_id.clone());
        Ok(())
    }
}

fn fail(arm: &str, reason: impl std::fmt::Display) -> ExitCode {
    eprintln!("ARM {arm} FAILED: {reason}");
    ExitCode::from(1)
}

fn main() -> ExitCode {
    if std::env::var_os("XDG_DATA_HOME").is_none() {
        eprintln!(
            "REFUSING: XDG_DATA_HOME is unset, so this would rebind the operator's LIVE \
             registry. Copy the captured tree under a scratch data home and point the \
             variable at it."
        );
        return ExitCode::from(1);
    }

    // ---- ARM 1: the restored root refuses, with the remedy --------------
    let lifecycle = match production_profile_lifecycle() {
        Ok(lifecycle) => lifecycle,
        Err(error) => return fail("1", format!("registry did not open: {error:?}")),
    };
    let root = lifecycle.registry().root().canonical_path().to_path_buf();
    println!("root: {}", root.display());
    let registry_path = root.join(".ck-browser-profile-registry-v1.json");
    let before: Value = match std::fs::read(&registry_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    {
        Some(value) => value,
        None => return fail("1", "no parseable registry in the restored tree"),
    };
    let projects: Vec<String> = before["records"]
        .as_object()
        .map(|records| records.keys().cloned().collect())
        .unwrap_or_default();
    println!(
        "registry before: generation {} · {} record(s) · identity {}",
        before["generation"],
        projects.len(),
        before["managed_root_identity"]
    );
    if projects.is_empty() {
        return fail(
            "1",
            "the capture holds no durable record, so the arm cannot discriminate",
        );
    }
    for project in &projects {
        match lifecycle.registry().resolve_durable(project) {
            // The reasons a restore can produce that the rebind heals. The
            // path reason is included because a capture restored under a
            // different data home has moved as well as been recreated.
            Err(RegistryError::Untrustworthy(
                reason @ (UntrustworthyRegistryReason::ManagedRootInodeChanged
                | UntrustworthyRegistryReason::ManagedRootBirthTimeChanged
                | UntrustworthyRegistryReason::ManagedRootPathChanged
                | UntrustworthyRegistryReason::ManagedRootIdentityPredatesFacts),
            )) => {
                println!(
                    "  {project}: refused {} · remedy: {}",
                    untrustworthy_registry_reason_code(reason),
                    untrustworthy_registry_remedy(reason).unwrap_or("<none>")
                );
            }
            other => {
                return fail(
                    "1",
                    format!("{project} did not refuse on identity; got {other:?} -- was the tree actually restored (new inode)?"),
                )
            }
        }
    }

    // ---- ARM 2: rebind, then every record resolves unchanged -------------
    let provenance = RebindProvenance {
        ask_id: "launch-restore-drill".to_string(),
        conversation_key: "launch-restore-drill".to_string(),
        at_unix_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
    };
    let report = match lifecycle.registry().rebind_managed_root(&provenance) {
        Ok(report) => report,
        Err(refusal) => return fail("2", format!("rebind refused: {refusal:?}")),
    };
    println!(
        "rebound: {} -> {} · generation {} -> {} · {} record(s)",
        report.old_identity,
        report.new_identity,
        report.generation_before,
        report.generation_after,
        report.record_count
    );
    let after: Value = match std::fs::read(&registry_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    {
        Some(value) => value,
        None => return fail("2", "registry unreadable after rebind"),
    };
    if after["records"] != before["records"] {
        return fail("2", "records changed across the rebind");
    }
    for project in &projects {
        match lifecycle.registry().resolve_durable(project) {
            Ok(DurableResolution::TrustworthyExisting(record)) => {
                println!(
                    "  {project}: resolves · {:?} · {}",
                    record.state, record.target
                );
            }
            other => {
                return fail(
                    "2",
                    format!("{project} does not resolve after rebind: {other:?}"),
                )
            }
        }
    }
    let provenance_line = std::fs::read_to_string(root.join(PROFILE_ROOT_REBINDS_FILE))
        .ok()
        .and_then(|text| text.lines().last().map(str::to_string))
        .and_then(|line| serde_json::from_str::<Value>(&line).ok());
    match provenance_line {
        Some(line)
            if serde_json::to_value(&report.old_identity).ok().as_ref()
                == Some(&line["old_identity"])
                && serde_json::to_value(&report.new_identity).ok().as_ref()
                    == Some(&line["new_identity"]) =>
        {
            println!(
                "  provenance recorded: {} (elicited under {})",
                line["schema"], line["elicited"]["ask_id"]
            );
        }
        other => {
            return fail(
                "2",
                format!("provenance record missing or wrong: {other:?}"),
            )
        }
    }

    // ---- ARM 3: launch-journal recovery over the restored journal ---------
    let mut journal = match DurableLaunchJournal::open_filesystem(launch_journal_config()) {
        Ok(journal) => journal,
        Err(error) => return fail("3", format!("launch journal did not open: {error:?}")),
    };
    let mut process = ObserveOnly {
        would_terminate: Vec::new(),
    };
    let mut custody = ReportOnlyCustody {
        releases: Vec::new(),
        retains: Vec::new(),
    };
    let recovery = recover_browser_launches(&mut journal, &mut process, &mut custody);
    for generation in &process.would_terminate {
        println!(
            "  WOULD TERMINATE pid {} (start {}): a live process matches a restored attestation exactly",
            generation.pid, generation.start_time_micros
        );
    }
    match recovery {
        Ok(outcomes) if outcomes.is_empty() => {
            println!(
                "recovery: 0 active attempt(s) in the restored journal -- nothing to recover, \
                 nothing signalled (a quiet desk's capture; the arm is a null, not a proof of the reaper)"
            );
        }
        Ok(outcomes) => {
            for outcome in &outcomes {
                println!(
                    "  attempt {}: process {:?} · journal {:?}",
                    outcome.sequence, outcome.process, outcome.journal_action
                );
            }
            println!(
                "recovery: {} active attempt(s) examined; {} custody release(s) and {} retention(s) reported",
                outcomes.len(),
                custody.releases.len(),
                custody.retains.len()
            );
            if !process.would_terminate.is_empty() {
                // The observe-only control refuses termination on purpose, so
                // those attempts are left active with custody retained; that
                // IS the report that a live match existed.
                println!(
                    "recovery: {} attestation(s) matched a live process and were NOT signalled by this drill \
                     (production would terminate them)",
                    process.would_terminate.len()
                );
            }
        }
        Err(failure) => {
            return fail("3", format!("recovery failed: {failure:?}"));
        }
    }
    println!("all three arms held");
    ExitCode::SUCCESS
}
