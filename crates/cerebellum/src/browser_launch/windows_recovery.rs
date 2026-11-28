//! Startup recovery for launches made with Windows' suspended, job-bound creator.

use cerebellum_core::journal::{
    BindingError, JournalStorage, ObligationAuditRecord, RecoveryClassification,
};
use cerebellum_windows::process::{observe_process_generation, ProcessGenerationLiveness};

use super::{
    refuse_newer_launch_record, AuthorizedLaunchIntent, BrowserLaunchRecoveryFailure as Failure,
    BrowserProcessGeneration, DurableLaunchJournal, LaunchAttestationRecord, LaunchByteEncoding,
    LaunchGenerationRecord, LaunchProfile, WindowsRecoveryBasis as Basis, ATTESTATION_SLOT,
    GENERATION_SLOT, LAUNCH_CODEC_VERSION, LAUNCH_RECOVERY_CLEAR_FORMAT,
    RECOVERY_CLEAR_FORMAT_VERSION, RECOVERY_CLEAR_SLOT,
};
use crate::profile_custody::{
    HolderId, KernelSupervisorLiveness, SupervisorGeneration, SupervisorLiveness,
    SupervisorLivenessProbe,
};
use serde::{Deserialize, Serialize};

/// Open and recover before publishing a Windows launch service. Both store
/// openers are lazy so an unbound build cannot touch either store. The caller
/// must serialize journal changes and hold custody coordination while opening
/// and recovering; the reader cannot infer exclusivity from either PID.
///
/// Releasing a claim must verify the exact recorded holder, and is idempotent
/// if that claim was already released. A pending attempt is not retaken or
/// rewritten: a live holder must keep its ownership, and an unknown holder
/// must never be treated as stale.
pub fn open_windows_startup<S: JournalStorage, C>(
    open_journal: impl FnOnce() -> Result<DurableLaunchJournal<S>, BindingError>,
    open_custody: impl FnOnce() -> Result<C, Failure>,
    mut release: impl FnMut(
        &mut C,
        &AuthorizedLaunchIntent,
    ) -> Result<(), super::OrphanProfileCustodyFailure>,
) -> Result<Option<WindowsStartup<S>>, Failure> {
    if !crate::browser_build_admits() {
        return Ok(None);
    }
    let mut journal = open_journal().map_err(|_| Failure::JournalOpen)?;
    // Validate the entire active set before writing to either store.
    let attempts = active_attempts(&journal)?;
    let mut custody = open_custody()?;
    let mut pending = Vec::new();
    for attempt in attempts {
        let Some(basis) = attempt.clear.or_else(|| attempt.prove()) else {
            pending.push(attempt.intent);
            continue;
        };
        if attempt.clear.is_none() {
            persist_basis(&mut journal, &attempt, basis)?;
        }
        release(&mut custody, &attempt.intent).map_err(|_| Failure::ProfileCustodyRelease {
            sequence: attempt.sequence,
        })?;
        journal
            .core
            .recover_record_preserving_cancelled_evidence(attempt.sequence)
            .ok_or(Failure::JournalTerminalization)?;
    }
    Ok(Some(WindowsStartup { journal, pending }))
}

pub struct WindowsStartup<S: JournalStorage> {
    pub journal: DurableLaunchJournal<S>,
    /// These exact reservations remain held; none earned a recovery basis.
    pub pending: Vec<AuthorizedLaunchIntent>,
}

/// Pre-intent stale-break evidence. Open a fresh, complete journal snapshot
/// while coordinating the replacement of this exact custody record. A failed
/// read cannot establish absence. The caller records the returned basis in
/// the replacing custody record before granting a new holder.
pub fn no_intent_basis<S: JournalStorage>(
    open_journal: impl FnOnce() -> Result<DurableLaunchJournal<S>, BindingError>,
    holder_id: &HolderId,
    holder: SupervisorGeneration,
) -> Result<Option<Basis>, Failure> {
    if !crate::browser_build_admits() || !holder_is_gone(holder) {
        return Ok(None);
    }
    let journal = open_journal().map_err(|_| Failure::JournalOpen)?;
    let found = active_attempts(&journal)?
        .iter()
        .any(|attempt| attempt.intent.holder_id == holder_id.as_str());
    Ok((!found).then_some(Basis::NoIntentHolderGone))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cut {
    IntentOnly,
    Barred(BrowserProcessGeneration),
    Inconsistent,
}

impl Cut {
    fn basis_kind(self) -> Option<Basis> {
        match self {
            Self::IntentOnly => Some(Basis::NeverResumedHolderGone),
            Self::Barred(_) => Some(Basis::GenerationsGone),
            Self::Inconsistent => None,
        }
    }
}

struct Attempt {
    sequence: u64,
    intent: AuthorizedLaunchIntent,
    holder: SupervisorGeneration,
    cut: Cut,
    clear: Option<Basis>,
}

impl Attempt {
    fn prove(&self) -> Option<Basis> {
        if !holder_is_gone(self.holder) {
            return None;
        }
        match self.cut {
            Cut::IntentOnly => Some(Basis::NeverResumedHolderGone),
            Cut::Barred(generation)
                if generation.windows_filetime().is_some_and(|ticks| {
                    observe_process_generation(generation.pid, ticks)
                        == ProcessGenerationLiveness::Gone
                }) =>
            {
                Some(Basis::GenerationsGone)
            }
            // Unknown, alive, and incomplete evidence all keep custody.
            _ => None,
        }
    }
}

fn holder_is_gone(holder: SupervisorGeneration) -> bool {
    KernelSupervisorLiveness.observe(holder) == SupervisorLiveness::NotLive
}

fn active_attempts<S: JournalStorage>(
    journal: &DurableLaunchJournal<S>,
) -> Result<Vec<Attempt>, Failure> {
    let mut attempts = Vec::new();
    for sequence in 1..journal.core.next_sequence() {
        let Some(classification) = journal.core.classify(sequence) else {
            continue;
        };
        let audit = journal
            .read_attempt(sequence)
            .map_err(|_| Failure::JournalRead { sequence })?;
        refuse_newer_launch_record(sequence, &audit)?;
        attempts.push(read_attempt(sequence, classification, &audit)?);
    }
    Ok(attempts)
}

fn read_attempt(
    sequence: u64,
    classification: RecoveryClassification,
    audit: &ObligationAuditRecord,
) -> Result<Attempt, Failure> {
    let invalid = || Failure::InvalidIntent { sequence };
    let intent: AuthorizedLaunchIntent =
        serde_json::from_slice(&audit.descriptor_bytes).map_err(|_| invalid())?;
    let holder = intent
        .supervisor_generation
        .filter(|holder| holder.windows_filetime().is_some())
        .ok_or_else(invalid)?;
    if audit.codec_id != LAUNCH_CODEC_VERSION
        || intent.format_version != LAUNCH_CODEC_VERSION
        || !matches!(intent.profile.disposition, LaunchProfile::Registry(_))
        || intent.holder_id.is_empty()
        || intent.launch_attempt_id.is_empty()
        || !valid_windows_bytes(&intent)
    {
        return Err(invalid());
    }
    let cut = classify_cut(classification, audit, &intent);
    let mut clear = None;
    if let Some(bytes) = attachment(audit, RECOVERY_CLEAR_SLOT) {
        let record: RecoveryClear = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        if record.format_version != RECOVERY_CLEAR_FORMAT_VERSION
            || record.sequence != sequence
            || record.launch_attempt_id != intent.launch_attempt_id
            || record.holder_id != intent.holder_id
            || Some(record.basis) != cut.basis_kind()
        {
            return Err(invalid());
        }
        clear = Some(record.basis);
    }
    Ok(Attempt {
        sequence,
        intent,
        holder,
        cut,
        clear,
    })
}

fn valid_windows_bytes(intent: &AuthorizedLaunchIntent) -> bool {
    let vector = &intent.launch_vector;
    let even = |bytes: &[u8]| bytes.len().is_multiple_of(2);
    vector.encoding == Some(LaunchByteEncoding::Utf16le)
        && !vector.executable.is_empty()
        && even(&vector.executable)
        && vector.arguments.iter().all(|arg| even(arg))
        && vector
            .environment
            .iter()
            .all(|(name, value)| even(name) && even(value))
        && vector
            .lp_command_line
            .as_deref()
            .is_some_and(|line| !line.is_empty() && even(line))
        && !intent.profile.canonical_profile_path.is_empty()
        && even(&intent.profile.canonical_profile_path)
}

fn attachment<'a>(audit: &'a ObligationAuditRecord, slot: &str) -> Option<&'a [u8]> {
    audit
        .attachment_slots
        .iter()
        .find(|entry| entry.slot == slot)
        .map(|entry| entry.opaque_bytes.as_slice())
}

fn classify_cut(
    classification: RecoveryClassification,
    audit: &ObligationAuditRecord,
    intent: &AuthorizedLaunchIntent,
) -> Cut {
    match (
        attachment(audit, GENERATION_SLOT),
        attachment(audit, ATTESTATION_SLOT),
    ) {
        (None, None) if classification == RecoveryClassification::UnmarkedOrphan => Cut::IntentOnly,
        (Some(generation), Some(attestation)) => {
            let generation = serde_json::from_slice::<LaunchGenerationRecord>(generation);
            let attestation = serde_json::from_slice::<LaunchAttestationRecord>(attestation);
            match (generation, attestation) {
                (Ok(generation), Ok(attestation))
                    if generation.intent == *intent
                        && generation == attestation.generation
                        && generation.process_generation.windows_filetime().is_some()
                        && intent
                            .verified_executable_identity
                            .admits(&attestation.observed_executable_identity) =>
                {
                    Cut::Barred(generation.process_generation)
                }
                _ => Cut::Inconsistent,
            }
        }
        // An unreadable attachment is still an attachment. Its presence rules
        // out an intent with no attachments; it does not prove the child is gone.
        _ => Cut::Inconsistent,
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryClear {
    format_version: String,
    sequence: u64,
    launch_attempt_id: String,
    holder_id: String,
    basis: Basis,
}

fn persist_basis<S: JournalStorage>(
    journal: &mut DurableLaunchJournal<S>,
    attempt: &Attempt,
    basis: Basis,
) -> Result<(), Failure> {
    let handle = journal
        .core
        .active_reservation_handle(attempt.sequence)
        .ok_or(Failure::JournalTerminalization)?;
    let bytes = serde_json::to_vec(&RecoveryClear {
        format_version: RECOVERY_CLEAR_FORMAT_VERSION.to_owned(),
        sequence: attempt.sequence,
        launch_attempt_id: attempt.intent.launch_attempt_id.clone(),
        holder_id: attempt.intent.holder_id.clone(),
        basis,
    })
    .map_err(|_| Failure::JournalTerminalization)?;
    journal
        .core
        .raise_format_floor(LAUNCH_RECOVERY_CLEAR_FORMAT)
        .map_err(|_| Failure::JournalTerminalization)?;
    journal
        .core
        .attach_obligation_material(handle, RECOVERY_CLEAR_SLOT, 0, bytes)
        .map_err(|_| Failure::JournalTerminalization)?;
    Ok(())
}

#[cfg(test)]
mod tests;
