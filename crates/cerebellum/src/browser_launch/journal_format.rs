use cerebellum_core::journal::ObligationAuditRecord;

use super::{
    BrowserLaunchRecoveryFailure, LAUNCH_CODEC_VERSION, LAUNCH_ENTRY_FORMAT,
    LAUNCH_RECOVERY_CLEAR_FORMAT, RECOVERY_CLEAR_FORMAT_VERSION, RECOVERY_CLEAR_SLOT,
};

pub(super) fn windows_launch_descriptor(bytes: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(bytes).is_ok_and(|value| {
        value.get("supervisor_generation").is_some()
            || value
                .get("launch_vector")
                .is_some_and(|vector| vector.get("encoding").is_some())
    })
}

/// Refuse a newer writer before strict decoding: otherwise an unsupported
/// record can look like a missing intent and be consumed while still needed.
pub(super) fn refuse_newer_launch_record(
    sequence: u64,
    audit: &ObligationAuditRecord,
) -> Result<(), BrowserLaunchRecoveryFailure> {
    let refuse = |newer| BrowserLaunchRecoveryFailure::NewerWriter { sequence, newer };
    let version_of = |bytes: &[u8]| {
        serde_json::from_slice::<serde_json::Value>(bytes)
            .ok()
            .and_then(|value| {
                value
                    .get("format_version")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
    };
    LAUNCH_ENTRY_FORMAT
        .refuse_newer_tag(&audit.codec_id, LAUNCH_CODEC_VERSION)
        .map_err(refuse)?;
    if let Some(found) = version_of(&audit.descriptor_bytes) {
        LAUNCH_ENTRY_FORMAT
            .refuse_newer_tag(&found, LAUNCH_CODEC_VERSION)
            .map_err(refuse)?;
    }
    if let Some(found) = audit
        .attachment_slots
        .iter()
        .find(|attachment| attachment.slot == RECOVERY_CLEAR_SLOT)
        .and_then(|attachment| version_of(&attachment.opaque_bytes))
    {
        LAUNCH_RECOVERY_CLEAR_FORMAT
            .refuse_newer_tag(&found, RECOVERY_CLEAR_FORMAT_VERSION)
            .map_err(refuse)?;
    }
    Ok(())
}
