//! The durable formats this module reads back from the operator's data home,
//! with the highest version of each that this build reads, and where their
//! floors live.
//!
//! Staging compares this list against the format floors on disk and refuses
//! a build that reads less than a floor says is there. So every entry is the
//! constant the format's own reader checks against, never a copy of it: a
//! copy could say a build reads a version its reader refuses.
//!
//! The browser journal also has a floored reason for public-web actions allowed
//! by risk policy without asking a person. That reason must not be interpreted
//! by an older deployment as a person's approval.
//! Fill-login entries also have a floor for their closed capability/payload
//! vocabulary; the floor rises only when the first such entry is written.
//! Other write-only formats need no reader floor: the custody event log,
//! profile-root rebind log, and opaque legacy browser entries.

use std::collections::BTreeMap;
use std::path::PathBuf;

use cerebellum_core::format_floor::{floor_path, DurableFormat, FLOOR_TREES};

/// Every format whose reader refuses a newer version, as that reader sees it.
pub fn readable_formats() -> Vec<DurableFormat> {
    vec![
        // Under `journal/`.
        cerebellum_core::journal::AUDIT_JOURNAL_FORMAT,
        cerebellum_core::journal::REFUSAL_RING_FORMAT,
        crate::computer_grants::GRANT_STORE_FORMAT,
        crate::agent_grants::AGENT_GRANT_STORE_FORMAT,
        crate::open_app_history::LAUNCH_HISTORY_FORMAT,
        crate::browser_standing_grants::STANDING_GRANT_STORE_FORMAT,
        crate::browser_launch::LAUNCH_ENTRY_FORMAT,
        crate::browser_launch::LAUNCH_RECOVERY_CLEAR_FORMAT,
        cerebellum_computer::audit::COMPUTER_ENTRY_FORMAT,
        crate::journal::FILL_LOGIN_ENTRY_FORMAT,
        crate::journal::call_records::CALL_RECORD_FORMAT,
        crate::cingulate_client::desk::CINGULATE_RAISED_FORMAT,
        // Under `browser/`.
        crate::profile::REGISTRY_FORMAT,
        crate::browser_signed_in::SIGNED_IN_FORMAT,
        crate::profile_custody::CUSTODY_LOCK_FORMAT,
        // A separate tree keeps rollback to builds predating this optional
        // store a plain swap: their staging gate ignores this tree's floor.
        crate::private_content::PRIVATE_CONTENT_FORMAT,
        crate::agent_data::CHECKPOINT_FORMAT,
        cerebellum_computer::dispatch::RESTORE_LATENCY_FORMAT,
    ]
}

/// The floor file of each data tree, resolved through the same data-home
/// ladder the module's stores use, keyed by tree name. `None` when this
/// process has no absolute data home, in which case the module writes no
/// durable store either.
pub fn floor_paths() -> Option<BTreeMap<&'static str, PathBuf>> {
    let data_home = cerebellum_core::platform_dirs::data_home()?;
    Some(
        FLOOR_TREES
            .into_iter()
            .map(|tree| (tree, floor_path(&data_home, tree)))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::readable_formats;

    #[test]
    fn every_format_is_listed_once_under_its_own_name() {
        let formats = readable_formats();
        let names: BTreeSet<_> = formats.iter().map(|format| format.name).collect();
        assert_eq!(names.len(), formats.len(), "a format is listed twice");
        assert!(formats.iter().all(|format| format.version > 0));
    }

    #[test]
    fn open_app_history_reader_is_listed_for_the_staging_floor_gate() {
        assert!(readable_formats().contains(&crate::open_app_history::LAUNCH_HISTORY_FORMAT));
    }

    #[test]
    fn the_raised_card_registry_reader_is_listed_for_the_staging_floor_gate() {
        assert!(
            readable_formats().contains(&crate::cingulate_client::desk::CINGULATE_RAISED_FORMAT)
        );
    }

    #[test]
    fn restore_latency_is_listed_for_the_staging_floor_gate() {
        assert!(readable_formats().contains(&cerebellum_computer::dispatch::RESTORE_LATENCY_FORMAT));
    }
}
