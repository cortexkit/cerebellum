//! The durable formats this module reads back from the operator's data home,
//! with the highest version of each that this build reads, and where their
//! floors live.
//!
//! Staging compares this list against the format floors on disk and refuses
//! a build that reads less than a floor says is there. So every entry is the
//! constant the format's own reader checks against, never a copy of it: a
//! copy could say a build reads a version its reader refuses.
//!
//! Formats this module writes but never reads back are not listed: no build
//! fails on them, so no build should be refused over them. Those are the
//! custody event log and the profile-root rebind log (append-only records for
//! people) and the browser journal's entries (exported as written, never
//! decoded).

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
        crate::browser_launch::LAUNCH_ENTRY_FORMAT,
        crate::browser_launch::LAUNCH_RECOVERY_CLEAR_FORMAT,
        cerebellum_computer::audit::COMPUTER_ENTRY_FORMAT,
        // Under `browser/`.
        crate::profile::REGISTRY_FORMAT,
        crate::profile_custody::CUSTODY_LOCK_FORMAT,
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
}
