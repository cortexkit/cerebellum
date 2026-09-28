//! The durable formats this module reads back from the operator's data home,
//! with the highest version of each that this build reads.
//!
//! Staging compares this list against the format floor on disk and refuses a
//! build that reads less than the floor says is there. So every entry is the
//! constant the format's own reader checks against, never a copy of it: a
//! copy could say a build reads a version its reader refuses.
//!
//! Formats this module writes but never reads back (the custody event log and
//! the profile-root rebind log, both append-only records for people) are not
//! listed: no build fails on them, so no build should be refused over them.

use cerebellum_core::format_floor::DurableFormat;

/// Every format whose reader refuses a newer version, as that reader sees it.
pub fn readable_formats() -> Vec<DurableFormat> {
    vec![
        cerebellum_core::journal::AUDIT_JOURNAL_FORMAT,
        cerebellum_core::journal::REFUSAL_RING_FORMAT,
        crate::computer_grants::GRANT_STORE_FORMAT,
        crate::profile::REGISTRY_FORMAT,
        crate::profile_custody::CUSTODY_LOCK_FORMAT,
    ]
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
