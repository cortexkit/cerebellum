//! Installed Windows applications and launch admission. The OS seam supplies
//! shortcut, package, process and window facts; only this module binds them.

mod inventory;
mod windows;

pub use inventory::InstalledWindowsEntry;
pub(super) use inventory::LaunchInventory;
pub(super) use windows::{observe_running, open};

use super::identity::{Principal, IDENTITY_BOUND};
use crate::app_state::source::{AppStateReadError, BundleSignature, InstalledApp};
use std::time::Instant;

impl LaunchInventory {
    pub(super) fn signature(
        &self,
        app: &InstalledApp,
    ) -> Result<BundleSignature, AppStateReadError> {
        let fresh = self
            .fresh(app.clone(), Instant::now() + IDENTITY_BOUND)
            .ok_or(AppStateReadError::Unreadable)?;
        let signed = !matches!(fresh.principal, Principal::Unsigned { .. });
        Ok(BundleSignature {
            signed,
            ad_hoc: false,
            team_id: None,
            designated_requirement: signed.then(|| fresh.principal.to_string()),
            apple_anchored: false,
        })
    }
}

pub fn foreground_window() -> Option<u32> {
    cerebellum_windows::foreground_window_number()
}

pub fn foreground_sample() -> (Option<u32>, Option<u32>) {
    (foreground_window(), cerebellum_windows::last_input_tick())
}
