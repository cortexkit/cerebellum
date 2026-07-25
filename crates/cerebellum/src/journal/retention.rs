//! Provides browser-facing retention settings and maps them to the core
//! journal's capacity limits and retention behavior.

use super::store::JournalStore;
use super::{JournalConfig, JournalError};

impl JournalStore {
    pub fn retention_get(&self) -> JournalConfig {
        self.config()
    }

    pub fn retention_set(
        &mut self,
        proposed: JournalConfig,
    ) -> Result<JournalConfig, JournalError> {
        self.retention_set_core(proposed)?;
        Ok(proposed)
    }
}
