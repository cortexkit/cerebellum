//! Durable journal storage bindings.
//!
//! The in-memory binding is intentionally small but models restart correctly:
//! cloned bindings share durable state, while handles and tokens remain local to
//! the binding that minted them.

use std::sync::{Arc, Mutex};

use super::{DurableState, StorageError};

/// Storage contract used by the lifecycle binding.
pub trait JournalStorage: Clone {
    fn load(&self) -> Result<DurableState, StorageError>;
    fn save(&self, state: &DurableState) -> Result<(), StorageError>;
}

/// A process-independent durable state model for fixtures and compatibility
/// adapters. Cloning this value models opening the same journal after restart.
#[derive(Clone, Debug, Default)]
pub struct InMemoryJournalStorage {
    state: Arc<Mutex<DurableState>>,
}

impl InMemoryJournalStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

impl JournalStorage for InMemoryJournalStorage {
    fn load(&self) -> Result<DurableState, StorageError> {
        self.state
            .lock()
            .map(|state| state.clone())
            .map_err(|_| StorageError::Unavailable)
    }

    fn save(&self, state: &DurableState) -> Result<(), StorageError> {
        self.state
            .lock()
            .map(|mut current| {
                *current = state.clone();
            })
            .map_err(|_| StorageError::Unavailable)
    }
}
