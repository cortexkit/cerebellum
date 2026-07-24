//! Retained governing observations and snapshot retention.
//!
//! Cerebellum retains each caller-visible observation from a successful
//! `browser.snapshot` (redacted textual `content`) or `browser.screenshot`
//! (exact `image_png_b64`). At most `snapshot_retention_count` observations are
//! physically retained per live session across all document epochs; every
//! retained observation, including a pinned prior-epoch one, consumes one slot
//! until its backing bytes are deleted.
//!
//! An action requiring a governing snapshot atomically validates and pins that
//! observation. A pinned observation cannot be evicted or deleted before the
//! pending action reaches a durable terminal point (pre-dispatch rejection
//! finalization, dispatch commitment, or proven-safe cancellation); the pin is
//! released only then. A document-epoch transition invalidates every prior-epoch
//! observation: unpinned bytes are deleted immediately, pinned bytes remain
//! charged until the matching reservation reaches a durable terminal point.
//! Graceful teardown releases every remaining pin and slot exactly once after
//! every pending action has reached a durable terminal point.

use std::collections::BTreeMap;

use crate::journal::{GoverningObservation, ImageObservationPolicy, TextObservationPolicy};

/// A retained caller-visible observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observation {
    /// Redacted textual AX-snapshot content.
    Text { content: String },
    /// The exact returned screenshot base64 string.
    Screenshot { image_png_b64: String },
}

impl Observation {
    /// Build the governing-observation block for this retained bytes.
    pub fn to_governing(&self) -> GoverningObservation {
        match self {
            Observation::Text { content } => GoverningObservation::Text {
                bytes_utf8: content.clone(),
                observation_policy: TextObservationPolicy::RedactionV1,
            },
            Observation::Screenshot { image_png_b64 } => GoverningObservation::ImagePngB64 {
                bytes_utf8: image_png_b64.clone(),
                observation_policy: ImageObservationPolicy::VisualUnredactedV1,
            },
        }
    }
}

/// Failure of a snapshot-retention operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotError {
    /// All retention slots are pinned; no slot can be reserved and no capture
    /// occurs. Maps to B1's `result_serialization_limit`.
    ResultSerializationLimit,
    /// The requested observation was evicted or invalidated. Maps to B1's
    /// `stale_snapshot`.
    StaleSnapshot,
    /// Teardown has begun; no new validation, pin, or capture is permitted.
    TeardownInProgress,
}

#[derive(Debug, Clone)]
struct ObservationRecord {
    observation: Observation,
    epoch: u64,
    pin_count: usize,
    invalidated: bool,
}

/// The session-scoped snapshot retention store.
#[derive(Debug)]
pub struct SnapshotStore {
    retention_count: usize,
    records: BTreeMap<String, ObservationRecord>,
    /// Insertion order for oldest-first eviction.
    insertion_order: Vec<String>,
    epoch: u64,
    teardown_started: bool,
}

impl SnapshotStore {
    /// Create a store with a concrete positive retention count.
    pub fn new(retention_count: usize) -> Result<Self, SnapshotError> {
        if retention_count == 0 {
            return Err(SnapshotError::ResultSerializationLimit);
        }
        Ok(Self {
            retention_count,
            records: BTreeMap::new(),
            insertion_order: Vec::new(),
            epoch: 0,
            teardown_started: false,
        })
    }

    pub fn current_epoch(&self) -> u64 {
        self.epoch
    }

    pub fn retained_count(&self) -> usize {
        self.records.len()
    }

    pub fn pin_count(&self, id: &str) -> usize {
        self.records.get(id).map(|r| r.pin_count).unwrap_or(0)
    }

    /// Whether an observation is currently available for validation/pin.
    pub fn is_available(&self, id: &str) -> bool {
        self.records
            .get(id)
            .map(|r| !r.invalidated)
            .unwrap_or(false)
    }

    /// Retain a new observation, atomically reserving one session-wide slot.
    ///
    /// Evicts the oldest unpinned observation from any epoch when necessary. If
    /// every slot is pinned, no slot is reserved, no capture occurs, and
    /// `ResultSerializationLimit` is returned.
    pub fn retain(
        &mut self,
        id: impl Into<String>,
        observation: Observation,
    ) -> Result<(), SnapshotError> {
        if self.teardown_started {
            return Err(SnapshotError::TeardownInProgress);
        }
        let id = id.into();
        // If this id is already retained, replace it in place (no new slot).
        if self.records.contains_key(&id) {
            self.records.insert(
                id,
                ObservationRecord {
                    observation,
                    epoch: self.epoch,
                    pin_count: 0,
                    invalidated: false,
                },
            );
            return Ok(());
        }
        // Reserve a slot, evicting the oldest unpinned observation if needed.
        if self.records.len() >= self.retention_count && !self.evict_oldest_unpinned() {
            return Err(SnapshotError::ResultSerializationLimit);
        }
        self.insertion_order.push(id.clone());
        self.records.insert(
            id,
            ObservationRecord {
                observation,
                epoch: self.epoch,
                pin_count: 0,
                invalidated: false,
            },
        );
        Ok(())
    }

    /// Atomically validate and pin an observation, returning its bytes.
    ///
    /// Fails with `StaleSnapshot` if the observation was evicted or invalidated.
    pub fn validate_and_pin(&mut self, id: &str) -> Result<Observation, SnapshotError> {
        if self.teardown_started {
            return Err(SnapshotError::TeardownInProgress);
        }
        let record = self
            .records
            .get_mut(id)
            .filter(|r| !r.invalidated)
            .ok_or(SnapshotError::StaleSnapshot)?;
        record.pin_count += 1;
        Ok(record.observation.clone())
    }

    /// Release one pin on an observation at a durable terminal point.
    ///
    /// When an invalidated observation's last pin is released, its backing bytes
    /// are deleted and its slot is freed exactly once.
    pub fn release_pin(&mut self, id: &str) {
        let should_remove = if let Some(record) = self.records.get_mut(id) {
            record.pin_count = record.pin_count.saturating_sub(1);
            record.pin_count == 0 && record.invalidated
        } else {
            false
        };
        if should_remove {
            self.remove_observation(id);
        }
    }

    /// Transition to a new document epoch.
    ///
    /// Atomically makes every prior-epoch observation unavailable to new
    /// validation and pin acquisition. Unpinned prior-epoch bytes are deleted
    /// immediately; pinned prior-epoch bytes remain charged until their pin is
    /// released. The session-wide slot count is unchanged.
    pub fn transition_epoch(&mut self, new_epoch: u64) {
        self.epoch = new_epoch;
        let prior_ids: Vec<String> = self
            .records
            .iter()
            .filter(|(_, r)| r.epoch < new_epoch)
            .map(|(id, _)| id.clone())
            .collect();
        for id in prior_ids {
            let unpinned = {
                let record = self.records.get_mut(&id).expect("present");
                record.invalidated = true;
                record.pin_count == 0
            };
            if unpinned {
                self.remove_observation(&id);
            }
        }
    }

    // ------------------------------------------------------------------
    // Graceful teardown
    // ------------------------------------------------------------------

    /// Begin graceful teardown: prevent new validation, pin acquisition,
    /// capture, and dispatch.
    pub fn begin_teardown(&mut self) {
        self.teardown_started = true;
    }

    /// Whether teardown may complete: every pin must have been released at a
    /// durable terminal point.
    pub fn teardown_ready(&self) -> bool {
        self.records.values().all(|r| r.pin_count == 0)
    }

    /// Complete graceful teardown, releasing every remaining slot and deleting
    /// the session-scoped observation bytes exactly once.
    ///
    /// Fails if any pin is still held (a pending action has not reached a
    /// durable terminal point); teardown cannot delete those bytes yet.
    pub fn complete_teardown(&mut self) -> Result<(), SnapshotError> {
        if !self.teardown_ready() {
            return Err(SnapshotError::TeardownInProgress);
        }
        self.records.clear();
        self.insertion_order.clear();
        Ok(())
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    fn evict_oldest_unpinned(&mut self) -> bool {
        // Walk insertion order oldest-first, evicting the first unpinned,
        // non-invalidated observation.
        let candidate = self
            .insertion_order
            .iter()
            .find(|id| {
                self.records
                    .get(*id)
                    .map(|r| r.pin_count == 0)
                    .unwrap_or(false)
            })
            .cloned();
        match candidate {
            Some(id) => {
                self.remove_observation(&id);
                true
            }
            None => false,
        }
    }

    fn remove_observation(&mut self, id: &str) {
        self.records.remove(id);
        self.insertion_order.retain(|x| x != id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(content: &str) -> Observation {
        Observation::Text {
            content: content.to_string(),
        }
    }

    #[test]
    fn retention_count_must_be_positive() {
        assert!(SnapshotStore::new(0).is_err());
        assert!(SnapshotStore::new(1).is_ok());
    }

    #[test]
    fn oldest_unpinned_is_evicted_across_epochs() {
        let mut store = SnapshotStore::new(2).unwrap();
        store.retain("s1", text("a")).unwrap();
        store.transition_epoch(1);
        store.retain("s2", text("b")).unwrap();
        // Third observation evicts the oldest unpinned (s1, prior epoch).
        store.retain("s3", text("c")).unwrap();
        assert_eq!(store.retained_count(), 2);
        assert!(!store.is_available("s1"));
        assert!(store.is_available("s2"));
        assert!(store.is_available("s3"));
    }

    #[test]
    fn all_slots_pinned_rejects_without_capture_or_leak() {
        let mut store = SnapshotStore::new(2).unwrap();
        store.retain("s1", text("a")).unwrap();
        store.retain("s2", text("b")).unwrap();
        store.validate_and_pin("s1").unwrap();
        store.validate_and_pin("s2").unwrap();
        // Every slot pinned: no slot reserved, no capture.
        let err = store.retain("s3", text("c")).unwrap_err();
        assert_eq!(err, SnapshotError::ResultSerializationLimit);
        assert_eq!(store.retained_count(), 2);
    }

    #[test]
    fn epoch_transition_deletes_unpinned_prior_epoch_immediately() {
        let mut store = SnapshotStore::new(4).unwrap();
        store.retain("s1", text("a")).unwrap();
        store.retain("s2", text("b")).unwrap();
        store.validate_and_pin("s2").unwrap();
        store.transition_epoch(1);
        // s1 unpinned prior-epoch: deleted immediately.
        assert!(!store.is_available("s1"));
        assert_eq!(store.retained_count(), 1);
        // s2 pinned prior-epoch: remains charged and invalidated.
        assert!(store.records.contains_key("s2"));
        assert!(store.records["s2"].invalidated);
        // A pinned invalidated observation cannot be re-pinned.
        assert_eq!(
            store.validate_and_pin("s2").unwrap_err(),
            SnapshotError::StaleSnapshot
        );
        // Releasing the last pin deletes it and frees the slot exactly once.
        store.release_pin("s2");
        assert!(!store.records.contains_key("s2"));
        assert_eq!(store.retained_count(), 0);
    }

    #[test]
    fn pin_released_exactly_once_at_terminal_point() {
        let mut store = SnapshotStore::new(2).unwrap();
        store.retain("s1", text("a")).unwrap();
        store.validate_and_pin("s1").unwrap();
        store.validate_and_pin("s1").unwrap();
        assert_eq!(store.pin_count("s1"), 2);
        store.release_pin("s1");
        assert_eq!(store.pin_count("s1"), 1);
        store.release_pin("s1");
        assert_eq!(store.pin_count("s1"), 0);
        // Extra release is a harmless no-op (saturating).
        store.release_pin("s1");
        assert_eq!(store.pin_count("s1"), 0);
    }

    #[test]
    fn teardown_cannot_complete_while_a_pin_is_held() {
        let mut store = SnapshotStore::new(2).unwrap();
        store.retain("s1", text("a")).unwrap();
        store.validate_and_pin("s1").unwrap();
        store.begin_teardown();
        // New capture/validation prohibited during teardown.
        assert_eq!(
            store.retain("s2", text("b")).unwrap_err(),
            SnapshotError::TeardownInProgress
        );
        // Teardown cannot complete while the pin is held.
        assert!(!store.teardown_ready());
        assert!(store.complete_teardown().is_err());
        // After the durable terminal point releases the pin, teardown completes.
        store.release_pin("s1");
        assert!(store.teardown_ready());
        store.complete_teardown().unwrap();
        assert_eq!(store.retained_count(), 0);
    }

    #[test]
    fn governing_observation_carries_exact_retained_bytes() {
        let mut store = SnapshotStore::new(2).unwrap();
        store.retain("s1", text("redacted-content")).unwrap();
        let obs = store.validate_and_pin("s1").unwrap();
        match obs.to_governing() {
            GoverningObservation::Text { bytes_utf8, .. } => {
                assert_eq!(bytes_utf8, "redacted-content");
            }
            _ => panic!("expected text governing observation"),
        }
        store.release_pin("s1");
    }
}
