//! Plane-neutral late-event obligations and delivery routing.

use std::collections::BTreeMap;

use super::JournalIdentity;

/// The closed delivery route set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryRoute {
    Direct,
    Wait,
    RecordOnly,
}

/// Neutral causes; an adapter may expose a strict subset of these values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub enum LateEventCause {
    QueueFull,
    AllocatorFailed,
    CommitmentFailed,
    Backpressure,
    BoundUnavailable,
    DescriptorRefused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LateEventError {
    pub cause: LateEventCause,
}

impl LateEventError {
    pub const fn new(cause: LateEventCause) -> Self {
        Self { cause }
    }
}

/// Opaque event data admitted by a plane adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LateEventDescriptor {
    pub identity: JournalIdentity,
    pub opaque_bytes: Vec<u8>,
}

/// An admitted sequence. The field is private so callers cannot manufacture a
/// delivery reference for an event that was never admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LateEventSequence(u64);

impl LateEventSequence {
    pub fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LateDelivery {
    pub sequence: LateEventSequence,
    pub descriptor: LateEventDescriptor,
}

#[derive(Debug, Clone)]
struct LateRecord {
    descriptor: LateEventDescriptor,
    route: DeliveryRoute,
    committed: bool,
}

/// A bounded late-event obligation queue.
#[derive(Debug, Clone)]
pub struct LateEventQueue {
    bound: usize,
    next_sequence: u64,
    records: BTreeMap<u64, LateRecord>,
    faults: BTreeMap<LateEventCause, usize>,
}

impl LateEventQueue {
    pub fn new(bound: usize) -> Result<Self, LateEventError> {
        if bound == 0 {
            return Err(LateEventError::new(LateEventCause::BoundUnavailable));
        }
        Ok(Self {
            bound,
            next_sequence: 1,
            records: BTreeMap::new(),
            faults: BTreeMap::new(),
        })
    }

    pub fn bound(&self) -> usize {
        self.bound
    }

    pub fn combined_count(&self) -> usize {
        self.records.len()
    }

    pub fn arm_fault(&mut self, cause: LateEventCause, count: usize) {
        self.faults.insert(cause, count);
    }

    fn take_fault(&mut self, cause: LateEventCause) -> bool {
        match self.faults.get_mut(&cause) {
            Some(count) if *count > 0 => {
                *count -= 1;
                true
            }
            _ => false,
        }
    }

    /// Admit an event without allocating a sequence until the bound and
    /// descriptor checks have passed.
    pub fn admit_late_event(
        &mut self,
        descriptor: LateEventDescriptor,
        route: DeliveryRoute,
    ) -> Result<LateEventSequence, LateEventError> {
        if descriptor.opaque_bytes.is_empty() || self.take_fault(LateEventCause::DescriptorRefused)
        {
            return Err(LateEventError::new(LateEventCause::DescriptorRefused));
        }
        if self.records.len() >= self.bound {
            return Err(LateEventError::new(LateEventCause::QueueFull));
        }
        if self.take_fault(LateEventCause::AllocatorFailed) {
            return Err(LateEventError::new(LateEventCause::AllocatorFailed));
        }
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.records.insert(
            sequence,
            LateRecord {
                descriptor,
                route,
                committed: false,
            },
        );
        Ok(LateEventSequence(sequence))
    }

    /// Commit an admitted event. A failed commitment remains recoverable.
    pub fn commit_late_event(&mut self, sequence: LateEventSequence) -> Result<(), LateEventError> {
        if !self.records.contains_key(&sequence.0) {
            return Err(LateEventError::new(LateEventCause::CommitmentFailed));
        }
        if self.take_fault(LateEventCause::CommitmentFailed) {
            return Err(LateEventError::new(LateEventCause::CommitmentFailed));
        }
        self.records
            .get_mut(&sequence.0)
            .expect("checked above")
            .committed = true;
        Ok(())
    }

    /// Take the lowest committed item for the requested route.
    pub fn take_late_delivery(
        &mut self,
        route: DeliveryRoute,
    ) -> Result<LateDelivery, LateEventError> {
        let unresolved_wait = self
            .records
            .values()
            .any(|record| record.route == DeliveryRoute::Wait && !record.committed);
        if unresolved_wait {
            return Err(LateEventError::new(LateEventCause::Backpressure));
        }
        let sequence = self
            .records
            .iter()
            .find(|(_, record)| record.route == route && record.committed)
            .map(|(sequence, _)| *sequence)
            .ok_or_else(|| LateEventError::new(LateEventCause::Backpressure))?;
        let record = self.records.get(&sequence).expect("selected record exists");
        Ok(LateDelivery {
            sequence: LateEventSequence(sequence),
            descriptor: record.descriptor.clone(),
        })
    }

    /// Recover an admitted but uncommitted item at its original sequence.
    pub fn confirm_late_delivery(&mut self, sequence: LateEventSequence) -> bool {
        let committed = self
            .records
            .get(&sequence.0)
            .map(|record| record.committed)
            .unwrap_or(false);
        committed && self.records.remove(&sequence.0).is_some()
    }

    pub fn release_late_event(&mut self, sequence: LateEventSequence) -> bool {
        self.records.remove(&sequence.0).is_some()
    }

    pub fn recover_late_event(&mut self, sequence: LateEventSequence) -> bool {
        self.records
            .get_mut(&sequence.0)
            .map(|record| {
                record.committed = true;
                true
            })
            .unwrap_or(false)
    }

    pub fn has_uncommitted(&self) -> bool {
        self.records.values().any(|record| !record.committed)
    }

    pub fn uncommitted_count(&self) -> usize {
        self.records
            .values()
            .filter(|record| !record.committed)
            .count()
    }

    pub fn is_committed(&self, sequence: LateEventSequence) -> bool {
        self.records
            .get(&sequence.0)
            .map(|record| record.committed)
            .unwrap_or(false)
    }

    pub fn committed_count(&self, route: DeliveryRoute) -> usize {
        self.records
            .values()
            .filter(|record| record.route == route && record.committed)
            .count()
    }
}
