//! Raw Windows creation times used by launch and profile custody.

use cerebellum_windows::process::{observe_process_generation, ProcessGenerationLiveness};

use crate::browser_launch::BrowserProcessGeneration;
use crate::profile_custody::{SupervisorGeneration, SupervisorLiveness};

pub use crate::browser_launch::GenerationUnit;

impl BrowserProcessGeneration {
    pub fn from_windows_filetime(pid: u32, creation_ticks: u64) -> Self {
        Self {
            pid,
            start_time_micros: creation_ticks,
            boot_id: None,
            generation_unit: Some(GenerationUnit::Filetime100ns),
        }
    }

    /// Legacy and contradictory records are not Windows generations.
    pub fn windows_filetime(self) -> Option<u64> {
        (self.generation_unit == Some(GenerationUnit::Filetime100ns)
            && self.boot_id.is_none()
            && self.pid != 0
            && self.start_time_micros != 0)
            .then_some(self.start_time_micros)
    }
}

impl SupervisorGeneration {
    pub fn from_windows_filetime(pid: u32, creation_ticks: u64) -> Self {
        Self {
            pid,
            start_time: creation_ticks,
            boot_id: None,
            generation_unit: Some(GenerationUnit::Filetime100ns),
        }
    }

    /// Legacy and contradictory records are not Windows generations.
    pub fn windows_filetime(self) -> Option<u64> {
        (self.generation_unit == Some(GenerationUnit::Filetime100ns)
            && self.boot_id.is_none()
            && self.pid != 0
            && self.start_time != 0)
            .then_some(self.start_time)
    }
}

pub(crate) fn observe_supervisor(generation: SupervisorGeneration) -> SupervisorLiveness {
    let Some(ticks) = generation.windows_filetime() else {
        return SupervisorLiveness::Unavailable;
    };
    match observe_process_generation(generation.pid, ticks) {
        ProcessGenerationLiveness::Live => SupervisorLiveness::Live,
        ProcessGenerationLiveness::Gone => SupervisorLiveness::NotLive,
        ProcessGenerationLiveness::Unknown => SupervisorLiveness::Unavailable,
    }
}

#[cfg(test)]
mod tests;
