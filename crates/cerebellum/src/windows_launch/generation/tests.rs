use super::*;
use crate::profile_custody::{
    current_supervisor_generation, KernelSupervisorLiveness, SupervisorLivenessProbe,
};

#[test]
fn windows_generations_round_trip_and_distinguish_one_filetime_tick() {
    let ticks = 134_000_000_000_000_001;
    let first = BrowserProcessGeneration::from_windows_filetime(42, ticks);
    let next = BrowserProcessGeneration::from_windows_filetime(42, ticks + 1);
    let reopen = |generation| -> BrowserProcessGeneration {
        serde_json::from_slice(&serde_json::to_vec(&generation).unwrap()).unwrap()
    };
    assert_eq!(reopen(first), first);
    assert_eq!(reopen(next).windows_filetime(), Some(ticks + 1));
    assert_ne!(reopen(first), reopen(next));
    assert_eq!(
        serde_json::to_string(&first).unwrap(),
        r#"{"pid":42,"start_time_micros":134000000000000001,"generation_unit":"filetime_100ns"}"#
    );

    let first = SupervisorGeneration::from_windows_filetime(42, ticks);
    let next = SupervisorGeneration::from_windows_filetime(42, ticks + 1);
    let reopen = |generation| -> SupervisorGeneration {
        serde_json::from_slice(&serde_json::to_vec(&generation).unwrap()).unwrap()
    };
    assert_eq!(reopen(first), first);
    assert_eq!(reopen(next).windows_filetime(), Some(ticks + 1));
    assert_ne!(reopen(first), reopen(next));
    assert_eq!(
        serde_json::to_string(&first).unwrap(),
        r#"{"pid":42,"start_time":134000000000000001,"generation_unit":"filetime_100ns"}"#
    );
}

#[test]
fn windows_supervisor_observation_requires_the_filetime_discriminator() {
    let own = current_supervisor_generation().unwrap();
    assert_eq!(own.pid, std::process::id());
    assert_eq!(
        KernelSupervisorLiveness.observe(own),
        SupervisorLiveness::Live
    );
    let mut unmarked = serde_json::to_value(own).unwrap();
    unmarked.as_object_mut().unwrap().remove("generation_unit");
    let unmarked: SupervisorGeneration = serde_json::from_value(unmarked).unwrap();
    assert_eq!(unmarked.windows_filetime(), None);
    assert_eq!(
        KernelSupervisorLiveness.observe(unmarked),
        SupervisorLiveness::Unavailable
    );
    let unmarked: BrowserProcessGeneration =
        serde_json::from_str(r#"{"pid":42,"start_time_micros":134000000000000001}"#).unwrap();
    assert_eq!(unmarked.windows_filetime(), None);
}
