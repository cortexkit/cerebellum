//! Call-time permission admission from the plane's immutable startup readings.

use cerebellum_computer::audit::ComputerCapability;
use cerebellum_computer::platform::{
    vocabulary::required_permission_services, PermissionLiveness, PermissionLivenessReport,
    PermissionService,
};
use serde_json::{json, Value};

pub(super) fn refusal(
    capability: ComputerCapability,
    report: &PermissionLivenessReport,
) -> Option<Value> {
    let mut services = match required_permission_services(capability.capability_id()) {
        Ok(services) => services,
        Err(_) => {
            return Some(json!({
                "outcome": "not_servable",
                "remedy": "this capability's permission requirements cannot be read; report it",
            }))
        }
    };
    // The pointer move and drag also hit-test through accessibility. Preserve
    // that requirement from the advertisement gate even though their frozen
    // rows name only the posting/monitoring services.
    if matches!(
        capability,
        ComputerCapability::TakeoverMove | ComputerCapability::TakeoverDrag
    ) {
        services.push(PermissionService::Accessibility);
    }
    services.into_iter().find_map(|service| {
        let state = report.state(service);
        if state == PermissionLiveness::Live {
            return None;
        }
        let (permission, label) = match service {
            PermissionService::Accessibility | PermissionService::PostEvent => {
                ("accessibility", "Accessibility")
            }
            PermissionService::ScreenRecording => ("screen_recording", "Screen Recording"),
            PermissionService::InputMonitoring | PermissionService::RawHidObservation => {
                ("input_monitoring", "Input Monitoring")
            }
        };
        let remedy = if state == PermissionLiveness::GrantedPendingRelaunch {
            "restart cerebellum to use the permission already granted to ck-cerebellum".to_string()
        } else {
            format!(
                "grant {label} to ck-cerebellum in System Settings > Privacy & Security, then \
                 restart cerebellum; permission readings are taken only at startup"
            )
        };
        Some(json!({
            "outcome": "permission_missing",
            "detail": {"permission": permission, "state": state},
            "remedy": remedy,
        }))
    })
}

#[cfg(test)]
pub(crate) fn live_for_test() -> PermissionLivenessReport {
    PermissionLivenessReport::from_results(
        [
            PermissionService::Accessibility,
            PermissionService::ScreenRecording,
            PermissionService::InputMonitoring,
            PermissionService::PostEvent,
        ]
        .into_iter()
        .map(
            |service| cerebellum_computer::platform::PermissionProbeResult {
                service,
                liveness: PermissionLiveness::Live,
                responsible_process: "ck-cerebellum".into(),
                off_main: true,
            },
        ),
    )
}
