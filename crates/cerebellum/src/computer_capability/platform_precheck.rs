use cerebellum_core::journal::{JournalStorage, Redactor, SeverityTaxonomy};
use serde_json::Value;

#[cfg(target_os = "linux")]
use super::serialize;
#[cfg(windows)]
use super::{parse_wait_request, wait_wire_reply, Served};
use super::{ComputerPlane, Servable};
#[cfg(windows)]
use cerebellum_computer::dispatch::{WaitEvidence, WaitOutcome, WaitResult};
#[cfg(windows)]
use cerebellum_computer::platform::AccessibilityReadbackAttribute;

impl<B, R: Redactor, T: SeverityTaxonomy, S: JournalStorage, D> ComputerPlane<B, R, T, S, D> {
    #[cfg(target_os = "linux")]
    pub(super) async fn platform_precheck(
        &self,
        capability: Servable,
        _arguments: &Value,
    ) -> Option<Value> {
        let session = self.linux_session.as_ref()?;
        let refusal = session.refusal(capability.capability()).await?;
        Some(serialize::refused_in_queue(capability, refusal))
    }

    #[cfg(windows)]
    pub(super) async fn platform_precheck(
        &self,
        capability: Servable,
        arguments: &Value,
    ) -> Option<Value> {
        if !matches!(capability.0, Served::Wait) {
            return None;
        }
        #[cfg(test)]
        if self.windows_app_state_for_test.is_some() {
            return None;
        }
        let parsed = parse_wait_request(arguments).ok()?;
        if parsed.predicate.readback_attribute() != AccessibilityReadbackAttribute::Value {
            return None;
        }
        Some(wait_wire_reply(WaitResult {
            outcome: WaitOutcome::Indeterminate,
            evidence: WaitEvidence::Indeterminate {
                predicate: parsed.predicate,
                readback: None,
                reason: "scoped_read_unsupported".to_owned(),
            },
            attempts: 0,
        }))
    }
}
