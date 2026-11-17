//! Select All can use an accessibility range without taking the person's focus.

use super::*;
use cerebellum_computer::app_state::source::ElementActionError;
use cerebellum_computer::audit::{AccessibilityReadScope, AuditToken};
use cerebellum_computer::platform::ProcessGrant;
use cerebellum_core::config::AppUse;

impl<B, R, T, S, D> ComputerPlane<B, R, T, S, D>
where
    B: CaptureBackend + Send + 'static,
    R: Redactor + Send + 'static,
    T: SeverityTaxonomy + Send + 'static,
    S: JournalStorage + Send + 'static,
    D: PlatformDriver + 'static,
{
    pub(super) async fn try_semantic_select_all(
        &self,
        parsed: &ParsedSynthetic,
        grant: &ProcessGrant,
        identity: &JournalIdentity,
        management: &Arc<ManagementPlane>,
        work: &quarantine::CallWork,
    ) -> Option<Value> {
        if !matches!(&parsed.action, SyntheticAction::KeyCombination { key: SyntheticKey::A, modifiers }
                if modifiers.command && !modifiers.shift && !modifiers.control && !modifiers.option && !modifiers.windows)
            || AppUse::Background != app_use::call_mode().unwrap_or(AppUse::Background)
            || self
                .app_state_source
                .frontmost_pid()
                .is_none_or(|pid| pid == grant.pid)
        {
            return None;
        }
        let source = self.app_state_source.clone();
        let grant = grant.clone();
        let identity = identity.clone();
        let sessions = management.app_state_sessions().clone();
        let name = management.application_name(&grant);
        let work = work.clone();
        let audit = AuditToken::new(self.audit.clone(), work.gate());
        tokio::task::spawn_blocking(move || {
            let _ax = work.bound_ax();
            let _scope = AccessibilityReadScope::new(grant.pid, None);
            let focus = match keystrokes::read_target_focus(source.as_ref(), &grant) {
                Ok(Some(focus)) => focus,
                Ok(None) => return None,
                Err(refusal) => return Some(keystrokes::refused_before_posting(refusal.reply())),
            };
            let facts = match source.element_facts(&focus.handle) {
                Ok(facts) if facts.pid.is_none_or(|pid| pid == grant.pid) && !facts.is_secure() => facts,
                _ => return Some(keystrokes::refused_before_posting(keystrokes::FocusRefusal::Unreadable.reply())),
            };
            if !matches!(facts.role.as_deref(), Some("AXTextField" | "AXTextArea" | "AXComboBox")) {
                return None;
            }
            let length = focus.before.as_ref()?.encode_utf16().count();
            match element_actions::person_check_before_action(source.as_ref(), &sessions, &identity.conversation_key, &grant) {
                Ok(element_actions::PersonCheck::Changed(change)) => return Some(keystrokes::refused_before_posting(element_actions::state_changed_by_person_reply(&name, change))),
                Err(()) => return Some(keystrokes::refused_before_posting(json!({"outcome":"observer_unavailable","reason":"hardware_input_observer_unavailable","remedy":"The input watcher could not confirm whether the person used this app. Nothing was selected; read_state again before retrying."}))),
                _ => {}
            }
            let mut seen = SeenMarks::read(source.as_ref(), &grant);
            seen.after_agent_input = true;
            let element_id = match element_actions::adopt(&sessions, &identity.conversation_key, &grant, &focus.handle) {
                Ok(id) => id,
                Err(reply) => return Some(keystrokes::refused_before_posting(reply)),
            };
            let mut journal = element_actions::ElementJournal::new(audit, identity.clone(), ComputerCapability::Keys, &grant);
            let role = facts.role.as_deref().unwrap_or("unknown");
            let token = match journal.intent(&grant, &element_id, "SelectRange", role) {
                Ok(token) => token,
                Err(refusal) => return Some(keystrokes::refused_before_posting(refusal.reply())),
            };
            let selection = source.select_range(&focus.handle, (0, length));
            // The setter checks the range attribute's own settability. An
            // accepted setter with an unreadable result must never fall through
            // to a chord that would bring the application forward.
            let result = match selection {
                Err(ElementActionError::Unsupported | ElementActionError::UnsupportedOnPlatform | ElementActionError::Gone) => None,
                Ok(()) => match source.selected_range(&focus.handle) {
                    Ok(Some((0, selected))) if selected == length => match source.text_value(&focus.handle) {
                        Ok(Some(value)) if value.encode_utf16().count() == length => Some(true),
                        Ok(_) => None,
                        Err(_) => Some(false),
                    },
                    Ok(_) => None,
                    Err(_) => Some(false),
                },
                Err(_) => Some(false),
            };
            let outcome = match result { Some(true) => "completed", Some(false) => "delivery_unconfirmed", None => "dispatch_failed" };
            let _ = journal.outcome(token, outcome);
            if journal.finish().is_err() {
                return Some(json!({"outcome":"audit_unavailable","effect_status":"effect_indeterminate","target_fronted":false,"containment_rung":"semantic_element","posts_returned":0,"remedy":"The selection may have changed, but its result could not be recorded. Nothing was brought forward; read the state before retrying."}));
            }
            result.map(|confirmed| {
                if confirmed { sessions.remember_seen(&identity.conversation_key, &grant, seen); }
                let mut reply = json!({"outcome":outcome,"effect_status":if confirmed {"effect_observed"} else {"effect_indeterminate"},"target_fronted":false,"containment_rung":"semantic_element","posts_returned":0});
                if !confirmed {
                    reply["remedy"] = json!("The selection was requested, but its result could not be read. Nothing was posted or brought forward. Selecting all again is safe; retry if needed.");
                }
                reply
            })
        }).await.unwrap_or_else(|_| Some(json!({"outcome":"delivery_unconfirmed","effect_status":"effect_indeterminate","target_fronted":false,"containment_rung":"semantic_element","posts_returned":0,"remedy":"The selection result could not be read. Nothing was posted or brought forward; selecting all again is safe."})))
    }
}
