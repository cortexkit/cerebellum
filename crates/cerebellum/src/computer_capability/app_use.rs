//! The live `computer_use.app_use` setting.
//!
//! Each call takes the latest effective mode delivered by the daemon. A
//! foreground setting that the daemon did not attest as approved still needs
//! the person's operator confirmation, held only in memory.
//!
use std::sync::{Mutex, MutexGuard};

use cerebellum_core::config::AppUse;

use crate::settings::LiveSettings;

#[derive(Default)]
pub(crate) struct LiveAppUse {
    settings: Mutex<LiveSettings>,
    approval: super::app_use_approval::Approval,
}

impl LiveAppUse {
    #[cfg(test)]
    pub(crate) fn approved_for_test(app_use: AppUse) -> Self {
        let live = Self::default();
        live.apply(LiveSettings {
            app_use,
            approved: true,
        });
        live
    }

    /// For fixtures that exercise the foreground badge.
    pub(crate) fn foreground_for_test() -> Self {
        Self {
            settings: Mutex::new(LiveSettings {
                app_use: AppUse::Foreground,
                approved: false,
            }),
            approval: super::app_use_approval::Approval::foreground_fixture(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, LiveSettings> {
        self.settings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    #[cfg(any(test, target_os = "macos", target_os = "windows"))]
    pub(crate) fn apply(&self, settings: LiveSettings) {
        let mut current = self.lock();
        *current = settings;
        self.approval
            .observe((!settings.approved).then_some(settings.app_use));
    }

    pub(crate) fn settings_for_call(&self) -> LiveSettings {
        let current = self.lock();
        self.approval
            .observe((!current.approved).then_some(current.app_use));
        *current
    }

    pub(crate) async fn approved_mode(
        &self,
        settings: LiveSettings,
        cancel: &crate::CancelHandle,
    ) -> AppUse {
        if settings.approved {
            settings.app_use
        } else {
            self.approval.resolve(settings.app_use, cancel).await
        }
    }
}

tokio::task_local! {
    /// The mode the running `computer_use` call was admitted under, read once
    /// when the call arrived so every step of the call agrees on it.
    static CALL_APP_USE: AppUse;
}

/// Run `work` as a call whose mode is `mode`.
pub(crate) async fn scope<F: std::future::Future>(mode: AppUse, work: F) -> F::Output {
    CALL_APP_USE.scope(mode, work).await
}

/// The mode of the `computer_use` call this task is serving, or `None`
/// outside one.
// Only this crate's tests read it so far. Code that acts differently in the
// two modes reads the call's mode through this function.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn call_mode() -> Option<AppUse> {
    CALL_APP_USE.try_with(|mode| *mode).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn the_call_mode_is_set_only_inside_its_scope() {
        assert_eq!(call_mode(), None);
        assert_eq!(
            scope(AppUse::Foreground, async { call_mode() }).await,
            Some(AppUse::Foreground)
        );
        assert_eq!(call_mode(), None);
    }
}

#[cfg(test)]
mod serve_tests {
    use super::*;
    use crate::computer_capability::{
        permissions, servable, ComputerPlane, ResultSchemaEnforcement, ServeContext,
    };
    use cerebellum_computer::audit::redaction::ExcludeApplicationText;
    use cerebellum_computer::audit::ComputerAudit;
    use cerebellum_computer::capture::InMemoryCaptureBackend;
    use cerebellum_computer::capture_custody::{
        CaptureCustody, CustodyBounds, InMemoryCustodyStorage, InMemoryGrantAuthority,
    };
    use cerebellum_computer::platform::TargetResolution;
    use cerebellum_core::clock::FakeClock;
    use cerebellum_core::journal::{
        InMemoryJournalStorage, JournalConfig, JournalIdentity, ValidatedSeverityTaxonomy,
    };
    use serde_json::{json, Value};
    use std::sync::Arc;

    type Plane = ComputerPlane<
        InMemoryCaptureBackend,
        ExcludeApplicationText,
        ValidatedSeverityTaxonomy,
        InMemoryJournalStorage,
    >;

    struct MissingTarget;

    impl crate::management::TargetResolver for MissingTarget {
        fn resolve(&self, _bundle_identity: &str) -> TargetResolution {
            TargetResolution::NotRunning
        }
    }

    fn audit(
    ) -> ComputerAudit<ExcludeApplicationText, ValidatedSeverityTaxonomy, InMemoryJournalStorage>
    {
        let custody = CaptureCustody::new(
            CustodyBounds {
                maximum_verification_duration_ms: 100,
                maximum_pin_lifetime_ms: 100,
                maximum_concurrently_pinned_artifacts: 2,
                maximum_total_pinned_artifact_bytes: 1000,
                maximum_custody_attachment_bytes: 1000,
            },
            InMemoryGrantAuthority::default(),
            InMemoryCustodyStorage::new(),
        )
        .unwrap();
        ComputerAudit::new(
            ExcludeApplicationText,
            cerebellum_computer::platform::severity::load_severity_taxonomy().unwrap(),
            JournalConfig {
                journal_retention_bytes: 20000,
                journal_max_entry_bytes: 4000,
            },
            InMemoryJournalStorage::default(),
            custody,
        )
        .unwrap()
    }

    fn plane(live: LiveAppUse) -> Plane {
        ComputerPlane::with_result_schema_enforcement(audit(), ResultSchemaEnforcement::DetectOnly)
            .with_permission_liveness(permissions::live_for_test())
            .with_app_use(live)
    }

    #[test]
    fn a_plane_from_any_constructor_defaults_to_background() {
        let planes: [Plane; 3] = [
            ComputerPlane::new(audit()),
            ComputerPlane::with_result_schema_enforcement(
                audit(),
                ResultSchemaEnforcement::Withhold,
            ),
            ComputerPlane::with_synthetic_driver(
                audit(),
                cerebellum_computer::platform::UnsupportedPlatformDriver::new,
            ),
        ];
        for plane in planes {
            assert_eq!(plane.app_use.settings_for_call(), LiveSettings::default());
        }
    }

    fn identity() -> JournalIdentity {
        JournalIdentity {
            witness: cerebellum_core::dispatch_witness::DispatchWitness::detached(),
            principal: "prefrontal".into(),
            conversation_key: "conversation-1".into(),
            agent_project_id: "project-1".into(),
            session_kind: cerebellum_core::identity::SessionKind::Primary,
            origin: Default::default(),
            computer_order: None,
        }
    }

    async fn serve(
        plane: &Plane,
        management: &Arc<crate::management::ManagementPlane>,
        capability_id: &str,
        arguments: Value,
    ) -> Value {
        let clock = FakeClock::new();
        plane
            .serve(
                servable(capability_id).unwrap(),
                &arguments,
                ServeContext {
                    cancel: crate::CancelHandle::for_uninterruptible_probe(),
                    grantee: "project-1",
                    identity: identity(),
                    management,
                    consent: crate::computer_grants::ConsentContext::without_carrier(
                        crate::computer_grants::GrantCaller::new(
                            "conversation-1".into(),
                            "project-1".into(),
                            false,
                        ),
                    ),
                    clock: &clock,
                    now_ms: 10,
                },
                |_| InMemoryCaptureBackend::default(),
            )
            .await
            .expect("detect-only serving returns every reply")
    }

    fn management() -> Arc<crate::management::ManagementPlane> {
        Arc::new(crate::management::ManagementPlane::new(Arc::new(
            MissingTarget,
        )))
    }

    fn wait_arguments() -> Value {
        json!({
            "app": "com.example.Editor",
            "predicate": "element_enabled_is true Role:Title=AXButton:Save",
            "timeout_ms": 0,
        })
    }

    #[tokio::test]
    async fn an_unapproved_foreground_setting_reaches_serve_only_as_background() {
        let live = LiveAppUse::default();
        live.apply(LiveSettings {
            app_use: AppUse::Foreground,
            approved: false,
        });
        let plane = plane(live);
        let management = management();
        let note = crate::tool_result::APP_USE_NOTE
            .scope(std::cell::RefCell::new(None), async {
                serve(&plane, &management, "computer.wait", wait_arguments()).await;
                crate::tool_result::APP_USE_NOTE
                    .with(|note| note.borrow().clone())
                    .unwrap()
            })
            .await;
        assert_eq!(
            *plane.app_use_seen_for_test.lock().unwrap(),
            [Some(AppUse::Background)]
        );
        assert!(
            note.contains("unsupported"),
            "a call without a daemon carrier explains the fallback"
        );
    }

    #[tokio::test]
    async fn managed_updates_reach_the_next_call_without_a_restart() {
        let plane = plane(LiveAppUse::default());
        let management = management();

        serve(&plane, &management, "computer.wait", wait_arguments()).await;
        for app_use in [AppUse::Foreground, AppUse::Background] {
            plane.app_use.apply(LiveSettings {
                app_use,
                approved: true,
            });
            serve(&plane, &management, "computer.wait", wait_arguments()).await;
        }
        assert_eq!(
            *plane.app_use_seen_for_test.lock().unwrap(),
            [
                Some(AppUse::Background),
                Some(AppUse::Foreground),
                Some(AppUse::Background)
            ]
        );
    }

    #[tokio::test]
    async fn live_delivery_does_not_change_the_restart_only_cursor_setting() {
        use subc_protocol::config::{ConfigStatus, ConfigView};

        let (cursor, mut lines) = crate::computer_capability::cursor::Coordinator::channel();
        let plane = plane(LiveAppUse::default()).with_cursor(cursor);
        let management = management();
        let view = ConfigView::new(
            0,
            json!({"computer_use":{"agent_cursor":false,"app_use":"foreground"}}),
            Default::default(),
            vec![],
            ConfigStatus::Active,
        );
        plane
            .app_use
            .apply(crate::settings::config_apply(&view).unwrap());
        serve(&plane, &management, "computer.wait", wait_arguments()).await;
        assert_eq!(
            plane.app_use_seen_for_test.lock().unwrap().as_slice(),
            [Some(AppUse::Foreground)]
        );
        // Turning the cursor off sends its transport a wake line; none came.
        assert!(lines.try_recv().is_err());
    }
}
