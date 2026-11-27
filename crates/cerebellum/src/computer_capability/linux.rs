//! Linux release bindings and call-time desktop admission.

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use cerebellum_computer::audit::ComputerCapability;
use cerebellum_computer::capture::*;
use cerebellum_computer::platform::*;
use cerebellum_linux::session::{self, AccessibilityBus, DesktopSession, SessionKind};
use serde_json::{json, Value};
use tokio::sync::Mutex;
use tokio::time::{timeout_at, Instant};

use super::{
    computer_audit, permissions, ComputerPlane, ComputerPlaneUnavailable, ResultSchemaEnforcement,
    RunningComputerPlane,
};
use crate::{ComputerReleaseInputs, JournalPersistence};

pub(crate) fn compiled_reviews() -> LinuxReleaseInputs {
    LinuxReleaseInputs {
        app_identity: option_env!("CEREBELLUM_LINUX_APP_IDENTITY_REVIEW_REVISION")
            .map(str::to_owned),
        semantic: option_env!("CEREBELLUM_LINUX_SEMANTIC_REVIEW_REVISION").map(str::to_owned),
        launch: option_env!("CEREBELLUM_LINUX_LAUNCH_REVIEW_REVISION").map(str::to_owned),
        x11_capture: option_env!("CEREBELLUM_LINUX_X11_CAPTURE_REVIEW_REVISION").map(str::to_owned),
        x11_fronting: option_env!("CEREBELLUM_LINUX_X11_FRONTING_REVIEW_REVISION")
            .map(str::to_owned),
        x11_takeover: option_env!("CEREBELLUM_LINUX_X11_TAKEOVER_REVIEW_REVISION")
            .map(str::to_owned),
    }
}

#[allow(clippy::result_large_err)]
pub(crate) fn plane(
    inputs: &ComputerReleaseInputs,
    admitted: Arc<BTreeSet<String>>,
    journal: JournalPersistence,
) -> Result<Arc<RunningComputerPlane>, ComputerPlaneUnavailable> {
    let reviews = &inputs.linux;
    if !LinuxReleaseInputs::GATES
        .iter()
        .any(|gate| reviews.bound(gate))
    {
        return Err(ComputerPlaneUnavailable::NoLinuxReviews);
    }
    let session = Arc::new(LinuxSession::new(
        reviews.bound(LinuxReleaseInputs::SEMANTIC),
        admitted,
    ));
    let audit = computer_audit(journal)?;
    let driver_session = Arc::clone(&session);
    let app_use_fronting = [
        LinuxReleaseInputs::IDENTITY,
        LinuxReleaseInputs::SEMANTIC,
        LinuxReleaseInputs::FRONTING,
    ]
    .iter()
    .all(|gate| reviews.bound(gate));
    let plane = ComputerPlane::with_synthetic_driver_and_result_schema_enforcement(
        audit,
        ResultSchemaEnforcement::Withhold,
        move || LinuxDriver {
            session: Arc::clone(&driver_session),
        },
    )
    .with_fronting_bracket_admitted(app_use_fronting)
    .with_app_use_fronting_admitted(app_use_fronting)
    .with_takeover_pointer_fronting_admitted(
        app_use_fronting && reviews.bound(LinuxReleaseInputs::TAKEOVER),
    );
    Ok(Arc::new(ComputerPlane {
        linux_session: Some(session),
        ..plane
    }))
}

// Arrival runs on the frame reader. Bound both contention for the latch and
// all endpoint discovery, so a stalled local service cannot strand that loop.
const SESSION_READ_LIMIT: Duration = Duration::from_millis(250);

type ReadResult = Result<SessionReading, session::NoSupportedSession>;
type SessionReader = dyn Fn() -> Pin<Box<dyn Future<Output = ReadResult> + Send>> + Send + Sync;

struct SessionReading {
    desktop: DesktopSession,
    // A connection generation, not a DISPLAY string: a replacement X server
    // can use the same endpoint. Wayland never uses this component.
    x11_connection: Option<u64>,
    permissions: PermissionLivenessReport,
}

#[derive(PartialEq, Eq)]
struct EpochKey {
    session: String,
    kind: SessionKind,
    x11_connection: Option<u64>,
    accessibility: Option<AccessibilityBus>,
}

struct Epoch {
    key: EpochKey,
    permissions: PermissionLivenessReport,
}

pub(super) struct LinuxSession {
    read: Box<SessionReader>,
    epoch: Mutex<Option<(Arc<Epoch>, bool)>>,
    admitted: Arc<BTreeSet<String>>,
}

impl LinuxSession {
    fn new(require_accessibility: bool, admitted: Arc<BTreeSet<String>>) -> Self {
        Self {
            read: Box::new(move || {
                Box::pin(async move {
                    let desktop = session::resolve(require_accessibility).await?;
                    // Finding the accessibility bus is not evidence that a
                    // driver can read it. DISPLAY alone proves no X facilities.
                    Ok(SessionReading {
                        desktop,
                        x11_connection: None,
                        permissions: Default::default(),
                    })
                })
            }),
            epoch: Mutex::new(None),
            admitted,
        }
    }

    async fn refresh(&self) -> Result<(Arc<Epoch>, bool), LinuxRefusal> {
        let deadline = Instant::now() + SESSION_READ_LIMIT;
        let mut latch = timeout_at(deadline, self.epoch.lock())
            .await
            .map_err(|_| LinuxRefusal::NoSupportedSession)?;
        let reading = match timeout_at(deadline, (self.read)()).await {
            Ok(Ok(reading)) => reading,
            Ok(Err(_)) | Err(_) => {
                *latch = None;
                return Err(LinuxRefusal::NoSupportedSession);
            }
        };
        let key = EpochKey {
            session: reading.desktop.id,
            kind: reading.desktop.kind,
            x11_connection: if reading.desktop.kind == SessionKind::X11 {
                reading.x11_connection
            } else {
                None
            },
            accessibility: reading.desktop.accessibility,
        };
        let epoch = match latch.as_ref() {
            Some((epoch, _)) if epoch.key == key => Arc::clone(epoch),
            _ => Arc::new(Epoch {
                key,
                permissions: reading.permissions,
            }),
        };
        *latch = Some((epoch.clone(), reading.desktop.locked));
        Ok((epoch, reading.desktop.locked))
    }

    pub(super) async fn refusal(&self, capability: ComputerCapability) -> Option<Value> {
        use ComputerCapability::*;
        let (epoch, locked) = match self.refresh().await {
            Ok(state) => state,
            Err(reason) => return Some(reason.reply(capability)),
        };
        if locked {
            return Some(super::screen_locked_reply());
        }
        let reason =
            if capability != PressPoint && !self.admitted.contains(capability.capability_id()) {
                LinuxRefusal::RouteNotReviewed
            } else if capability == PressPoint {
                LinuxRefusal::PointHitTestUnsupported
            } else if epoch.key.kind == SessionKind::Wayland
                && matches!(
                    capability,
                    Type | Keys | TakeoverMove | TakeoverClick | TakeoverDrag | TakeoverScroll
                )
            {
                LinuxRefusal::WaylandSeatInputUnverifiable
            } else if epoch.key.kind == SessionKind::X11 && epoch.key.x11_connection.is_none() {
                LinuxRefusal::BackendUnavailable
            } else if let Some(reply) = permissions::refusal(capability, &epoch.permissions) {
                return Some(reply);
            } else {
                // No Linux backend can resolve applications, read their trees,
                // launch them, or send input. Do not fall through to shared handlers.
                LinuxRefusal::BackendUnavailable
            };
        Some(reason.reply(capability))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LinuxRefusal {
    NoSupportedSession,
    RouteNotReviewed,
    PointHitTestUnsupported,
    WaylandSeatInputUnverifiable,
    BackendUnavailable,
}

impl LinuxRefusal {
    fn reply(self, capability: ComputerCapability) -> Value {
        use ComputerCapability::*;
        let (reason, remedy) = match self {
            Self::NoSupportedSession => (
                "no_supported_session",
                "use an active, verifiable Linux desktop session",
            ),
            Self::RouteNotReviewed => (
                "route_not_reviewed",
                "use a build that carries the reviews for this operation",
            ),
            Self::PointHitTestUnsupported => (
                "point_hit_test_unsupported",
                "use press_element with an accessibility element id",
            ),
            Self::WaylandSeatInputUnverifiable => (
                "wayland_seat_input_unverifiable",
                "use an accessibility action instead of seat input on Wayland",
            ),
            Self::BackendUnavailable => (
                "backend_unavailable",
                "the Linux backend for this operation is unavailable",
            ),
        };
        let outcome = match capability {
            ListApps | ReadState | Wait => "targets_unreadable",
            OpenApp => "launch_failed",
            Type | Keys => "not_servable",
            _ => "authorization_denied",
        };
        json!({"outcome": outcome, "reason": reason, "remedy": remedy})
    }
}

pub struct LinuxDriver {
    session: Arc<LinuxSession>,
}

macro_rules! unsupported {
    ($error:expr; $(fn $name:ident($($parameter:ident: $input:ty),*) -> $output:ty;)*) => {
        $(fn $name(&mut self, $($parameter: $input),*) -> $output { Err($error) })*
    };
}

impl PlatformDriver for LinuxDriver {
    fn capability_declarations(
        &self,
        context: &CapabilityAdvertisementContext,
    ) -> Vec<CapabilityDeclaration> {
        capability_declarations(context, true)
    }

    fn session_locked(&self) -> Option<bool> {
        let epoch = self.session.epoch.try_lock().ok()?;
        epoch.as_ref().map(|(_, locked)| *locked)
    }

    fn input_observer_liveness(&self) -> InputObserverLiveness {
        InputObserverLiveness {
            session_tap_live: false,
            raw_hid_live: false,
            self_echo_filter_live: false,
        }
    }

    unsupported!(DriverError::Unsupported("Linux desktop backend");
        fn read_accessibility_tree(_request: AccessibilityTreeRequest) -> Result<AccessibilityTreeResult, DriverError>;
        fn resolve_element(_request: ElementResolutionRequest) -> Result<ElementResolutionResult, DriverError>;
        fn dispatch_semantic(_request: SemanticDispatchRequest) -> Result<DispatchResult, DriverError>;
        fn dispatch_per_pid(_request: SyntheticDispatchRequest, _cancelled: &dyn Fn() -> bool) -> Result<DispatchResult, DriverError>;
        fn dispatch_global(_request: GlobalDispatchRequest, _cancelled: &dyn Fn() -> bool) -> Result<DispatchResult, DriverError>;
        fn query_focus(_request: FocusQueryRequest) -> Result<FocusQueryResult, DriverError>;
        fn fronting_snapshot(_target: &ProcessGrant) -> Result<FrontingSnapshot, DriverError>;
        fn observe_input(_request: InputObservationRequest) -> Result<InputObservationResult, DriverError>;
        fn observe_effect(_request: EffectObservationRequest) -> Result<EffectObservationResult, DriverError>;
        fn verify_attendance(_request: AttendancePreconditionRequest) -> Result<AttendancePreconditionResult, DriverError>;
    );
}

pub struct LinuxCaptureBackend;

impl CaptureBackend for LinuxCaptureBackend {
    fn platform_support(&self) -> Result<(), BackendError> {
        Err(BackendError::UnsupportedOnPlatform)
    }

    fn screen_recording_liveness(&self) -> PermissionLiveness {
        PermissionLiveness::Unresolved
    }

    unsupported!(BackendError::UnsupportedOnPlatform;
        fn enumerate_windows(_target: &ProcessGrant) -> Result<Vec<EnumeratedWindow>, BackendError>;
        fn poll_window_change(_target: &ProcessGrant) -> Result<Option<WindowChange>, BackendError>;
        fn capture_window(_request: &WindowCaptureRequest) -> Result<WindowCaptureFrame, BackendError>;
        fn capture_display(_request: &BroadDisplayCaptureRequest) -> Result<CaptureArtifact, BackendError>;
        fn begin_teardown() -> Result<BackendTeardownProgress, BackendError>;
        fn poll_teardown(_elapsed_ms: u64) -> Result<BackendTeardownProgress, BackendError>;
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use cerebellum_computer::platform::vocabulary::validate_capability_result;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use subc_protocol::{Frame, FrameType};

    fn read_with(
        kind: SessionKind,
        id: &str,
        a11y_id: &str,
        permissions: PermissionLivenessReport,
    ) -> SessionReading {
        SessionReading {
            desktop: DesktopSession {
                id: id.into(),
                kind,
                locked: false,
                environment: Default::default(),
                accessibility: Some(AccessibilityBus {
                    address: "fixture-bus".into(),
                    id: a11y_id.into(),
                }),
            },
            x11_connection: Some(1),
            permissions,
        }
    }

    #[tokio::test]
    async fn latch_remembers_only_the_current_epoch_and_rereads_the_lock() {
        use std::collections::VecDeque;
        let kind = SessionKind::Wayland;
        let unresolved = PermissionLivenessReport::default();
        let live = permissions::live_for_test();
        let first = read_with(kind, "1", "bus-one", unresolved.clone());
        let mut same = read_with(kind, "1", "bus-one", live.clone());
        same.desktop.locked = true;
        same.x11_connection = Some(31); // Xwayland has no X11 epoch component.
        let replaced_bus = read_with(kind, "1", "bus-two", live.clone());
        let replaced_session = read_with(SessionKind::X11, "2", "bus-two", unresolved);
        let mut reconnected_x11 = read_with(SessionKind::X11, "2", "bus-two", live);
        reconnected_x11.x11_connection = Some(2);
        let readings = std::sync::Mutex::new(VecDeque::from([
            Err(session::NoSupportedSession),
            Ok(first),
            Ok(same),
            Ok(replaced_bus),
            Ok(replaced_session),
            Ok(reconnected_x11),
            Err(session::NoSupportedSession),
        ]));
        let mut session = LinuxSession::new(true, Arc::default());
        session.read = Box::new(move || {
            Box::pin(std::future::ready(
                readings.lock().unwrap().pop_front().unwrap(),
            ))
        });
        assert!(matches!(
            session.refresh().await,
            Err(LinuxRefusal::NoSupportedSession)
        ));
        let (first, unlocked) = session.refresh().await.unwrap();
        assert!(!unlocked);
        let (same, locked) = session.refresh().await.unwrap();
        assert!(locked);
        assert!(Arc::ptr_eq(&first, &same));
        assert_eq!(
            same.permissions.state(PermissionService::Accessibility),
            PermissionLiveness::Unresolved
        );
        let (replaced_bus, _) = session.refresh().await.unwrap();
        assert!(!Arc::ptr_eq(&first, &replaced_bus));
        assert_eq!(
            replaced_bus
                .permissions
                .state(PermissionService::Accessibility),
            PermissionLiveness::Live
        );
        let (replaced_session, _) = session.refresh().await.unwrap();
        assert!(!Arc::ptr_eq(&replaced_bus, &replaced_session));
        let (reconnected, _) = session.refresh().await.unwrap();
        assert!(!Arc::ptr_eq(&replaced_session, &reconnected));
        assert!(matches!(
            session.refresh().await,
            Err(LinuxRefusal::NoSupportedSession)
        ));
        assert!(session.epoch.lock().await.is_none());
    }

    fn bind_fixture(planes: &crate::Planes) {
        planes.routes.insert(7, 1, crate::AcceptedBindFacts::from_bind(
            &subc_protocol::BindIdentity::new("test", "session".to_string()),
            crate::session_caller_principal_for_test(),
            Some(&json!({"agentProjectId":"test-project", "sessionKind":"primary", "effectiveCapabilityScope":["*"]})),
            Some(&["elicitation".to_string()]),
            &subc_protocol::RouteTarget::ToolProvider { module_id: "cerebellum".into() },
        ));
    }

    fn request(corr: u64, name: &str, arguments: Value) -> Frame {
        Frame::build(
            FrameType::Request,
            subc_protocol::Flags::new(false, subc_protocol::Priority::Interactive, true),
            7,
            1,
            corr,
            serde_json::to_vec(&json!({"name":name, "arguments":arguments})).unwrap(),
        )
        .unwrap()
    }

    fn planes_with(session: LinuxSession) -> crate::Planes {
        let mut planes = crate::Planes::with_browser_config_journaling(
            Arc::default(),
            None,
            JournalPersistence::Isolated,
        );
        planes.computer_admitted = Arc::clone(&session.admitted);
        let audit = computer_audit(JournalPersistence::Isolated).unwrap();
        let refusing_plane = ComputerPlane::with_synthetic_driver_and_result_schema_enforcement(
            audit,
            ResultSchemaEnforcement::Withhold,
            || panic!("early refusal reached the dispatch driver"),
        );
        planes.computer = Ok(Arc::new(ComputerPlane {
            linux_session: Some(Arc::new(session)),
            ..refusing_plane
        }));
        bind_fixture(&planes);
        planes
    }

    #[tokio::test]
    async fn arrival_and_serve_apply_linux_refusal_order_before_permissions() {
        for (admitted, kind, capability, missing, reason) in [
            (
                true,
                SessionKind::Wayland,
                "type",
                true,
                "no_supported_session",
            ),
            (
                false,
                SessionKind::Wayland,
                "type",
                false,
                "route_not_reviewed",
            ),
            (
                true,
                SessionKind::Wayland,
                "type",
                false,
                "wayland_seat_input_unverifiable",
            ),
            (
                false,
                SessionKind::X11,
                "press_point",
                true,
                "no_supported_session",
            ),
            (
                false,
                SessionKind::X11,
                "press_point",
                false,
                "point_hit_test_unsupported",
            ),
            (true, SessionKind::X11, "type", false, "permission_missing"),
        ] {
            let name = format!("computer.{capability}");
            let names = if admitted {
                BTreeSet::from([name.clone()])
            } else {
                BTreeSet::new()
            };
            let mut session = LinuxSession::new(true, Arc::new(names));
            let queries = Arc::new(AtomicUsize::new(0));
            let probe_count = Arc::clone(&queries);
            session.read = Box::new(move || {
                probe_count.fetch_add(1, Ordering::Relaxed);
                Box::pin(std::future::ready(if missing {
                    Err(session::NoSupportedSession)
                } else {
                    Ok(read_with(
                        kind,
                        "fixture",
                        "bus",
                        PermissionLivenessReport::default(),
                    ))
                }))
            });
            let planes = planes_with(session);
            let (tx, mut rx) = tokio::sync::mpsc::channel(8);
            let arguments = if capability == "type" {
                json!({"target":"fixture","text":"x"})
            } else {
                json!({"image_id":"previous-image","x":1,"y":1})
            };
            crate::handle_frame(request(42, &name, arguments), &tx, &planes)
                .await
                .unwrap();
            let response = tokio::time::timeout(crate::test_support::HANG_GUARD, rx.recv())
                .await
                .unwrap()
                .unwrap();
            let reply: Value = serde_json::from_slice(&response.body).unwrap();
            assert_eq!(response.header.ty, FrameType::Response, "{reply}");
            if reason == "permission_missing" {
                assert_eq!(reply["outcome"], reason);
                assert!(reply["remedy"]
                    .as_str()
                    .unwrap()
                    .contains("Linux desktop session"));
            } else {
                assert_eq!(reply["reason"], reason, "{reply}");
            }
            validate_capability_result(&name, &reply).unwrap();
            assert_eq!(
                queries.load(Ordering::Relaxed),
                2,
                "arrival and serve each check, without constructing a dispatch driver"
            );
        }
    }

    #[tokio::test]
    async fn a_stalled_arrival_cannot_wedge_the_frame_reader() {
        let mut session =
            LinuxSession::new(true, Arc::new(BTreeSet::from(["computer.type".into()])));
        let queries = Arc::new(AtomicUsize::new(0));
        let probe_count = Arc::clone(&queries);
        session.read = Box::new(move || {
            probe_count.fetch_add(1, Ordering::Relaxed);
            Box::pin(std::future::pending())
        });
        let planes = planes_with(session);
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let next_frame = async {
            crate::handle_frame(
                request(42, "computer.type", json!({"target":"fixture","text":"x"})),
                &tx,
                &planes,
            )
            .await
            .unwrap();
            crate::handle_frame(
                request(43, "browser_use", json!({"action":"status"})),
                &tx,
                &planes,
            )
            .await
            .unwrap();
            let other = rx.recv().await.unwrap();
            assert_eq!(
                other.header.corr, 43,
                "browser route need not wait for serve's session timeout"
            );
        };
        tokio::time::timeout(crate::test_support::HANG_GUARD, next_frame)
            .await
            .unwrap();
        let refusal = tokio::time::timeout(crate::test_support::HANG_GUARD, rx.recv())
            .await
            .unwrap()
            .unwrap();
        let reply: Value = serde_json::from_slice(&refusal.body).unwrap();
        assert_eq!(refusal.header.corr, 42);
        assert_eq!(reply["reason"], "no_supported_session");
        assert_eq!(queries.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn unbound_linux_build_refuses_direct_rows_and_empty_sets_disable_flat_tool() {
        let mut inputs = ComputerReleaseInputs {
            app_state_review_revision: Some("non-linux-review".into()),
            element_addressed_review_revision: Some("non-linux-review".into()),
            takeover_dispatch_review_revision: Some("non-linux-review".into()),
            ..Default::default()
        };
        let mut planes = crate::Planes::with_browser_config_journaling(
            Arc::default(),
            None,
            JournalPersistence::Isolated,
        );
        bind_fixture(&planes);
        planes.computer_admitted = Arc::default();
        planes.computer = plane(
            &inputs,
            Arc::clone(&planes.computer_admitted),
            JournalPersistence::Isolated,
        );
        assert!(matches!(
            planes.computer,
            Err(ComputerPlaneUnavailable::NoLinuxReviews)
        ));
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        for (index, row) in ComputerCapability::ALL.into_iter().enumerate() {
            let frame = request(
                100 + index as u64,
                row.capability_id(),
                json!({
                    "target": "fixture", "element_id": "old1", "image_id": "old-image"
                }),
            );
            crate::handle_frame(frame, &tx, &planes).await.unwrap();
            let refusal = tokio::time::timeout(crate::test_support::HANG_GUARD, rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(refusal.header.ty, FrameType::Error);
            let body = String::from_utf8_lossy(&refusal.body);
            assert!(
                body.contains("capability_not_admitted"),
                "{}: {body}",
                row.capability_id()
            );
        }

        inputs.linux.app_identity = Some("identity-review".into());
        for (index, capture) in [None, Some("capture-review".into())]
            .into_iter()
            .enumerate()
        {
            inputs.linux.x11_capture = capture;
            planes.computer = plane(
                &inputs,
                Arc::clone(&planes.computer_admitted),
                JournalPersistence::Isolated,
            );
            assert!(
                planes.computer.is_ok(),
                "a bound review builds the plane, not a tool"
            );
            crate::handle_frame(
                request(
                    200 + index as u64,
                    "computer_use",
                    json!({"action":"list_apps"}),
                ),
                &tx,
                &planes,
            )
            .await
            .unwrap();
            let refusal = tokio::time::timeout(crate::test_support::HANG_GUARD, rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(refusal.header.ty, FrameType::Error);
            let body = String::from_utf8_lossy(&refusal.body);
            assert!(body.contains("tool_disabled"), "{body}");
        }
    }
}
