//! Serve a real `computer.read_state` on this machine and print the reply,
//! to see what a caller gets while the screen is locked.
//!
//! A locked screen hides every application's interface from the
//! accessibility API while the windows stay listed, so an unchecked read
//! returns an empty tree that looks like an empty application. The plane
//! refuses such a read as `screen_locked` instead, and this probe shows that
//! refusal coming out of the real serving path: the macOS platform driver
//! reading the lock from the window server, the platform target resolver, and
//! result-schema enforcement in withholding mode, so the printed reply also
//! passed its row's schema. The journal is held in memory, so nothing is
//! written to the operator's own.
//!
//! Run with the screen locked (for example over ssh):
//!
//! ```text
//! cargo run -p cerebellum --example live_screen_locked -- [bundle-identity]
//! ```
//!
//! Without an argument it reads Discord if it is running, and otherwise the
//! first running application of a short list. It prints `PASS` when the
//! screen is locked and the reply is the `screen_locked` refusal, and exits
//! non-zero otherwise.

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("this probe reads the macOS screen lock and has nothing to run here");
}

#[cfg(target_os = "macos")]
fn main() {
    std::process::exit(macos_probe::run());
}

#[cfg(target_os = "macos")]
mod macos_probe {
    use std::sync::Arc;
    use std::time::Duration;

    use cerebellum::computer_capability::{
        computer_audit, servable, ComputerPlane, ResultSchemaEnforcement, ServeContext,
    };
    use cerebellum::computer_grants::{ConsentContext, GrantCaller};
    use cerebellum::management::{ManagementPlane, PlatformResolver};
    use cerebellum::JournalPersistence;
    use cerebellum_computer::platform::native::{resolve_target, NativeCaptureBackend};
    use cerebellum_computer::platform::{MacOs26PlatformDriver, TargetResolution};
    use cerebellum_core::clock::SystemClock;
    use cerebellum_core::identity::SessionKind;
    use cerebellum_core::journal::JournalIdentity;
    use serde_json::json;

    /// Applications tried in order when none is named.
    const CANDIDATES: [&str; 4] = [
        "com.hnc.Discord",
        "com.apple.finder",
        "com.apple.TextEdit",
        "com.apple.Notes",
    ];

    pub fn run() -> i32 {
        let lock = cerebellum_macos::screen_is_locked();
        println!("screen_is_locked: {lock:?}");

        let named = std::env::args().nth(1);
        let candidates: Vec<String> = match &named {
            Some(bundle) => vec![bundle.clone()],
            None => CANDIDATES.iter().map(ToString::to_string).collect(),
        };
        let running = candidates.iter().find_map(|bundle| {
            match resolve_target(bundle, Duration::from_secs(3)) {
                TargetResolution::Resolved(grant) => Some(grant),
                _ => None,
            }
        });
        let Some(target) = running else {
            println!("FAILED: none of {candidates:?} is running as exactly one process");
            return 1;
        };
        println!(
            "application: {} (pid {})",
            target.bundle_identity, target.pid
        );

        let runtime = tokio::runtime::Runtime::new().expect("a runtime");
        let reply = runtime.block_on(async move {
            let audit = computer_audit(JournalPersistence::Isolated)
                .map_err(|error| format!("no isolated journal: {error}"))?;
            // The macOS driver the running module builds for every call; the
            // review bindings it also carries only matter for posting input,
            // which a read never does.
            let plane = ComputerPlane::<NativeCaptureBackend, _, _, _, _>::with_synthetic_driver_and_result_schema_enforcement(
                audit,
                ResultSchemaEnforcement::Withhold,
                || MacOs26PlatformDriver::default().without_expected_post_condition(),
            );
            let management = Arc::new(ManagementPlane::new(Arc::new(PlatformResolver::new())));
            let grantee = "pj-live-probe";
            let clock = SystemClock::new();
            // Nobody to ask: without the lock refusal this read would stop at
            // consent_unavailable, which is itself a different answer.
            let consent = ConsentContext::without_carrier(GrantCaller {
                conversation_key: "live-probe".to_string(),
                agent_project_id: grantee.to_string(),
                durable_identity_attested: false,
            });
            plane
                .serve(
                    servable("computer.read_state").expect("read_state is served"),
                    &json!({"target": target.bundle_identity}),
                    ServeContext {
                        cancel: cerebellum::CancelHandle::for_uninterruptible_probe(),
                        grantee,
                        identity: JournalIdentity {
                            witness: cerebellum_core::dispatch_witness::DispatchWitness::detached(),
                            principal: "prefrontal-core".to_string(),
                            conversation_key: "live-probe".to_string(),
                            agent_project_id: grantee.to_string(),
                            session_kind: SessionKind::Primary,
                        },
                        management: &management,
                        consent,
                        clock: &clock,
                        now_ms: 0,
                    },
                    |_grant| cerebellum_computer::platform::native::NativeCaptureBackend::new(
                        Duration::from_secs(10),
                    ),
                )
                .await
                .map_err(|error| format!("the reply left its row: {error:?}"))
        });
        let reply = match reply {
            Ok(reply) => reply,
            Err(reason) => {
                println!("FAILED: {reason}");
                return 1;
            }
        };
        println!("read_state reply: {reply}");
        if lock == Some(true) && reply["outcome"] == "screen_locked" {
            println!("PASS: the locked screen was refused by name");
            0
        } else if lock != Some(true) {
            println!("UNMEASURABLE: the screen is not locked, so there is no refusal to show");
            2
        } else {
            println!("FAILED: the screen is locked and the read was not refused");
            1
        }
    }
}
