//! Drive a real screenshot through the plane, from target to reply.
//!
//! Every automated test of this path uses a fixture capture backend, which
//! proves the plumbing and cannot prove that a real capture survives it. This
//! runs the actual sequence against a real window: resolve a target, ask for
//! the app grant, check authority, reserve the journal, capture, encode,
//! admit to custody, finalize, and read the reply.
//!
//! It calls the plane directly rather than going through the wire, so it does
//! NOT exercise the release-gate admission a dispatched request must pass. That
//! is deliberate: this probe answers whether a real capture survives the
//! machinery, and requiring a build-time attestation to ask that question would
//! make it unrunnable during development, which is when the answer is wanted.
//!
//! The consequence is worth stating rather than leaving to be discovered: a
//! green run here does NOT mean a caller can obtain a screenshot. Whether the
//! module OFFERS the capability is a separate question, answered by the
//! what_ships probe, and both must be green for a caller to get a picture.
//!
//! A probe rather than a test. It needs an unlocked screen, a granted capture
//! permission and a named application running, so as a test it would skip in
//! most runs -- and a test that skips under the conditions it exists to check
//! reads as coverage while proving nothing.
//!
//! It performs no pre-checks for those conditions. The path already turns a
//! locked screen and a missing permission into typed refusals, so asking first
//! would test the question rather than the answer, and a probe that reported a
//! condition the real path handles differently would be worse than none.
//!
//! Run with: cargo run -p cerebellum --example live_screenshot -- <bundle-id>

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("this probe drives macOS capture and has nothing to run here");
}

#[cfg(target_os = "macos")]
fn main() {
    use std::sync::Arc;

    use cerebellum::computer_capability::{servable, ComputerPlane, ServeContext};
    use cerebellum::management::{ManagementPlane, PlatformResolver};
    use cerebellum_core::clock::SystemClock;
    use cerebellum_core::identity::SessionKind;
    use cerebellum_core::journal::JournalIdentity;
    use serde_json::json;

    let bundle = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "com.apple.finder".to_string());

    let runtime = tokio::runtime::Runtime::new().expect("a runtime");
    runtime.block_on(async move {
        let audit = match cerebellum::computer_capability::production_audit() {
            Ok(audit) => audit,
            Err(reason) => {
                println!("FAILED: the production audit could not be assembled: {reason}");
                return;
            }
        };
        let plane: cerebellum::computer_capability::RunningComputerPlane =
            ComputerPlane::with_synthetic_driver(audit, || {
                cerebellum_computer::platform::MacOs26PlatformDriver::default()
                    .without_expected_post_condition()
            });
        let management = Arc::new(ManagementPlane::new(Arc::new(PlatformResolver::new())));
        let clock = SystemClock::new();
        let grantee = "pj-live-probe";

        println!("target application: {bundle}");
        // No separate opening step: the action asks for its app grant itself.
        // This probe has no person to relay a question to, so a call without
        // the grant is refused `consent_unavailable` rather than asked.
        let consent = cerebellum::computer_grants::ConsentContext::without_carrier(
            cerebellum::computer_grants::GrantCaller {
                holder: None,
                conversation_key: "live-probe".to_string(),
                agent_project_id: grantee.to_string(),
                durable_identity_attested: false,
            },
        );

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_millis() as u64)
            .unwrap_or_default();

        let started = std::time::Instant::now();
        let result = plane
            .serve(
                servable("computer.screenshot").expect("screenshot is servable"),
                &json!({ "scope": "target_windows", "include_cursor": false }),
                ServeContext {
                    cancel: cerebellum::CancelHandle::for_uninterruptible_probe(),
                    grantee,
                    identity: JournalIdentity {
                        witness: cerebellum_core::dispatch_witness::DispatchWitness::detached(),
                        principal: "prefrontal-core".to_string(),
                        conversation_key: "live-probe".to_string(),
                        agent_project_id: grantee.to_string(),
                        session_kind: SessionKind::Primary,
                        origin: Default::default(),
                        computer_order: None,
                    },
                    management: &management,
                    consent,
                    clock: &clock,
                    now_ms,
                },
                |_grant| {
                    cerebellum_computer::platform::native::NativeCaptureBackend::new(
                        std::time::Duration::from_secs(15),
                    )
                },
            )
            .await
            .expect("detect-only result-schema validation preserves the live reply");
        let elapsed = started.elapsed();

        println!(
            "screenshot -> {} in {}ms",
            result["outcome"],
            elapsed.as_millis()
        );
        match result["windows"].as_array() {
            Some(windows) => {
                println!("  {} window(s)", windows.len());
                for window in windows.iter().take(5) {
                    let encoded = window["image_png_b64"].as_str().unwrap_or_default();
                    // Base64 carries 3 bytes per 4 characters.
                    let bytes = encoded.len() / 4 * 3;
                    let (w, h) = (
                        window["width_px"].as_u64().unwrap_or(0),
                        window["height_px"].as_u64().unwrap_or(0),
                    );
                    // The charge is one token per 28x28 patch, capped at 1568.
                    let tokens = (w.div_ceil(28) * h.div_ceil(28)).min(1568);
                    println!(
                        "    {}x{}  {:.2}MB encoded  ~{} tokens  png={}",
                        w,
                        h,
                        bytes as f64 / 1_048_576.0,
                        tokens,
                        encoded.starts_with("iVBORw0KGgo")
                    );
                }
            }
            None => println!("  detail: {result}"),
        }

        println!("journal entries: {}", plane.journal_entry_count().await);
    });
}
