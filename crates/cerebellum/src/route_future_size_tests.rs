//! The size of the futures a route request is served by.
//!
//! In an unoptimized build, an async function's poll frame keeps a separate
//! stack slot for each future it awaits, so nesting large handler futures by
//! value multiplies stack use: the unboxed route path took over 2 MiB of a
//! thread stack. The handlers are boxed at their call boundaries, which keeps
//! each future small. These tests build each future on the route path without
//! polling it and check its size, so a handler that stops being boxed fails
//! here. Actual calls also run on 1 MiB stacks: browser navigation in
//! `browser_session_wire` and computer consent in
//! `computer_consent_wire_tests::stack_tests`.

use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use subc_protocol::{Flags, Frame, FrameType, Priority, PROTOCOL_VERSION};
use tokio::sync::mpsc;

use crate::{
    browser, browser_queue, handle_frame, handle_keyed_tool_request, handle_route_request,
    handle_tool_request, handle_tool_request_inner, run_arbitrated_route, BrowserConfig,
    CallObservation, HealthState, JournalPersistence, Planes, TerminalArbiter,
};

/// Bound for each route or computer-consent future in an unoptimized build.
/// With boxed enforcement inputs, the largest native debug future measured
/// 9,008 bytes. Without those boxes the enforcement wrapper was 135,296 bytes
/// and computer dispatch was 43,904. The 16 KiB bound catches an oversized
/// future before nested poll frames can exhaust a normal thread stack.
pub(crate) const MAX_ROUTE_FUTURE_BYTES: usize = 16 * 1024;

/// Bound the spawned route future that the frame reader constructs on its
/// stack before moving it into `tokio::spawn`. Boxing its route-request
/// handler keeps it at 2,296 bytes; the 8 KiB limit catches unboxing that
/// previously made it 35,600 bytes.
pub(crate) const MAX_SPAWNED_ROUTE_BYTES: usize = 8 * 1024;

fn planes() -> Planes {
    Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(BrowserConfig {
            executable_path: None,
            expected_identity: None,
            launch_handshake_deadline_ms: 100,
            termination_grace_period_ms: 100,
            browser_idle_timeout_ms: 30_000,
            browser_exit_observation_deadline_ms: 100,
            navigation_settle_deadline_ms: 100,
        }),
        JournalPersistence::Isolated,
    )
}

fn request() -> Frame {
    Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        9,
        3,
        1,
        serde_json::to_vec(&json!({"name": browser::NAVIGATE, "arguments": {}})).unwrap(),
    )
    .unwrap()
}

/// The size of each future on the route path, largest first.
fn route_future_sizes() -> Vec<(&'static str, usize)> {
    let planes = planes();
    let (tx, _rx) = mpsc::channel(4);
    let call = CallObservation::new();
    let identity = cerebellum_core::identity::RouteIdentity::from_bind(
        &subc_protocol::BindIdentity::new("test", "test-session".to_string()),
        &Some(subc_protocol::Principal::Direct),
    );
    let arguments = json!({});
    let mut sizes = vec![
        (
            "handle_frame",
            std::mem::size_of_val(&handle_frame(request(), &tx, &planes)),
        ),
        (
            "handle_route_request",
            std::mem::size_of_val(&handle_route_request(request(), &tx, &planes)),
        ),
        (
            "handle_keyed_tool_request",
            std::mem::size_of_val(&handle_keyed_tool_request(request(), &tx, &planes)),
        ),
        (
            "handle_tool_request",
            std::mem::size_of_val(&handle_tool_request(request(), &tx, &planes, &call)),
        ),
        (
            "handle_tool_request_inner",
            std::mem::size_of_val(&handle_tool_request_inner(request(), &tx, &planes, &call)),
        ),
        (
            "browser_queue::enter",
            std::mem::size_of_val(&browser_queue::enter(&request(), &planes)),
        ),
        (
            "BrowserPlane::serve",
            std::mem::size_of_val(&planes.browser.serve(
                &identity,
                browser::BrowserCapability::Navigate,
                &arguments,
            )),
        ),
        (
            "BrowserPlane::dispatch",
            std::mem::size_of_val(&planes.browser.dispatch(
                &identity,
                browser::BrowserCapability::Navigate,
                &arguments,
            )),
        ),
    ];
    // The spawned route task, with the route handler as its worker as the
    // frame reader builds it.
    let frame = request();
    let (proxy, outgoing) = mpsc::channel(16);
    let worker_planes = planes.clone();
    let worker = async move {
        Box::pin(browser_queue::scope(
            None,
            Box::pin(handle_route_request(frame, &proxy, &worker_planes)),
        ))
        .await
    };
    sizes.push(("route worker", std::mem::size_of_val(&worker)));
    let now = tokio::time::Instant::now();
    let route = run_arbitrated_route(
        Box::pin(worker),
        outgoing,
        tx.clone(),
        planes.clone(),
        planes.cancellations.register((9, 3, 1)),
        Arc::new(planes.health.enter_request()),
        Arc::new(TerminalArbiter::new(request())),
        now + Duration::from_secs(1),
        now + Duration::from_secs(1),
    );
    sizes.push(("run_arbitrated_route", std::mem::size_of_val(&route)));
    drop(route);
    #[cfg(target_os = "macos")]
    sizes.extend(crate::computer_consent_wire_tests::stack_tests::future_sizes());
    sizes.sort_by_key(|(_, size)| std::cmp::Reverse(*size));
    sizes
}

#[tokio::test]
async fn route_futures_stay_small_enough_to_build_on_a_thread_stack() {
    let sizes = route_future_sizes();
    for (name, size) in &sizes {
        println!("{name}: {size} bytes");
    }
    for (name, size) in sizes {
        if name == "run_arbitrated_route" {
            assert!(
                size <= MAX_SPAWNED_ROUTE_BYTES,
                "the spawned route task is {size} bytes, over the \
                 {MAX_SPAWNED_ROUTE_BYTES}-byte bound; box its worker"
            );
        }
        assert!(
            size <= MAX_ROUTE_FUTURE_BYTES,
            "{name} is {size} bytes, over the {MAX_ROUTE_FUTURE_BYTES}-byte bound; box the \
             large inner future at the boundary where it is built"
        );
    }
}
