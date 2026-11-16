use super::*;

fn planes() -> Planes {
    Planes::with_browser_config_journaling(
        Arc::new(HealthState::default()),
        None,
        JournalPersistence::Isolated,
    )
}

fn frame(ty: FrameType, channel: u16, epoch: u32, corr: u64) -> Frame {
    Frame::build(ty, control_flags(), channel, epoch, corr, b"{}".to_vec()).unwrap()
}

#[tokio::test]
async fn a_cancel_for_an_unknown_corr_is_ignored_by_name() {
    let planes = planes();
    let (tx, mut rx) = mpsc::channel(8);
    for channel in [0, 7] {
        assert!(
            handle_frame(frame(FrameType::Cancel, channel, 1, 42), &tx, &planes)
                .await
                .unwrap()
        );
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }
    assert!(handle_frame(frame(FrameType::Ping, 0, 0, 43), &tx, &planes)
        .await
        .unwrap());
    assert_eq!(rx.recv().await.unwrap().header.ty, FrameType::Pong);
}

#[tokio::test]
async fn a_cancel_after_the_reply_does_not_disturb_the_next_request() {
    let planes = planes();
    let (tx, mut rx) = mpsc::channel(8);
    handle_frame(frame(FrameType::Request, 7, 1, 42), &tx, &planes)
        .await
        .unwrap();
    assert_eq!(rx.recv().await.unwrap().header.corr, 42);
    tokio::task::yield_now().await;
    assert!(planes.cancellations.get((7, 1, 42)).is_none());
    handle_frame(frame(FrameType::Cancel, 7, 1, 42), &tx, &planes)
        .await
        .unwrap();
    handle_frame(frame(FrameType::Request, 7, 1, 43), &tx, &planes)
        .await
        .unwrap();
    assert_eq!(rx.recv().await.unwrap().header.corr, 43);
    assert!(matches!(
        rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn route_close_cancels_every_request_on_that_route() {
    let mut planes = planes();
    let resume = Arc::new(tokio::sync::Notify::new());
    let parked = resume.clone();
    planes.route_test_handler = Some(Arc::new(move || {
        let parked = parked.clone();
        Box::pin(async move {
            parked.notified().await;
        })
    }));
    let (tx, _rx) = mpsc::channel(8);
    for (channel, epoch, corr) in [(7, 1, 42), (7, 1, 43), (7, 2, 44), (8, 1, 45)] {
        handle_frame(
            frame(FrameType::Request, channel, epoch, corr),
            &tx,
            &planes,
        )
        .await
        .unwrap();
    }
    let first = planes.cancellations.get((7, 1, 42)).unwrap();
    let second = planes.cancellations.get((7, 1, 43)).unwrap();
    let other_epoch = planes.cancellations.get((7, 2, 44)).unwrap();
    let other_channel = planes.cancellations.get((8, 1, 45)).unwrap();
    handle_frame(frame(FrameType::Cancel, 7, 1, 42), &tx, &planes)
        .await
        .unwrap();
    assert!(first.is_cancelled());
    assert!(!second.is_cancelled());
    handle_frame(frame(FrameType::Goodbye, 7, 1, 0), &tx, &planes)
        .await
        .unwrap();
    assert!(second.is_cancelled());
    assert!(!other_epoch.is_cancelled());
    assert!(!other_channel.is_cancelled());
    tokio::task::yield_now().await;
    resume.notify_waiters();
    tokio::task::yield_now().await;
    assert!(planes.cancellations.0.lock().unwrap().is_empty());
}

/// A request that reaches the computer plane without a cancellation entry is
/// refused rather than served without a way to stop it.
///
/// Production registers before spawning and both test entry points go
/// through the same registration, so this state takes calling the handler
/// directly to construct at all. That is the point: the invariant is held at
/// a DIFFERENT call site than the one relying on it, so the day a second
/// entry point forgets it, this says so on the wire rather than panicking
/// inside a spawned task, where the only trace would be an indeterminate
/// audit record.
// macOS-only: the computer plane's admission field is target-gated, so on a
// host without it this request is answered `unknown_method` long before the
// check under test, and the assertion would pass for the wrong reason.
#[cfg(target_os = "macos")]
#[tokio::test]
async fn an_unregistered_request_is_refused_rather_than_served_uninterruptibly() {
    let mut planes = planes();
    let route_bindings = Arc::new(RouteBindings::new());
    let request = Frame::build(
        FrameType::Request,
        control_flags(),
        7,
        1,
        42,
        serde_json::to_vec(&json!({"name": "computer.wait", "arguments": {}})).unwrap(),
    )
    .unwrap();
    install_test_bind(&route_bindings, &request);
    planes.routes = route_bindings;
    #[cfg(target_os = "macos")]
    {
        planes.computer_admitted = test_admitted_computer_capabilities();
    }
    let (tx, mut rx) = mpsc::channel(8);

    // Deliberately NOT registered: the only way to reach the state.
    handle_tool_request(request, &tx, &planes, &CallObservation::new())
        .await
        .unwrap();

    let reply = rx.recv().await.unwrap();
    assert_eq!(reply.header.ty, FrameType::Error);
    let body: serde_json::Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(body["code"], "request_not_interruptible");
}
