use super::*;
use serde_json::json;

const ROUTE: Route = Route {
    channel: 7,
    epoch: 9,
};

fn launch(
    bridge: &UserBrowserBridge,
    name: &str,
    cancel: &CancelHandle,
) -> tokio::task::JoinHandle<ActionOutcome> {
    let bridge = bridge.clone();
    let command = json!({"action": name});
    let cancel = cancel.clone();
    tokio::spawn(async move { bridge.invoke(ROUTE, command, cancel).await })
}

#[cfg(unix)]
async fn registered(bridge: &UserBrowserBridge, count: usize) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while bridge.state().calls.len() != count {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("action registration did not arrive");
}

#[tokio::test]
async fn not_connected_refuses_with_remedy_and_no_dispatch() {
    let bridge = UserBrowserBridge::new();
    let result = bridge
        .invoke(ROUTE, json!({"action":"click"}), CancelHandle::pending())
        .await;
    assert_eq!(result.terminal, Terminal::Refused);
    assert_eq!(result.reason, Some(Reason::NotConnected));
    assert_eq!(result.input_dispatched, Some(false));
    assert_eq!(result.phases, [ActionPhase::Queued]);
    assert!(result.remedy.unwrap().contains("extension"));
}

#[tokio::test(start_paused = true)]
async fn attach_deadline_cancels_and_a_missing_detach_closes_the_connection() {
    let bridge = UserBrowserBridge::new();
    let (_, mut outgoing, _) = bridge.connect().unwrap();
    let task = launch(&bridge, "snapshot", &CancelHandle::pending());
    assert!(matches!(
        outgoing.recv().await.unwrap().body,
        MessageBody::Attach { .. }
    ));
    tokio::time::advance(ATTACH_DEADLINE).await;
    assert_eq!(outgoing.recv().await.unwrap().body, MessageBody::Cancel);
    tokio::time::advance(CANCEL_DEADLINE).await;
    let result = task.await.unwrap();
    assert_eq!(result.terminal, Terminal::Refused);
    assert_eq!(result.reason, Some(Reason::CancelDeadline));
    assert_eq!(result.input_dispatched, Some(false));
    assert_eq!(bridge.connected_epoch(), None);
}

#[tokio::test(start_paused = true)]
async fn dispatch_deadline_never_resends_the_command() {
    let bridge = UserBrowserBridge::new();
    let (epoch, mut outgoing, _) = bridge.connect().unwrap();
    let task = launch(&bridge, "click", &CancelHandle::pending());
    let attach = outgoing.recv().await.unwrap();
    bridge.receive(Message {
        id: attach.id,
        epoch,
        body: MessageBody::Attached,
    });
    assert_eq!(outgoing.recv().await.unwrap().body, MessageBody::Dispatch);
    tokio::time::advance(DISPATCH_DEADLINE).await;
    assert_eq!(outgoing.recv().await.unwrap().body, MessageBody::Cancel);
    bridge.receive(Message {
        id: attach.id,
        epoch,
        body: MessageBody::Cancelled {
            input_dispatched: true,
            detached: true,
        },
    });
    let result = task.await.unwrap();
    assert_eq!(result.terminal, Terminal::OutcomeUnknown);
    assert_eq!(result.reason, Some(Reason::DispatchDeadline));
    assert_eq!(result.input_dispatched, Some(true));
    assert!(outgoing.try_recv().is_err());
}

#[tokio::test(start_paused = true)]
async fn chunk_deadline_stops_the_transfer_without_exposing_partial_content() {
    let bridge = UserBrowserBridge::new();
    let (epoch, mut outgoing, _) = bridge.connect().unwrap();
    let task = launch(&bridge, "snapshot", &CancelHandle::pending());
    let attach = outgoing.recv().await.unwrap();
    let reply = |body| {
        bridge.receive(Message {
            id: attach.id,
            epoch,
            body,
        })
    };
    reply(MessageBody::Attached);
    assert_eq!(outgoing.recv().await.unwrap().body, MessageBody::Dispatch);
    reply(MessageBody::Dispatched {
        input_dispatched: false,
    });
    reply(MessageBody::ReplyStart {
        bytes: 30,
        input_dispatched: false,
    });
    reply(MessageBody::ReplyChunk {
        sequence: 0,
        data: "{\"partial\":".into(),
    });
    // Let the consumer establish its per-chunk deadline before advancing time.
    tokio::task::yield_now().await;
    tokio::time::advance(CHUNK_DEADLINE).await;
    assert_eq!(outgoing.recv().await.unwrap().body, MessageBody::Cancel);
    reply(MessageBody::Cancelled {
        input_dispatched: false,
        detached: true,
    });
    let result = task.await.unwrap();
    assert_eq!(result.reason, Some(Reason::ChunkDeadline));
    assert_eq!(result.result, None);
}

#[tokio::test(start_paused = true)]
async fn reply_deadline_is_bounded_independently_of_dispatch() {
    let bridge = UserBrowserBridge::new();
    let (epoch, mut outgoing, _) = bridge.connect().unwrap();
    let task = launch(&bridge, "click", &CancelHandle::pending());
    let attach = outgoing.recv().await.unwrap();
    bridge.receive(Message {
        id: attach.id,
        epoch,
        body: MessageBody::Attached,
    });
    assert_eq!(outgoing.recv().await.unwrap().body, MessageBody::Dispatch);
    bridge.receive(Message {
        id: attach.id,
        epoch,
        body: MessageBody::Dispatched {
            input_dispatched: true,
        },
    });
    tokio::task::yield_now().await;
    tokio::time::advance(REPLY_DEADLINE).await;
    assert_eq!(outgoing.recv().await.unwrap().body, MessageBody::Cancel);
    bridge.receive(Message {
        id: attach.id,
        epoch,
        body: MessageBody::Cancelled {
            input_dispatched: true,
            detached: true,
        },
    });
    let result = task.await.unwrap();
    assert_eq!(result.reason, Some(Reason::ReplyDeadline));
    assert_eq!(result.terminal, Terminal::OutcomeUnknown);
}

#[cfg(unix)]
mod wire {
    use super::super::socket::{read_frame, test_listener, write_frame};
    use super::*;
    use cerebellum_bridge_protocol::{
        Frame, ParentAttestation, EXTENSION_ORIGIN, PROTOCOL_VERSION,
    };
    use std::path::PathBuf;
    use tokio::net::UnixStream;

    struct Fixture {
        bridge: UserBrowserBridge,
        listener: Option<BridgeListener>,
        directory: PathBuf,
        path: PathBuf,
    }

    impl Fixture {
        fn new(signed: bool) -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
            let directory = std::env::temp_dir().join(format!(
                "ck-bridge-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            cerebellum_core::private_fs::create_dir(&directory).unwrap();
            let path = directory.join("user-browser.sock");
            let bridge = UserBrowserBridge::new();
            let listener = Some(test_listener(bridge.clone(), &path, signed).unwrap());
            Self {
                bridge,
                listener,
                directory,
                path,
            }
        }

        async fn connect(&self) -> (UnixStream, u64) {
            let mut stream = UnixStream::connect(&self.path).await.unwrap();
            write_frame(&mut stream, &hello()).await.unwrap();
            match bounded_read(&mut stream).await {
                Frame::HostAccepted {
                    protocol: PROTOCOL_VERSION,
                    epoch,
                } => (stream, epoch),
                frame => panic!("unexpected admission {frame:?}"),
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.listener.take();
            std::fs::remove_dir_all(&self.directory).unwrap();
        }
    }

    fn hello() -> Frame {
        Frame::HostHello {
            protocol: PROTOCOL_VERSION,
            extension_origin: EXTENSION_ORIGIN.into(),
            parent: ParentAttestation {
                team_id: Some("EQHXZ8M8AV".into()),
                probe_cdhash: None,
                pid: 1,
                start_time_micros: 2,
            },
        }
    }
    async fn bounded_read(stream: &mut UnixStream) -> Frame {
        tokio::time::timeout(Duration::from_secs(2), read_frame(stream))
            .await
            .expect("extension double timed out")
            .unwrap()
    }
    async fn next(stream: &mut UnixStream) -> Message {
        match bounded_read(stream).await {
            Frame::Relay { message } => serde_json::from_value(message).unwrap(),
            frame => panic!("unexpected frame {frame:?}"),
        }
    }
    async fn reply(stream: &mut UnixStream, message: &Message, body: MessageBody) {
        let value = serde_json::to_value(Message {
            id: message.id,
            epoch: message.epoch,
            body,
        })
        .unwrap();
        write_frame(stream, &Frame::Relay { message: value })
            .await
            .unwrap();
    }
    async fn dispatch(stream: &mut UnixStream, attach: &Message, input: bool) {
        reply(stream, attach, MessageBody::Attached).await;
        let dispatch = next(stream).await;
        assert_eq!(dispatch.id, attach.id);
        assert_eq!(dispatch.epoch, attach.epoch);
        assert_eq!(dispatch.body, MessageBody::Dispatch);
        reply(
            stream,
            attach,
            MessageBody::Dispatched {
                input_dispatched: input,
            },
        )
        .await;
    }
    async fn complete(stream: &mut UnixStream, attach: &Message, input: bool) {
        reply(
            stream,
            attach,
            MessageBody::Completed {
                result: json!({"ok":true}),
                input_dispatched: input,
                detached: true,
            },
        )
        .await;
    }

    #[tokio::test]
    async fn socket_unsigned_peer_is_refused_before_hello_or_actions() {
        let fixture = Fixture::new(false);
        let mut client = UnixStream::connect(&fixture.path).await.unwrap();
        write_frame(&mut client, &hello()).await.unwrap();
        assert_eq!(
            bounded_read(&mut client).await,
            Frame::HostRefused {
                reason: "unsigned_peer".into()
            }
        );
        assert_eq!(fixture.bridge.connected_epoch(), None);
        let result = fixture
            .bridge
            .invoke(ROUTE, json!({"action":"click"}), CancelHandle::pending())
            .await;
        assert_eq!(result.reason, Some(Reason::NotConnected));
    }

    #[tokio::test]
    async fn socket_requires_pinned_origin_and_exclusive_chrome_parent_attestation() {
        let fixture = Fixture::new(true);
        let mut client = UnixStream::connect(&fixture.path).await.unwrap();
        let mut frame = hello();
        if let Frame::HostHello {
            extension_origin, ..
        } = &mut frame
        {
            *extension_origin = "chrome-extension://attacker/".into();
        }
        write_frame(&mut client, &frame).await.unwrap();
        assert_eq!(
            bounded_read(&mut client).await,
            Frame::HostRefused {
                reason: "extension_origin_mismatch".into()
            }
        );
        for (team, probe) in [
            (None, None),
            (Some("other"), None),
            (Some("EQHXZ8M8AV"), Some("abcd")),
            (None, Some("abcd")),
        ] {
            let mut client = UnixStream::connect(&fixture.path).await.unwrap();
            let mut frame = hello();
            if let Frame::HostHello { parent, .. } = &mut frame {
                parent.team_id = team.map(str::to_owned);
                parent.probe_cdhash = probe.map(str::to_owned);
            }
            write_frame(&mut client, &frame).await.unwrap();
            assert_eq!(
                bounded_read(&mut client).await,
                Frame::HostRefused {
                    reason: "parent_attestation_invalid".into()
                }
            );
        }
        assert_eq!(fixture.bridge.connected_epoch(), None);
    }

    #[tokio::test]
    async fn socket_second_connection_is_typed_busy_and_never_replaces_the_first() {
        let fixture = Fixture::new(true);
        let (_first, epoch) = fixture.connect().await;
        let mut second = UnixStream::connect(&fixture.path).await.unwrap();
        write_frame(&mut second, &hello()).await.unwrap();
        assert_eq!(
            bounded_read(&mut second).await,
            Frame::HostRefused {
                reason: "connection_busy".into()
            }
        );
        assert_eq!(fixture.bridge.connected_epoch(), Some(epoch));
    }

    #[tokio::test]
    async fn socket_queue_is_fifo_and_queued_cancel_dispatches_nothing() {
        let fixture = Fixture::new(true);
        let (mut extension, _) = fixture.connect().await;
        let first = launch(&fixture.bridge, "first", &CancelHandle::pending());
        let first_attach = next(&mut extension).await;
        let second = launch(&fixture.bridge, "second", &CancelHandle::pending());
        registered(&fixture.bridge, 2).await;
        let cancel = CancelHandle::pending();
        let skipped = launch(&fixture.bridge, "skipped", &cancel);
        registered(&fixture.bridge, 3).await;
        let third = launch(&fixture.bridge, "third", &CancelHandle::pending());
        registered(&fixture.bridge, 4).await;
        cancel.cancel();
        let skipped = skipped.await.unwrap();
        assert_eq!(skipped.terminal, Terminal::Cancelled);
        assert_eq!(skipped.phases, [ActionPhase::Queued]);
        dispatch(&mut extension, &first_attach, false).await;
        complete(&mut extension, &first_attach, false).await;
        assert_eq!(first.await.unwrap().terminal, Terminal::Completed);
        let second_attach = next(&mut extension).await;
        assert!(
            matches!(&second_attach.body, MessageBody::Attach { command, .. } if command["action"] == "second")
        );
        dispatch(&mut extension, &second_attach, false).await;
        complete(&mut extension, &second_attach, false).await;
        assert_eq!(second.await.unwrap().terminal, Terminal::Completed);
        let third_attach = next(&mut extension).await;
        assert!(
            matches!(&third_attach.body, MessageBody::Attach { command, .. } if command["action"] == "third")
        );
        dispatch(&mut extension, &third_attach, false).await;
        complete(&mut extension, &third_attach, false).await;
        assert_eq!(third.await.unwrap().terminal, Terminal::Completed);
    }

    #[tokio::test]
    async fn socket_cancel_during_attach_stops_before_dispatch_and_acknowledges_detach() {
        let fixture = Fixture::new(true);
        let (mut extension, _) = fixture.connect().await;
        let cancel = CancelHandle::pending();
        let task = launch(&fixture.bridge, "click", &cancel);
        let attach = next(&mut extension).await;
        cancel.cancel();
        assert_eq!(next(&mut extension).await.body, MessageBody::Cancel);
        reply(
            &mut extension,
            &attach,
            MessageBody::Cancelled {
                input_dispatched: false,
                detached: true,
            },
        )
        .await;
        let result = task.await.unwrap();
        assert_eq!(result.terminal, Terminal::Cancelled);
        assert_eq!(result.input_dispatched, Some(false));
        assert_eq!(result.phases, [ActionPhase::Queued, ActionPhase::Attaching]);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), read_frame(&mut extension))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn socket_cancel_during_chunks_drops_content_and_reports_already_dispatched_input() {
        let fixture = Fixture::new(true);
        let (mut extension, _) = fixture.connect().await;
        let cancel = CancelHandle::pending();
        let task = launch(&fixture.bridge, "type", &cancel);
        let attach = next(&mut extension).await;
        dispatch(&mut extension, &attach, true).await;
        reply(
            &mut extension,
            &attach,
            MessageBody::ReplyStart {
                bytes: 100,
                input_dispatched: true,
            },
        )
        .await;
        reply(
            &mut extension,
            &attach,
            MessageBody::ReplyChunk {
                sequence: 0,
                data: "{\"secret\":".into(),
            },
        )
        .await;
        cancel.cancel();
        assert_eq!(next(&mut extension).await.body, MessageBody::Cancel);
        reply(
            &mut extension,
            &attach,
            MessageBody::Cancelled {
                input_dispatched: true,
                detached: true,
            },
        )
        .await;
        let result = task.await.unwrap();
        assert_eq!(result.terminal, Terminal::Cancelled);
        assert_eq!(result.result, None);
        assert_eq!(result.input_dispatched, Some(true));
        complete(&mut extension, &attach, true).await;
        let next_task = launch(&fixture.bridge, "snapshot", &CancelHandle::pending());
        let next_attach = next(&mut extension).await;
        dispatch(&mut extension, &next_attach, false).await;
        complete(&mut extension, &next_attach, false).await;
        assert_eq!(next_task.await.unwrap().terminal, Terminal::Completed);
    }

    #[tokio::test]
    async fn socket_disconnect_after_dispatch_is_unknown_and_old_epoch_replies_are_dropped() {
        let fixture = Fixture::new(true);
        let (mut extension, old_epoch) = fixture.connect().await;
        let task = launch(&fixture.bridge, "click", &CancelHandle::pending());
        let old_attach = next(&mut extension).await;
        reply(&mut extension, &old_attach, MessageBody::Attached).await;
        assert_eq!(next(&mut extension).await.body, MessageBody::Dispatch);
        drop(extension);
        let result = task.await.unwrap();
        assert_eq!(result.terminal, Terminal::OutcomeUnknown);
        assert_eq!(result.input_dispatched, None);
        assert!(result.remedy.unwrap().contains("again"));
        let (mut new_extension, new_epoch) = fixture.connect().await;
        assert_ne!(old_epoch, new_epoch);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), read_frame(&mut new_extension))
                .await
                .is_err()
        );
        let next_task = launch(&fixture.bridge, "snapshot", &CancelHandle::pending());
        let new_attach = next(&mut new_extension).await;
        dispatch(&mut new_extension, &new_attach, false).await;
        let stale = Message {
            id: new_attach.id,
            epoch: old_epoch,
            body: MessageBody::Attached,
        };
        complete(&mut new_extension, &stale, true).await;
        let stale_id = Message {
            id: old_attach.id,
            epoch: new_epoch,
            body: MessageBody::Attached,
        };
        complete(&mut new_extension, &stale_id, true).await;
        assert!(!next_task.is_finished());
        complete(&mut new_extension, &new_attach, false).await;
        let result = next_task.await.unwrap();
        assert_eq!(result.terminal, Terminal::Completed);
        assert_eq!(result.input_dispatched, Some(false));
    }

    #[tokio::test]
    async fn socket_goodbye_frame_cancels_the_route_and_reports_detachment_without_closing_tabs() {
        let fixture = Fixture::new(true);
        let (mut extension, _) = fixture.connect().await;
        let mut planes =
            crate::Planes::new(Arc::new(cerebellum_core::health::HealthState::default()));
        planes.user_browser = fixture.bridge.clone();
        let task = launch(&fixture.bridge, "click", &CancelHandle::pending());
        let attach = next(&mut extension).await;
        let (writer, _responses) = mpsc::channel(8);
        let frame = subc_protocol::Frame::build(
            subc_protocol::FrameType::Goodbye,
            crate::wire::control_flags(),
            ROUTE.channel,
            ROUTE.epoch,
            0,
            Vec::new(),
        )
        .unwrap();
        crate::handle_frame_for_test(frame, &writer, &planes)
            .await
            .unwrap();
        let first = next(&mut extension).await;
        let second = next(&mut extension).await;
        assert!(matches!(
            (&first.body, &second.body),
            (MessageBody::Goodbye { route: ROUTE }, MessageBody::Cancel)
                | (MessageBody::Cancel, MessageBody::Goodbye { route: ROUTE })
        ));
        reply(
            &mut extension,
            &attach,
            MessageBody::Cancelled {
                input_dispatched: false,
                detached: true,
            },
        )
        .await;
        let result = task.await.unwrap();
        assert_eq!(result.terminal, Terminal::Cancelled);
        assert_eq!(result.input_dispatched, Some(false));
    }

    #[tokio::test]
    async fn socket_complete_chunked_result_is_returned_only_after_reply_end() {
        let fixture = Fixture::new(true);
        let (mut extension, _) = fixture.connect().await;
        let task = launch(&fixture.bridge, "snapshot", &CancelHandle::pending());
        let attach = next(&mut extension).await;
        dispatch(&mut extension, &attach, false).await;
        let value = json!({"text": "λ".repeat(600_000)});
        let encoded = serde_json::to_string(&value).unwrap();
        reply(
            &mut extension,
            &attach,
            MessageBody::ReplyStart {
                bytes: encoded.len(),
                input_dispatched: false,
            },
        )
        .await;
        let mut start = 0;
        let mut sequence = 0;
        while start < encoded.len() {
            let mut end = (start + MAX_CHUNK_BYTES).min(encoded.len());
            while !encoded.is_char_boundary(end) {
                end -= 1;
            }
            let body = MessageBody::ReplyChunk {
                sequence,
                data: encoded[start..end].into(),
            };
            let message = Message {
                id: attach.id,
                epoch: attach.epoch,
                body: body.clone(),
            };
            assert!(serde_json::to_vec(&message).unwrap().len() < MAX_MESSAGE_BYTES);
            reply(&mut extension, &attach, body).await;
            start = end;
            sequence += 1;
        }
        assert!(!task.is_finished());
        reply(
            &mut extension,
            &attach,
            MessageBody::ReplyEnd {
                input_dispatched: false,
                detached: true,
            },
        )
        .await;
        assert_eq!(task.await.unwrap().result, Some(value));
    }

    #[tokio::test]
    async fn socket_permissions_are_private_and_oversized_frames_close_without_admission() {
        use std::os::unix::fs::PermissionsExt;
        use tokio::io::AsyncWriteExt;
        let fixture = Fixture::new(true);
        assert_eq!(
            std::fs::metadata(&fixture.directory)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&fixture.path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let mut stream = UnixStream::connect(&fixture.path).await.unwrap();
        stream
            .write_all(&((MAX_FRAME_BYTES + 1) as u32).to_be_bytes())
            .await
            .unwrap();
        assert_eq!(
            bounded_read(&mut stream).await,
            Frame::HostRefused {
                reason: "protocol_error".into()
            }
        );
        assert_eq!(fixture.bridge.connected_epoch(), None);
    }
}

#[tokio::test]
async fn shutdown_cannot_admit_a_host_that_was_still_handshaking() {
    let bridge = UserBrowserBridge::new();
    bridge.shutdown();
    assert!(matches!(bridge.connect(), Err(Reason::NotConnected)));
}

#[tokio::test]
async fn oversized_command_is_refused_before_attachment() {
    let bridge = UserBrowserBridge::new();
    let (_, mut outgoing, _) = bridge.connect().unwrap();
    let result = bridge
        .invoke(
            ROUTE,
            json!({"text":"x".repeat(MAX_MESSAGE_BYTES)}),
            CancelHandle::pending(),
        )
        .await;
    assert_eq!(result.reason, Some(Reason::CommandTooLarge));
    assert_eq!(result.phases, [ActionPhase::Queued]);
    assert_eq!(result.input_dispatched, Some(false));
    assert!(outgoing.try_recv().is_err());
}

#[tokio::test]
async fn disconnect_after_a_no_input_yet_ack_does_not_claim_no_input_occurred() {
    let bridge = UserBrowserBridge::new();
    let (epoch, mut outgoing, _) = bridge.connect().unwrap();
    let task = launch(&bridge, "type", &CancelHandle::pending());
    let attach = outgoing.recv().await.unwrap();
    bridge.receive(Message {
        id: attach.id,
        epoch,
        body: MessageBody::Attached,
    });
    assert_eq!(outgoing.recv().await.unwrap().body, MessageBody::Dispatch);
    bridge.receive(Message {
        id: attach.id,
        epoch,
        body: MessageBody::Dispatched {
            input_dispatched: false,
        },
    });
    tokio::task::yield_now().await;
    bridge.disconnect(epoch);
    let result = task.await.unwrap();
    assert_eq!(result.terminal, Terminal::OutcomeUnknown);
    assert_eq!(result.input_dispatched, None);
}

#[tokio::test]
async fn cancelled_actions_cannot_leave_attach_or_input_in_the_writer_queue() {
    let bridge = UserBrowserBridge::new();
    let (epoch, mut outgoing, _) = bridge.connect().unwrap();
    let cancel = CancelHandle::pending();
    let task = launch(&bridge, "click", &cancel);
    let attach = outgoing.recv().await.unwrap();
    assert!(bridge.should_send(&attach));
    bridge.receive(Message {
        id: attach.id,
        epoch,
        body: MessageBody::Attached,
    });
    let dispatch = outgoing.recv().await.unwrap();
    assert_eq!(dispatch.body, MessageBody::Dispatch);
    assert!(bridge.should_send(&dispatch));
    cancel.cancel();
    assert!(!bridge.should_send(&attach));
    assert!(!bridge.should_send(&dispatch));
    let cancel_frame = outgoing.recv().await.unwrap();
    assert_eq!(cancel_frame.body, MessageBody::Cancel);
    assert!(bridge.should_send(&cancel_frame));
    bridge.receive(Message {
        id: attach.id,
        epoch,
        body: MessageBody::Cancelled {
            input_dispatched: false,
            detached: true,
        },
    });
    let result = task.await.unwrap();
    assert_eq!(result.terminal, Terminal::Cancelled);
    assert_eq!(result.input_dispatched, Some(false));
}

#[tokio::test(start_paused = true)]
async fn queue_deadline_refuses_without_attaching_or_dispatching() {
    let bridge = UserBrowserBridge::new();
    let (_, mut outgoing, _) = bridge.connect().unwrap();
    let _held_lane = bridge.0.lane.lock().await;
    let task = launch(&bridge, "click", &CancelHandle::pending());
    tokio::task::yield_now().await;
    tokio::time::advance(QUEUE_DEADLINE).await;
    let result = task.await.unwrap();
    assert_eq!(result.terminal, Terminal::Refused);
    assert_eq!(result.reason, Some(Reason::QueueDeadline));
    assert_eq!(result.phases, [ActionPhase::Queued]);
    assert_eq!(result.input_dispatched, Some(false));
    assert!(outgoing.try_recv().is_err());
}

#[tokio::test]
async fn extension_refusals_end_once_and_preserve_the_typed_detail() {
    for dispatched in [false, true] {
        let bridge = UserBrowserBridge::new();
        let (epoch, mut outgoing, _) = bridge.connect().unwrap();
        let task = launch(&bridge, "click", &CancelHandle::pending());
        let attach = outgoing.recv().await.unwrap();
        if dispatched {
            bridge.receive(Message {
                id: attach.id,
                epoch,
                body: MessageBody::Attached,
            });
            assert_eq!(outgoing.recv().await.unwrap().body, MessageBody::Dispatch);
            bridge.receive(Message {
                id: attach.id,
                epoch,
                body: MessageBody::Dispatched {
                    input_dispatched: true,
                },
            });
        }
        bridge.receive(Message {
            id: attach.id,
            epoch,
            body: MessageBody::Refused {
                reason: "tab_taken_back".into(),
                input_dispatched: dispatched,
                detached: true,
            },
        });
        let result = task.await.unwrap();
        assert_eq!(result.terminal, Terminal::Refused);
        assert_eq!(result.reason, Some(Reason::ExtensionRefused));
        assert_eq!(result.extension_reason.as_deref(), Some("tab_taken_back"));
        assert_eq!(result.input_dispatched, Some(dispatched));
        assert_eq!(result.phases.len(), if dispatched { 3 } else { 2 });
        assert!(bridge.state().replies.is_empty());
        assert!(bridge.state().calls.is_empty());
    }
}
