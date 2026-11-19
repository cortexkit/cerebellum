use super::*;
use crate::{ability::helper::Helpers, ability_helper::*, terminal_arbiter::TerminalCause};
use std::{
    collections::VecDeque,
    io,
    path::Path,
    pin::Pin,
    sync::atomic::AtomicBool,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{advance, Duration, Instant},
};

#[derive(Clone, Copy)]
enum Fault {
    None,
    Oversized,
    Malformed,
    Exit,
}

#[derive(Clone)]
struct Config {
    commit: &'static str,
    start_error: bool,
    status: PermissionStatus,
    prompting: bool,
    hang: bool,
    fault: Fault,
    result: Value,
    stop_at_prompt: Option<Arc<TerminalArbiter>>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            commit: "same-commit",
            start_error: false,
            status: PermissionStatus::Granted,
            prompting: false,
            hang: false,
            fault: Fault::None,
            result: json!({"items":[]}),
            stop_at_prompt: None,
        }
    }
}

#[derive(Default)]
struct Fake {
    config: Mutex<Config>,
    frames: Mutex<Vec<Value>>,
    starts: AtomicUsize,
    kills: AtomicUsize,
    reaps: AtomicUsize,
    closes: AtomicUsize,
    request_apis: AtomicUsize,
    idle_exited: AtomicBool,
    hold_reap: AtomicBool,
    reap_wake: tokio::sync::Notify,
}

struct FakeLauncher(Arc<Fake>);
impl Launcher for FakeLauncher {
    fn start<'a>(
        &'a self,
        kind: UnitKind,
        path: &'a Path,
    ) -> HelperFuture<'a, io::Result<Box<dyn Process>>> {
        Box::pin(async move {
            assert!(path.is_absolute());
            assert_eq!(path.parent(), std::env::current_exe().unwrap().parent());
            assert_eq!(
                path.file_name().unwrap(),
                if kind == UnitKind::Pim {
                    "ck-cerebellum-pim"
                } else {
                    "ck-cerebellum-fda"
                }
            );
            self.0.starts.fetch_add(1, Ordering::SeqCst);
            let config = self.0.config.lock().unwrap().clone();
            if config.start_error {
                return Err(io::Error::other("absent, not startable or unverified"));
            }
            self.0.idle_exited.store(false, Ordering::SeqCst);
            let mut channel = FakeChannel {
                fake: self.0.clone(),
                input: vec![],
                output: VecDeque::new(),
                eof: false,
                stop_after_read: None,
            };
            channel.reply(Reply::Hello {
                build_commit: config.commit.into(),
            });
            Ok(Box::new(FakeProcess { channel }) as Box<dyn Process>)
        })
    }
}

struct FakeProcess {
    channel: FakeChannel,
}
impl Process for FakeProcess {
    fn channel(&mut self) -> &mut dyn Channel {
        &mut self.channel
    }
    fn has_exited(&mut self) -> io::Result<bool> {
        Ok(self.channel.fake.idle_exited.load(Ordering::SeqCst))
    }
    fn kill(&mut self) -> io::Result<()> {
        self.channel.fake.kills.fetch_add(1, Ordering::SeqCst);
        self.channel.eof = true;
        Ok(())
    }
    fn close_channel(&mut self) {
        self.channel.fake.closes.fetch_add(1, Ordering::SeqCst);
        self.channel.eof = true;
    }
    fn reap(&mut self) -> HelperFuture<'_, io::Result<()>> {
        Box::pin(async {
            while self.channel.fake.hold_reap.load(Ordering::SeqCst) {
                self.channel.fake.reap_wake.notified().await;
            }
            self.channel.fake.reaps.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }
}

struct FakeChannel {
    fake: Arc<Fake>,
    input: Vec<u8>,
    output: VecDeque<u8>,
    eof: bool,
    stop_after_read: Option<Arc<TerminalArbiter>>,
}
impl FakeChannel {
    fn reply(&mut self, reply: Reply) {
        let body = serde_json::to_vec(&reply).unwrap();
        self.output.extend((body.len() as u32).to_be_bytes());
        self.output.extend(body);
    }

    fn request(&mut self, request: Value) {
        self.fake.frames.lock().unwrap().push(request.clone());
        let config = self.fake.config.lock().unwrap().clone();
        match config.fault {
            Fault::Oversized => {
                self.output.extend(((REPLY_MAX + 1) as u32).to_be_bytes());
                return;
            }
            Fault::Malformed => {
                self.output.extend([0, 0, 0, 1, b'{']);
                return;
            }
            Fault::Exit => {
                self.eof = true;
                return;
            }
            Fault::None => {}
        }
        match request["method"].as_str().unwrap() {
            "status" if !config.hang => {
                let tokens: Vec<Token> = serde_json::from_value(request["tokens"].clone()).unwrap();
                self.reply(Reply::Status {
                    tokens: tokens
                        .into_iter()
                        .map(|token| TokenStatus {
                            token,
                            status: config.status,
                        })
                        .collect(),
                });
            }
            "setup" if config.prompting => {
                self.reply(Reply::Prompting);
                self.stop_after_read = config.stop_at_prompt;
            }
            "setup" if !config.hang => self.reply(Reply::Setup {
                status: config.status,
            }),
            "proceed" => {
                self.fake.request_apis.fetch_add(1, Ordering::SeqCst);
                if !config.hang {
                    self.reply(Reply::Setup {
                        status: config.status,
                    });
                }
            }
            "call" | "choices" => self.reply(Reply::Result {
                value: config.result,
            }),
            _ => {}
        }
    }
}

impl AsyncRead for FakeChannel {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.output.is_empty() {
            return if self.eof {
                Poll::Ready(Ok(()))
            } else {
                Poll::Pending
            };
        }
        while buf.remaining() > 0 {
            let Some(byte) = self.output.pop_front() else {
                break;
            };
            buf.put_slice(&[byte]);
        }
        if self.output.is_empty() {
            if let Some(gate) = self.stop_after_read.take() {
                assert!(gate.stop(TerminalCause::Cancelled));
            }
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for FakeChannel {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.input.extend_from_slice(bytes);
        while self.input.len() >= 4 {
            let len = u32::from_be_bytes(self.input[..4].try_into().unwrap()) as usize;
            assert!(len <= REQUEST_MAX);
            if self.input.len() < len + 4 {
                break;
            }
            let request = serde_json::from_slice(&self.input[4..len + 4]).unwrap();
            self.input.drain(..len + 4);
            self.request(request);
        }
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn fixture_helper(config: Config) -> (Planes, Arc<Fake>) {
    let fake = Arc::new(Fake {
        config: Mutex::new(config),
        ..Default::default()
    });
    let mut planes = fixture(Arc::new(FakeStatus::default()), Platform::MacOs);
    let abilities = &mut Arc::get_mut(&mut planes.management).unwrap().abilities;
    abilities.binding = Arc::new(Bound);
    abilities.helpers = Some(Helpers::new(
        "same-commit".into(),
        Arc::new(FakeLauncher(fake.clone())),
    ));
    (planes, fake)
}

fn setup_request(token: Token) -> Value {
    json!({"method":SETUP, "params":{"token":token.as_str()}})
}
async fn rows(planes: &Planes) -> Vec<Value> {
    planes
        .browser
        .journal_export_for_test()
        .await
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}
async fn dispatch_setup(
    planes: &Planes,
    gate: Arc<TerminalArbiter>,
) -> Result<Option<Value>, Refusal> {
    let body = setup_request(Token::Contacts);
    dispatch(
        &planes.management.abilities,
        &planes.browser,
        &facts("prefrontal"),
        SETUP,
        body.as_object().unwrap(),
        gate,
    )
    .await
}

#[tokio::test]
async fn helper_first_need_revision_and_launch_failures_are_fail_closed() {
    for (config, expected) in [
        (
            Config {
                start_error: true,
                ..Default::default()
            },
            "helper_unverified",
        ),
        (
            Config {
                commit: "another-commit",
                ..Default::default()
            },
            "helper_revision_mismatch",
        ),
    ] {
        let (planes, fake) = fixture_helper(config);
        assert_eq!(fake.starts.load(Ordering::SeqCst), 0);
        let described = body(&reserved(&planes, json!({"method":DESCRIBE})).await);
        assert!(described["tokens"]
            .as_array()
            .unwrap()
            .iter()
            .all(|token| token["unavailable_reason"] == expected));
        assert!(fake.frames.lock().unwrap().is_empty());
        assert_eq!(
            body(&reserved(&planes, setup_request(Token::Contacts)).await)["code"],
            expected
        );
    }
}

#[tokio::test(start_paused = true)]
async fn helper_idle_death_is_reaped_and_replaced_and_channel_expires_at_thirty_seconds() {
    let (planes, fake) = fixture_helper(Config::default());
    reserved(&planes, setup_request(Token::Contacts)).await;
    assert_eq!(fake.starts.load(Ordering::SeqCst), 1);
    fake.idle_exited.store(true, Ordering::SeqCst);
    assert_eq!(
        body(&reserved(&planes, setup_request(Token::Contacts)).await),
        json!({"state":"granted"})
    );
    assert_eq!(fake.starts.load(Ordering::SeqCst), 2);
    assert_eq!(fake.reaps.load(Ordering::SeqCst), 1);
    advance(Duration::from_secs(29)).await;
    assert_eq!(fake.closes.load(Ordering::SeqCst), 1);
    advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(fake.closes.load(Ordering::SeqCst), 2);
    assert_eq!(fake.reaps.load(Ordering::SeqCst), 2);
    assert_eq!(fake.kills.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn helper_source_deadline_bad_frames_and_inflight_exit_kill_and_reap() {
    for (config, expected) in [
        (
            Config {
                hang: true,
                ..Default::default()
            },
            "ability_source_timeout",
        ),
        (
            Config {
                fault: Fault::Oversized,
                ..Default::default()
            },
            "ability_source_failed",
        ),
        (
            Config {
                fault: Fault::Malformed,
                ..Default::default()
            },
            "ability_source_failed",
        ),
        (
            Config {
                fault: Fault::Exit,
                ..Default::default()
            },
            "ability_source_failed",
        ),
    ] {
        let (planes, fake) = fixture_helper(config);
        let before = Instant::now();
        assert_eq!(
            body(&reserved(&planes, setup_request(Token::Contacts)).await)["code"],
            expected
        );
        if expected == "ability_source_timeout" {
            assert_eq!(Instant::now() - before, Duration::from_secs(10));
        }
        assert_eq!(fake.kills.load(Ordering::SeqCst), 1);
        assert_eq!(fake.reaps.load(Ordering::SeqCst), 1);
        assert_eq!(rows(&planes).await[0]["detail"]["outcome"], expected);
    }
}

#[tokio::test]
async fn helper_decided_permissions_never_prompt_and_fda_setup_has_only_its_optional_path() {
    for status in [
        PermissionStatus::Granted,
        PermissionStatus::Denied,
        PermissionStatus::Restricted,
        PermissionStatus::WriteOnly,
    ] {
        let (planes, fake) = fixture_helper(Config {
            status,
            ..Default::default()
        });
        let expected = if status == PermissionStatus::Granted {
            "granted"
        } else {
            "denied"
        };
        assert_eq!(
            body(&reserved(&planes, setup_request(Token::Contacts)).await),
            json!({"state":expected})
        );
        assert_eq!(fake.request_apis.load(Ordering::SeqCst), 0);
        if status != PermissionStatus::Granted {
            assert_eq!(
                body(&reserved(&planes, list(Token::Contacts, 10)).await)["code"],
                "permission_missing"
            );
        }
    }
    for (status, state) in [
        (PermissionStatus::PermissionMissing, "needs_person_action"),
        (PermissionStatus::FormatUnrecognized, "granted"),
        (PermissionStatus::Granted, "granted"),
    ] {
        let (planes, _) = fixture_helper(Config {
            status,
            ..Default::default()
        });
        let reply = body(&reserved(&planes, setup_request(Token::Mail)).await);
        assert_eq!(reply["state"], state);
        assert_eq!(
            reply.as_object().unwrap().contains_key("executable_path"),
            state == "needs_person_action"
        );
        if state == "needs_person_action" {
            assert!(reply["executable_path"]
                .as_str()
                .unwrap()
                .ends_with("ck-cerebellum-fda"));
        }
    }
    let (planes, _) = fixture_helper(Config {
        status: PermissionStatus::SourceMissing,
        ..Default::default()
    });
    assert_eq!(
        body(&reserved(&planes, setup_request(Token::Mail)).await)["code"],
        "source_missing"
    );
}

#[tokio::test(start_paused = true)]
async fn helper_prompt_proceed_grants_or_denies_and_park_lapse_is_unanswered() {
    for status in [PermissionStatus::Granted, PermissionStatus::Denied] {
        let (planes, fake) = fixture_helper(Config {
            status,
            prompting: true,
            ..Default::default()
        });
        let reply = body(&reserved(&planes, setup_request(Token::Contacts)).await);
        assert_eq!(
            reply["state"],
            if status == PermissionStatus::Granted {
                "granted"
            } else {
                "denied"
            }
        );
        assert_eq!(fake.request_apis.load(Ordering::SeqCst), 1);
        assert_eq!(fake.frames.lock().unwrap()[1], json!({"method":"proceed"}));
    }
    let (planes, fake) = fixture_helper(Config {
        prompting: true,
        hang: true,
        ..Default::default()
    });
    let before = Instant::now();
    assert_eq!(
        body(&reserved(&planes, setup_request(Token::Contacts)).await),
        json!({"state":"unanswered"})
    );
    assert_eq!(Instant::now() - before, Duration::from_secs(120));
    assert_eq!(fake.kills.load(Ordering::SeqCst), 1);
    assert_eq!(fake.reaps.load(Ordering::SeqCst), 1);
    assert_eq!(rows(&planes).await[0]["detail"]["outcome"], "unanswered");
}

#[tokio::test]
async fn helper_cancelled_after_prompting_sends_no_proceed_and_commits_stopped() {
    let gate = Arc::new(TerminalArbiter::new(request(setup_request(
        Token::Contacts,
    ))));
    let (planes, fake) = fixture_helper(Config {
        prompting: true,
        stop_at_prompt: Some(gate.clone()),
        ..Default::default()
    });
    assert!(dispatch_setup(&planes, gate).await.unwrap().is_none());
    assert_eq!(
        fake.frames.lock().unwrap().as_slice(),
        &[json!({"method":"setup","token":Token::Contacts.as_str()})]
    );
    assert_eq!(fake.request_apis.load(Ordering::SeqCst), 0);
    assert_eq!(fake.kills.load(Ordering::SeqCst), 1);
    assert_eq!(fake.reaps.load(Ordering::SeqCst), 1);
    assert_eq!(rows(&planes).await[0]["detail"]["outcome"], "stopped");
}

#[tokio::test(start_paused = true)]
async fn helper_open_prompt_stop_kills_within_one_second_and_holds_unit_until_reaped_and_committed()
{
    let gate = Arc::new(TerminalArbiter::new(request(setup_request(
        Token::Contacts,
    ))));
    let (planes, fake) = fixture_helper(Config {
        prompting: true,
        hang: true,
        ..Default::default()
    });
    fake.hold_reap.store(true, Ordering::SeqCst);
    let work = dispatch_setup(&planes, gate.clone());
    tokio::pin!(work);
    tokio::select! {
        biased;
        _ = &mut work => panic!("prompt must stay open"),
        _ = tokio::task::yield_now() => {},
    }
    assert_eq!(fake.request_apis.load(Ordering::SeqCst), 1);
    advance(Duration::from_secs(31)).await;
    assert_eq!(
        fake.closes.load(Ordering::SeqCst),
        0,
        "a parked setup is not idle"
    );
    assert!(gate.stop(TerminalCause::Cancelled));
    let stopped_at = Instant::now();
    tokio::select! {
        biased;
        _ = &mut work => panic!("reap is held"),
        _ = tokio::time::sleep(Duration::from_millis(250)) => {},
    }
    assert_eq!(fake.kills.load(Ordering::SeqCst), 1);
    assert!(Instant::now() - stopped_at <= Duration::from_secs(1));
    assert!(rows(&planes).await.is_empty(), "commit must follow reap");
    let unit = planes
        .management
        .abilities
        .units
        .for_token(Token::Contacts)
        .unwrap();
    let next_gate = Arc::new(TerminalArbiter::new(request(setup_request(
        Token::Contacts,
    ))));
    let next = unit.arrive(next_gate).unwrap().wait();
    tokio::pin!(next);
    tokio::select! { biased; _ = &mut next => panic!("unit must remain held"), _ = tokio::task::yield_now() => {} }
    fake.hold_reap.store(false, Ordering::SeqCst);
    fake.reap_wake.notify_one();
    assert!(work.await.unwrap().is_none());
    assert_eq!(rows(&planes).await[0]["detail"]["outcome"], "stopped");
    drop(next.await.unwrap());
    *fake.config.lock().unwrap() = Config::default();
    assert_eq!(
        body(&reserved(&planes, setup_request(Token::Contacts)).await),
        json!({"state":"granted"})
    );
    assert_eq!(fake.starts.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn helper_busy_prompt_or_hang_and_older_os_precedence_have_no_source_or_journal_effects() {
    for prompting in [false, true] {
        let (mut planes, fake) = fixture_helper(Config {
            prompting,
            hang: true,
            ..Default::default()
        });
        Arc::get_mut(&mut planes.management)
            .unwrap()
            .abilities
            .macos_14_or_newer = false;
        let gate = Arc::new(TerminalArbiter::new(request(setup_request(
            Token::Contacts,
        ))));
        let work = dispatch_setup(&planes, gate.clone());
        tokio::pin!(work);
        tokio::select! { biased; _ = &mut work => panic!("park must stay open"), _ = tokio::task::yield_now() => {} }
        let before = Instant::now();
        let frames = fake.frames.lock().unwrap().len();
        assert_eq!(
            body(&reserved(&planes, list(Token::Calendar, 10)).await)["code"],
            "os_unsupported"
        );
        assert_eq!(Instant::now(), before);
        assert_eq!(fake.frames.lock().unwrap().len(), frames);
        assert!(rows(&planes).await.is_empty());
        assert_eq!(
            body(&reserved(&planes, list(Token::Contacts, 10)).await)["code"],
            "ability_source_timeout"
        );
        assert_eq!(Instant::now() - before, Duration::from_secs(10));
        assert_eq!(fake.frames.lock().unwrap().len(), frames);
        assert!(rows(&planes).await.is_empty());
        assert!(gate.stop(TerminalCause::Cancelled));
        assert!(work.await.unwrap().is_none());
    }
}

#[tokio::test(start_paused = true)]
async fn helper_older_os_describe_keeps_os_reason_over_missing_revision_and_hung_contacts() {
    for (config, reason) in [
        (
            Config {
                start_error: true,
                ..Default::default()
            },
            "helper_unverified",
        ),
        (
            Config {
                commit: "different",
                ..Default::default()
            },
            "helper_revision_mismatch",
        ),
        (
            Config {
                hang: true,
                ..Default::default()
            },
            "source_unresponsive",
        ),
    ] {
        let (mut planes, fake) = fixture_helper(config);
        Arc::get_mut(&mut planes.management)
            .unwrap()
            .abilities
            .macos_14_or_newer = false;
        for token in [Token::Calendar, Token::Reminders] {
            assert_eq!(
                body(&reserved(&planes, setup_request(token)).await)["code"],
                "os_unsupported"
            );
        }
        assert_eq!(fake.starts.load(Ordering::SeqCst), 0);
        let description = body(&reserved(&planes, json!({"method":DESCRIBE})).await);
        let tokens = description["tokens"].as_array().unwrap();
        assert_eq!(tokens[0]["unavailable_reason"], "os_unsupported");
        assert_eq!(tokens[1]["unavailable_reason"], "os_unsupported");
        assert_eq!(tokens[2]["unavailable_reason"], reason);
        for request in fake.frames.lock().unwrap().iter() {
            let tokens = request["tokens"].as_array().unwrap();
            assert!(!tokens.contains(&json!(Token::Calendar)));
            assert!(!tokens.contains(&json!(Token::Reminders)));
        }
        assert!(rows(&planes).await.is_empty());
    }
}

#[tokio::test]
async fn helper_scope_check_discards_whole_page_and_cursor_and_get_id_cap_sends_nothing() {
    let token = Token::Calendar;
    let args = validate_args(
        token,
        "events.list",
        &json!({"from_ms":0,"to_ms":30,"limit":1}),
    )
    .unwrap();
    let scope = validate_scope(token, &json!({"calendar":["bound"]})).unwrap();
    let page = cerebellum_ability::page::build_page(
        token,
        "events.list",
        &args,
        &scope,
        [item(token, "one", "bound"), item(token, "two", "bound")].map(TaggedItem::from_item),
    )
    .unwrap();
    let mut value = serde_json::to_value(page).unwrap();
    assert!(value.get("next_cursor").is_some());
    let (planes, fake) = fixture_helper(Config {
        result: value.clone(),
        ..Default::default()
    });
    assert_eq!(body(&reserved(&planes, list(token, 1)).await), value);
    value["items"][0]["calendar"] = json!("outside");
    fake.config.lock().unwrap().result = value;
    let refused = body(&reserved(&planes, list(token, 1)).await);
    assert_eq!(refused["code"], "ability_source_failed");
    assert!(refused.get("items").is_none());
    assert!(refused.get("next_cursor").is_none());
    assert_eq!(fake.kills.load(Ordering::SeqCst), 1);
    let before = fake.frames.lock().unwrap().len();
    let starts = fake.starts.load(Ordering::SeqCst);
    let entries = rows(&planes).await.len();
    assert_eq!(
        body(
            &reserved(
                &planes,
                call(token, "events.get", json!({"id":"x".repeat(2049)}))
            )
            .await
        )["code"],
        "ability_args_invalid"
    );
    assert_eq!(fake.frames.lock().unwrap().len(), before);
    assert_eq!(fake.starts.load(Ordering::SeqCst), starts);
    assert_eq!(rows(&planes).await.len(), entries);
}

#[tokio::test(start_paused = true)]
async fn helper_frames_use_big_endian_lengths_and_enforce_both_byte_caps() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut writer, mut reader) = tokio::io::duplex(32);
    write_frame(&mut writer, &json!({"x":1}), REQUEST_MAX)
        .await
        .unwrap();
    let mut bytes = [0; 11];
    reader.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"\0\0\0\x07{\"x\":1}");
    assert!(
        write_frame(&mut writer, &"x".repeat(REQUEST_MAX), REQUEST_MAX)
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(1), reader.read_u8())
            .await
            .is_err(),
        "oversized request sent bytes"
    );
    let (mut writer, mut reader) = tokio::io::duplex(REPLY_MAX + 4);
    let maximum = "x".repeat(REQUEST_MAX - 2);
    write_frame(&mut writer, &maximum, REQUEST_MAX)
        .await
        .unwrap();
    assert_eq!(
        read_frame::<String>(&mut reader, REQUEST_MAX)
            .await
            .unwrap(),
        maximum
    );
    let maximum = "x".repeat(REPLY_MAX - 2);
    write_frame(&mut writer, &maximum, REPLY_MAX).await.unwrap();
    assert_eq!(
        read_frame::<String>(&mut reader, REPLY_MAX).await.unwrap(),
        maximum
    );
    writer.write_u32((REPLY_MAX + 1) as u32).await.unwrap();
    assert!(
        read_frame::<Value>(&mut reader, REPLY_MAX).await.is_err(),
        "reject header before reading or allocating its body"
    );
}
