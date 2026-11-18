use super::*;
use crate::computer_capability::cursor::{Coordinator, Identity, SessionScope, TurnOutcome};
use cerebellum_computer::cursor::{CursorEvent, CursorKind, CursorLine, PictureMotion};
use std::sync::{
    atomic::{AtomicU64, AtomicUsize, Ordering},
    Mutex,
};

const SESSION: &str = "0123456789abcdef0123456789abcdef";

#[derive(Default)]
struct Fake {
    opened: AtomicUsize,
    closed: Arc<AtomicUsize>,
    senders: Mutex<Vec<mpsc::Sender<Notice>>>,
    gate: Mutex<Option<Arc<tokio::sync::Notify>>>,
    refresh_after: AtomicU64,
}

struct Closed(Arc<AtomicUsize>);
impl Drop for Closed {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

impl Transport for Fake {
    fn open(&self) -> BoxFuture<'_, Result<Connection, OpenFailure>> {
        Box::pin(async move {
            self.opened.fetch_add(1, Ordering::SeqCst);
            let gate = self.gate.lock().unwrap().clone();
            if let Some(gate) = gate {
                gate.notified().await;
            }
            let (sender, notices) = mpsc::channel(8);
            self.senders.lock().unwrap().push(sender);
            let refresh = self.refresh_after.load(Ordering::SeqCst);
            Ok(Connection {
                notices,
                refresh_at: (refresh != 0).then(|| Instant::now() + Duration::from_secs(refresh)),
                _guard: Box::new(Closed(self.closed.clone())),
            })
        })
    }
}

impl Fake {
    async fn emit(&self, agent: &str, kind: Kind, seq: u64) {
        let sender = self.senders.lock().unwrap().last().unwrap().clone();
        sender
            .send(Notice {
                module: "thalamus-harness",
                agent: agent.into(),
                session: SESSION.into(),
                seq,
                kind,
            })
            .await
            .unwrap();
        settle().await;
    }
}

async fn settle() {
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
}

fn setup() -> (Coordinator, mpsc::Receiver<CursorLine>, Arc<Fake>) {
    let (cursor, lines) = Coordinator::channel();
    let transport = Arc::new(Fake::default());
    cursor.listen_for_turn_hints(transport.clone());
    (cursor, lines, transport)
}

fn draw(cursor: &Coordinator) {
    cursor.draw_for_test(&Identity::for_test(
        "agent-a",
        None,
        Some(SessionScope {
            scope_ref: "head-a".into(),
            epoch: 1,
        }),
    ));
    cursor.send_scheduled_for_test(CursorEvent {
        agent: "agent-a".into(),
        initial: 'A',
        to: [1.0, 1.0],
        target: None,
        window: None,
        resting: true,
        label: None,
        kind: CursorKind::Reading,
        serial: 1,
        avatar_rgba: None,
        avatar_update: false,
        avatar_tint: None,
        motion: PictureMotion::still(),
    });
}

fn hides(lines: &mut mpsc::Receiver<CursorLine>) -> Vec<String> {
    let mut result = Vec::new();
    while let Ok(line) = lines.try_recv() {
        if let CursorLine::Hide(hide) = line {
            result.push(hide.agent);
        }
    }
    result
}

#[tokio::test(start_paused = true)]
async fn matching_turn_ended_hint_ends_the_badge() {
    let (cursor, mut lines, transport) = setup();
    draw(&cursor);
    settle().await;
    transport.emit("agent-a", Kind::Ended, 2).await;
    assert_eq!(hides(&mut lines), ["agent-a"]);
}

#[tokio::test(start_paused = true)]
async fn a_preview_without_motion_opens_hints_and_hides_on_either_turn_end() {
    for direct in [false, true] {
        let (cursor, mut lines, transport) = setup();
        let showing = cursor.show_preview_for_test(&Identity::for_test(
            "agent-a",
            None,
            Some(SessionScope {
                scope_ref: "head-a".into(),
                epoch: 1,
            }),
        ));
        let line = lines.try_recv().unwrap();
        assert!(matches!(line, CursorLine::Preview(_)));
        settle().await;
        assert_eq!(
            transport.opened.load(Ordering::SeqCst),
            0,
            "enqueue is not a confirmed write"
        );
        cursor.confirm_write_for_test(&line);
        settle().await;
        assert_eq!(
            transport.opened.load(Ordering::SeqCst),
            1,
            "a written preview counts as drawn without motion"
        );
        assert!(showing());
        if direct {
            assert!(cursor.turn_ended(SESSION, Some("head-a"), TurnOutcome::Completed));
        } else {
            transport.emit("agent-a", Kind::Ended, 2).await;
        }
        assert_eq!(hides(&mut lines), ["agent-a"]);
        assert!(!showing());
        cursor.confirm_write_for_test(&line);
        settle().await;
        tokio::time::advance(LINGER - Duration::from_secs(1)).await;
        settle().await;
        assert_eq!(transport.closed.load(Ordering::SeqCst), 0);
        tokio::time::advance(Duration::from_secs(1)).await;
        settle().await;
        assert_eq!(
            transport.closed.load(Ordering::SeqCst),
            1,
            "an obsolete write must not keep hints subscribed"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn another_agents_turn_ended_hint_ends_nothing() {
    let (cursor, mut lines, transport) = setup();
    draw(&cursor);
    settle().await;
    transport.emit("agent-b", Kind::Ended, 2).await;
    assert!(hides(&mut lines).is_empty());
    transport.emit("agent-a", Kind::Ended, 2).await;
    assert_eq!(hides(&mut lines), ["agent-a"]);
}

#[tokio::test(start_paused = true)]
async fn stale_hint_never_ends_a_badge_after_a_newer_start() {
    let (cursor, mut lines, transport) = setup();
    draw(&cursor);
    settle().await;
    transport.emit("agent-a", Kind::Started, 1).await;
    transport.emit("agent-a", Kind::Ended, 2).await;
    assert_eq!(hides(&mut lines), ["agent-a"]);
    transport.emit("agent-a", Kind::Started, 10).await;
    draw(&cursor);
    transport.emit("agent-a", Kind::Ended, 9).await;
    assert!(hides(&mut lines).is_empty());
    transport.emit("agent-a", Kind::Ended, 11).await;
    assert_eq!(hides(&mut lines), ["agent-a"]);
}

#[tokio::test(start_paused = true)]
async fn direct_and_hint_end_the_same_turn_once_in_either_order() {
    for direct_first in [true, false] {
        let (cursor, mut lines, transport) = setup();
        draw(&cursor);
        settle().await;
        if direct_first {
            assert!(cursor.turn_ended(SESSION, Some("head-a"), TurnOutcome::Completed));
            transport.emit("agent-a", Kind::Ended, 2).await;
        } else {
            transport.emit("agent-a", Kind::Ended, 2).await;
            assert!(!cursor.turn_ended(SESSION, Some("head-a"), TurnOutcome::Completed));
        }
        assert_eq!(hides(&mut lines), ["agent-a"]);
        draw(&cursor);
        transport.emit("agent-a", Kind::Ended, 2).await;
        assert!(
            hides(&mut lines).is_empty(),
            "redelivery must not hide a new appearance"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn no_subscription_opens_until_a_badge_is_drawn() {
    let (cursor, _lines, transport) = setup();
    settle().await;
    tokio::time::advance(Duration::from_secs(3600)).await;
    settle().await;
    assert_eq!(transport.opened.load(Ordering::SeqCst), 0);
    cursor.draw_for_test(&Identity::for_test("agent-a", None, None));
    settle().await;
    assert_eq!(
        transport.opened.load(Ordering::SeqCst),
        0,
        "recording a geometry read is not drawing"
    );
}

#[tokio::test(start_paused = true)]
async fn subscription_closes_after_linger_and_back_to_back_draws_reuse_it() {
    let (cursor, _lines, transport) = setup();
    draw(&cursor);
    settle().await;
    assert_eq!(transport.opened.load(Ordering::SeqCst), 1);
    cursor.end("agent-a");
    settle().await;
    tokio::time::advance(Duration::from_secs(29)).await;
    settle().await;
    assert_eq!(transport.closed.load(Ordering::SeqCst), 0);
    draw(&cursor);
    settle().await;
    tokio::time::advance(Duration::from_secs(2)).await;
    settle().await;
    assert_eq!(transport.opened.load(Ordering::SeqCst), 1);
    assert_eq!(transport.closed.load(Ordering::SeqCst), 0);
    cursor.end("agent-a");
    settle().await;
    tokio::time::advance(LINGER).await;
    settle().await;
    assert_eq!(transport.closed.load(Ordering::SeqCst), 1);
    tokio::time::advance(Duration::from_secs(3600)).await;
    settle().await;
    assert_eq!(transport.opened.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn core_ends_while_the_live_connection_is_opening() {
    let (cursor, mut lines, transport) = setup();
    let gate = Arc::new(tokio::sync::Notify::new());
    *transport.gate.lock().unwrap() = Some(gate.clone());
    draw(&cursor);
    settle().await;
    assert_eq!(transport.opened.load(Ordering::SeqCst), 1);
    assert!(cursor.turn_ended(SESSION, Some("head-a"), TurnOutcome::Completed));
    assert_eq!(hides(&mut lines), ["agent-a"]);
    gate.notify_one();
    settle().await;
    transport.emit("agent-a", Kind::Ended, 2).await;
    assert!(
        hides(&mut lines).is_empty(),
        "opening must not resurrect the consumed appearance"
    );
    tokio::time::advance(LINGER).await;
    settle().await;
    assert_eq!(transport.closed.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn active_badges_resubscribe_on_refresh_and_disconnect() {
    let (cursor, _lines, transport) = setup();
    transport.refresh_after.store(5, Ordering::SeqCst);
    draw(&cursor);
    settle().await;
    tokio::time::advance(Duration::from_secs(5)).await;
    settle().await;
    assert_eq!(transport.opened.load(Ordering::SeqCst), 2);
    assert_eq!(transport.closed.load(Ordering::SeqCst), 1);
    transport.senders.lock().unwrap().clear();
    settle().await;
    tokio::time::advance(RETRY).await;
    settle().await;
    assert_eq!(transport.opened.load(Ordering::SeqCst), 3);
    cursor.shutdown();
    settle().await;
    let opens = transport.opened.load(Ordering::SeqCst);
    tokio::time::advance(Duration::from_secs(3600)).await;
    settle().await;
    assert_eq!(transport.opened.load(Ordering::SeqCst), opens);
    assert_eq!(transport.closed.load(Ordering::SeqCst), 3);
}

#[tokio::test(start_paused = true)]
async fn ordinary_idle_fade_also_stops_the_subscription() {
    let (cursor, _lines, transport) = setup();
    draw(&cursor);
    settle().await;
    let idle = Duration::from_millis(
        cerebellum_computer::cursor::IDLE_FADE_AFTER_MS + cerebellum_computer::cursor::IDLE_FADE_MS,
    );
    tokio::time::advance(idle + LINGER).await;
    settle().await;
    assert_eq!(transport.closed.load(Ordering::SeqCst), 1);
    assert_eq!(transport.opened.load(Ordering::SeqCst), 1);
}
