//! A lossy, memory-only picture alongside an admitted action. Nothing here
//! returns an action outcome or receives a request body.

use std::sync::{Arc, OnceLock};
use std::time::Duration;
#[cfg(any(target_os = "macos", test))]
use std::time::Instant;

use cerebellum_computer::app_state::source::{AppStateSource, ElementHandle};
use cerebellum_computer::cursor::{label, CursorEvent, CursorKind};
use cerebellum_computer::platform::ProcessGrant;
use tokio::sync::mpsc;

const READ_BUDGET: Duration = Duration::from_millis(50);
const CAPACITY: usize = 32;

#[cfg(target_os = "macos")]
pub(crate) mod avatar;

tokio::task_local! {
    pub(crate) static ACTING_AGENT: Option<String>;
}

pub(crate) struct Identity {
    badge: String,
    avatar_agent: Option<String>,
}

impl Identity {
    pub(crate) fn current(fallback: String) -> Self {
        let avatar_agent = ACTING_AGENT.try_with(Clone::clone).ok().flatten();
        Self {
            badge: avatar_agent.clone().unwrap_or(fallback),
            avatar_agent,
        }
    }
}

#[derive(Default)]
struct State {
    stopped: std::sync::atomic::AtomicBool,
    sender: OnceLock<mpsc::Sender<CursorEvent>>,
    serial: std::sync::atomic::AtomicU64,
    #[cfg(target_os = "macos")]
    avatars: OnceLock<Arc<avatar::Avatars>>,
    #[cfg(target_os = "macos")]
    generation: std::sync::Mutex<Option<cerebellum_macos::ProcessGeneration>>,
}

#[derive(Clone, Default)]
pub struct Coordinator(Arc<State>);

/// An initial launch and at most one restart, no sooner than a minute later.
/// A second crash leaves the cosmetic helper off until the module restarts.
#[derive(Default)]
#[cfg(any(target_os = "macos", test))]
struct RestartLimit {
    first: Option<Instant>,
    restarted: bool,
}

#[cfg(any(target_os = "macos", test))]
impl RestartLimit {
    fn admit(&mut self, now: Instant) -> bool {
        match self.first {
            None => {
                self.first = Some(now);
                true
            }
            Some(first)
                if !self.restarted && now.duration_since(first) >= Duration::from_secs(60) =>
            {
                self.restarted = true;
                true
            }
            _ => false,
        }
    }
}

impl Coordinator {
    #[cfg(target_os = "macos")]
    pub(crate) fn set_avatars(&self, avatars: Arc<avatar::Avatars>) {
        let _ = self.0.avatars.set(avatars);
    }
    /// Tests may supply a blocked or closed receiver without drawing a window.
    /// All production planes start disabled; only the module's config loader
    /// enables the native transport.
    #[doc(hidden)]
    pub fn channel() -> (Self, mpsc::Receiver<CursorEvent>) {
        let result = Self::default();
        let (tx, rx) = mpsc::channel(CAPACITY);
        let _ = result.0.sender.set(tx);
        (result, rx)
    }

    pub fn enable(&self, enabled: bool) {
        if !enabled {
            self.shutdown();
        }
        #[cfg(target_os = "macos")]
        if enabled && self.0.sender.get().is_none() {
            let (tx, rx) = mpsc::channel(CAPACITY);
            if self.0.sender.set(tx).is_ok() {
                let state = self.0.clone();
                let _ = std::thread::Builder::new()
                    .name("agent-cursor-pipe".into())
                    .spawn(move || transport(state, rx));
            }
        }
    }

    /// No lock, await, backpressure, journal, or call-record writer on this path.
    pub fn send(&self, event: CursorEvent) {
        if self.0.stopped.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        if let Some(sender) = self.0.sender.get() {
            let _ = sender.try_send(event);
        }
    }

    /// The whole optional read has a deadline. A slow AX reply may still finish
    /// on its blocking thread, but it can never emit a late picture or hold an
    /// action. Do not change a retained AX element's timeout: dispatch shares it.
    pub(crate) fn schedule(
        &self,
        identity: Identity,
        kind: CursorKind,
        grant: ProcessGrant,
        source: Arc<dyn AppStateSource>,
        handle: Option<ElementHandle>,
        point: Option<[f64; 2]>,
    ) {
        if self.0.sender.get().is_none()
            || self.0.stopped.load(std::sync::atomic::Ordering::Acquire)
        {
            return;
        }
        let cursor = self.clone();
        let serial = self
            .0
            .serial
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        tokio::spawn(async move {
            let agent = identity.badge;
            #[cfg(not(target_os = "macos"))]
            let _ = identity.avatar_agent;
            let read = tokio::task::spawn_blocking(move || {
                let (title, secure, frame) = match handle {
                    Some(handle) => {
                        // A read's picture has no label, so it reads no title.
                        let (title, secure) = if kind == CursorKind::Reading {
                            (None, false)
                        } else {
                            source.cursor_label(&handle).unwrap_or((None, true))
                        };
                        let frame = source.cursor_frame(&handle);
                        (title, secure, frame)
                    }
                    None => (None, false, None),
                };
                // Element actions without an exact point aim at the frame's
                // visible centre, never its origin. Only reads may appear with
                // nothing to aim at; a press or a write with no geometry shows
                // no picture rather than a misleading one.
                if point.is_none()
                    && frame.is_none()
                    && matches!(kind, CursorKind::Press | CursorKind::Write)
                {
                    return None;
                }
                let to = source.visible_cursor_point(&grant, point, frame)?;
                Some(CursorEvent {
                    initial: agent.chars().next().unwrap_or('A').to_ascii_uppercase(),
                    agent,
                    to,
                    target: frame,
                    resting: point.is_none() && frame.is_none(),
                    label: label(kind, title.as_deref(), secure),
                    kind,
                    serial,
                    avatar_rgba: None,
                    avatar_update: false,
                })
            });
            if let Ok(Ok(Some(event))) = tokio::time::timeout(READ_BUDGET, read).await {
                cursor.send(event.clone());
                #[cfg(target_os = "macos")]
                if let (Some(agent), Some(avatars)) =
                    (identity.avatar_agent, cursor.0.avatars.get())
                {
                    if let Some(pixels) = avatars.fetch_and_render(&agent).await {
                        let mut update = event;
                        update.avatar_rgba = Some(pixels);
                        update.avatar_update = true;
                        cursor.send(update);
                    }
                }
            }
        });
    }

    /// Signal before browser teardown starts. Reaping and any blocked pipe write
    /// belong to the transport thread, never to the twenty-second drain budget.
    pub fn shutdown(&self) {
        self.0
            .stopped
            .store(true, std::sync::atomic::Ordering::Release);
        #[cfg(target_os = "macos")]
        if let Some(generation) = *self
            .0
            .generation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            let _ = cerebellum_macos::terminate_exact_generation(generation);
        }
        if let Some(sender) = self.0.sender.get() {
            // Wake an idle transport so it can reap its child. A full channel
            // already guarantees a wake; the stopped flag prevents any drawing.
            let _ = sender.try_send(CursorEvent {
                agent: String::new(),
                initial: 'A',
                to: [0.0, 0.0],
                target: None,
                resting: true,
                label: None,
                kind: CursorKind::Reading,
                serial: 0,
                avatar_rgba: None,
                avatar_update: false,
            });
        }
    }
}

#[cfg(target_os = "macos")]
fn transport(state: Arc<State>, mut rx: mpsc::Receiver<CursorEvent>) {
    use std::io::Write;
    let mut helper: Option<(cerebellum_macos::ReleasedChild, std::fs::File)> = None;
    let mut restarts = RestartLimit::default();
    while let Some(event) = rx.blocking_recv() {
        if state.stopped.load(std::sync::atomic::Ordering::Acquire) {
            break;
        }
        // A locked or unreadable screen never launches or displays the helper.
        if cerebellum_macos::screen_is_locked() != Some(false) {
            continue;
        }
        if helper.is_none() {
            if !restarts.admit(Instant::now()) {
                continue;
            }
            let launched = (|| {
                let executable = std::env::current_exe().ok()?;
                let (barred, pipe) =
                    cerebellum_macos::spawn_barred_stdin(&executable, &["--agent-cursor".into()])
                        .ok()?;
                let mut generation = state
                    .generation
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if state.stopped.load(std::sync::atomic::Ordering::Acquire) {
                    return None;
                }
                *generation = Some(barred.generation());
                cerebellum_macos::register_cursor_generation(*generation);
                drop(generation);
                let child = barred.release().ok()?;
                Some((child, std::fs::File::from(pipe)))
            })();
            helper = launched;
        }
        let Some(line) = event.encode_line() else {
            continue;
        };
        if helper
            .as_mut()
            .is_some_and(|(_, pipe)| pipe.write_all(&line).is_err())
        {
            helper.take();
            cerebellum_macos::register_cursor_generation(None);
            *state
                .generation
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        }
    }
    drop(helper);
}

#[cfg(test)]
mod tests {
    use super::*;

    struct SlowGeometry;
    impl AppStateSource for SlowGeometry {
        fn read_app_state(
            &self,
            _: &ProcessGrant,
            _: cerebellum_computer::app_state::source::ReadBounds,
        ) -> Result<
            cerebellum_computer::app_state::source::RawAppState,
            cerebellum_computer::app_state::source::AppStateReadError,
        > {
            Err(cerebellum_computer::app_state::source::AppStateReadError::Unreadable)
        }
        fn cursor_label(&self, _: &ElementHandle) -> Option<(Option<String>, bool)> {
            Some((Some("Send".into()), false))
        }
        fn cursor_frame(&self, _: &ElementHandle) -> Option<[f64; 4]> {
            std::thread::sleep(Duration::from_millis(150));
            Some([0.0, 0.0, 10.0, 10.0])
        }
        fn visible_cursor_point(
            &self,
            _: &ProcessGrant,
            p: Option<[f64; 2]>,
            _: Option<[f64; 4]>,
        ) -> Option<[f64; 2]> {
            p
        }
    }

    #[tokio::test]
    async fn cursor_geometry_deadline_discards_late_reads_without_blocking_actions() {
        let (cursor, mut receiver) = Coordinator::channel();
        let grant = ProcessGrant {
            bundle_identity: "test.app".into(),
            pid: 7,
            process_generation_evidence: "generation".into(),
        };
        let start = Instant::now();
        cursor.schedule(
            Identity::current("agent".into()),
            CursorKind::Press,
            grant,
            Arc::new(SlowGeometry),
            Some(cerebellum_computer::app_state::source::RawElement::fixture(1, "AXButton").handle),
            None,
        );
        assert!(
            start.elapsed() < READ_BUDGET,
            "scheduling must not read geometry inline"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(250), receiver.recv())
                .await
                .is_err(),
            "late geometry must not reach the helper"
        );
    }

    #[test]
    fn cursor_restart_limit_is_one_after_a_minute() {
        let start = Instant::now();
        let mut limit = RestartLimit::default();
        assert!(limit.admit(start));
        assert!(!limit.admit(start + Duration::from_secs(59)));
        assert!(limit.admit(start + Duration::from_secs(60)));
        assert!(!limit.admit(start + Duration::from_secs(120)));
    }

    #[test]
    fn cursor_send_never_waits_on_a_full_pipe() {
        let (cursor, _receiver) = Coordinator::channel();
        let event = CursorEvent {
            agent: "agent".into(),
            initial: 'A',
            to: [1.0, 1.0],
            target: None,
            resting: false,
            label: None,
            kind: CursorKind::Press,
            serial: 0,
            avatar_rgba: None,
            avatar_update: false,
        };
        for _ in 0..CAPACITY {
            cursor.send(event.clone());
        }
        // On a separate thread so an accidentally blocking send fails by timeout
        // rather than wedging the test executor.
        let (done, received) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            cursor.send(event);
            let _ = done.send(());
        });
        assert!(
            received.recv_timeout(Duration::from_millis(100)).is_ok(),
            "cursor send awaited a full channel"
        );
    }
}
