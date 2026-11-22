//! Health-only observations of the helper the transport owns.

use cerebellum_macos::ProcessGeneration;
use std::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, AtomicUsize, Ordering};

const STARTED: usize = 0;
const START_REASONS: &[&str] = &[
    "started",
    "pin_failure",
    "spawn_error",
    "release_error",
    "screen_locked_or_unreadable",
    "restart_limit",
    "launch_deadline",
    "reply_reader_start_error",
    "unknown",
];

pub(super) const SCREEN_LOCKED: &str = "mouse-down recipient helper screen locked or unreadable";

#[derive(Clone, Copy)]
pub(super) enum ExitReason {
    SenderDisconnect,
    PipeWriteFailure,
    PipeStalled,
    ChildExited,
    ChildUnverified,
    ReplyMalformed,
    Shutdown,
}

const EXIT_REASONS: &[&str] = &[
    "sender_disconnect",
    "pipe_write_failure",
    "pipe_stalled",
    "child_exited",
    "child_unverified",
    "reply_malformed",
    "shutdown",
];

pub(super) struct HelperGauges {
    start: [AtomicU64; START_REASONS.len()],
    last_failure: AtomicUsize,
    exits: [AtomicU64; EXIT_REASONS.len()],
    last_wait_status: AtomicI32,
    reply_disconnects: AtomicU64,
    pid: AtomicU32,
    start_micros: AtomicU64,
}

impl HelperGauges {
    pub(super) const fn new() -> Self {
        Self {
            start: [const { AtomicU64::new(0) }; START_REASONS.len()],
            last_failure: AtomicUsize::new(STARTED),
            exits: [const { AtomicU64::new(0) }; EXIT_REASONS.len()],
            last_wait_status: AtomicI32::new(-1),
            reply_disconnects: AtomicU64::new(0),
            pid: AtomicU32::new(0),
            start_micros: AtomicU64::new(0),
        }
    }

    pub(super) fn started(&self, generation: ProcessGeneration) {
        self.start[STARTED].fetch_add(1, Ordering::Relaxed);
        self.start_micros
            .store(generation.start_time_micros, Ordering::Relaxed);
        self.pid.store(generation.pid, Ordering::Release);
    }

    pub(super) fn start_failed(&self, error: &'static str) {
        let index = match error {
            "mouse-down recipient helper pinned executable unavailable"
            | "mouse-down recipient helper pinned child verification failed" => 1,
            "mouse-down recipient helper spawn failed" => 2,
            "mouse-down recipient helper release failed" => 3,
            SCREEN_LOCKED => 4,
            "mouse-down recipient helper restart limit reached" => 5,
            "mouse-down recipient helper launch budget exceeded" => 6,
            "mouse-down recipient helper reply reader start failed" => 7,
            _ => 8,
        };
        self.start[index].fetch_add(1, Ordering::Relaxed);
        self.last_failure.store(index, Ordering::Relaxed);
    }

    pub(super) fn exit(&self, reason: ExitReason, status: Option<i32>) {
        self.pid.store(0, Ordering::Release);
        if let Some(status) = status {
            self.last_wait_status.store(status, Ordering::Relaxed);
        }
        self.exits[reason as usize].fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn reply_reader_disconnected(&self) {
        self.reply_disconnects.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn report(&self) -> serde_json::Value {
        let counts = |reasons: &[&str], counts: &[AtomicU64]| -> serde_json::Map<_, _> {
            reasons
                .iter()
                .zip(counts)
                .map(|(&reason, count)| (reason.to_owned(), count.load(Ordering::Relaxed).into()))
                .collect()
        };
        let failure = self.last_failure.load(Ordering::Relaxed);
        let status = self.last_wait_status.load(Ordering::Relaxed);
        let pid = self.pid.load(Ordering::Acquire);
        let pid = (pid != 0
            && cerebellum_macos::process_start_time_micros(pid)
                == Some(self.start_micros.load(Ordering::Relaxed)))
        .then_some(pid);
        let mut exits = counts(EXIT_REASONS, &self.exits);
        // Kept for health consumers that still read the previous key.
        exits.insert("pipe_would_block".into(), 0.into());
        serde_json::json!({
            "cursorHelperStartOutcomes": counts(START_REASONS, &self.start),
            "cursorHelperLastStartFailure": (failure != STARTED).then(|| START_REASONS[failure]),
            "cursorHelperExitReasons": exits,
            "cursorHelperLastWaitStatus": (status >= 0).then_some(status),
            "cursorHelperReplyReaderDisconnects": self.reply_disconnects.load(Ordering::Relaxed),
            "cursorHelperPid": pid,
        })
    }
}

pub(super) static HELPER_GAUGES: HelperGauges = HelperGauges::new();
