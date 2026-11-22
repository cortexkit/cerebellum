//! Process-lifetime counts only: no window, app or agent identity is retained.

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NoFrameReason {
    Controller,
    Permission,
    Enumeration,
    WindowNotVerified,
    Capture,
    Owner,
    CaptureSize,
    Encode,
    EncodedSize,
    Unsupported,
    Stale,
    Minimized,
    InvalidFrame,
    NoWriter,
    QueueFull,
    Superseded,
    HiddenBeforeWrite,
    Stopped,
    EncodeLine,
    Transport,
    ScreenLockedOrUnreadable,
    HelperUnavailable,
    PipeWrite,
    // Kept in the health report; transient backpressure no longer drops frames.
    PipeWouldBlock,
    PipeStalled,
}

const REASONS: &[(NoFrameReason, &str)] = {
    use NoFrameReason::*;
    &[
        (Controller, "controller"),
        (Permission, "permission"),
        (Enumeration, "enumeration"),
        (WindowNotVerified, "window_not_verified"),
        (Capture, "capture"),
        (Owner, "owner"),
        (CaptureSize, "capture_size"),
        (Encode, "encode"),
        (EncodedSize, "encoded_size"),
        (Unsupported, "unsupported"),
        (Stale, "stale"),
        (Minimized, "minimized"),
        (InvalidFrame, "invalid_frame"),
        (NoWriter, "no_writer"),
        (QueueFull, "queue_full"),
        (Superseded, "superseded"),
        (HiddenBeforeWrite, "hidden_before_write"),
        (Stopped, "stopped"),
        (EncodeLine, "encode_line"),
        (Transport, "transport"),
        (ScreenLockedOrUnreadable, "screen_locked_or_unreadable"),
        (HelperUnavailable, "helper_unavailable"),
        (PipeWrite, "pipe_write"),
        (PipeWouldBlock, "pipe_would_block"),
        (PipeStalled, "pipe_stalled"),
    ]
};

/// The health lane reads process counters without taking any preview locks.
#[derive(Debug)]
pub(crate) struct PreviewGauges {
    capture_requests: AtomicU64,
    frames_written: AtomicU64,
    capture_wait_timeouts: AtomicU64,
    show_enqueue_drops: AtomicU64,
    no_frame: [AtomicU64; REASONS.len()],
}

impl PreviewGauges {
    pub(crate) const fn new() -> Self {
        Self {
            capture_requests: AtomicU64::new(0),
            frames_written: AtomicU64::new(0),
            capture_wait_timeouts: AtomicU64::new(0),
            show_enqueue_drops: AtomicU64::new(0),
            no_frame: [const { AtomicU64::new(0) }; REASONS.len()],
        }
    }

    pub(crate) fn capture_requests(&self) -> u64 {
        self.capture_requests.load(Ordering::Relaxed)
    }

    pub(crate) fn frames_written(&self) -> u64 {
        self.frames_written.load(Ordering::Relaxed)
    }

    pub(crate) fn frame_written(&self) {
        self.frames_written.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn capture_requested(&self) {
        self.capture_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn capture_wait_elapsed(&self) {
        self.capture_wait_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    pub(super) fn show_enqueue_dropped(&self) {
        self.show_enqueue_drops.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn no_frame(&self, reason: NoFrameReason) {
        self.no_frame[reason as usize].fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(any(test, target_os = "macos"))]
    pub(crate) fn report(&self) -> serde_json::Value {
        let reasons: serde_json::Map<_, _> = REASONS
            .iter()
            .map(|&(reason, word)| {
                let count = self.no_frame[reason as usize].load(Ordering::Relaxed);
                (word.to_owned(), count.into())
            })
            .collect();
        serde_json::json!({
            "previewCaptureWaitTimeouts": self.capture_wait_timeouts.load(Ordering::Relaxed),
            "previewShowEnqueueDrops": self.show_enqueue_drops.load(Ordering::Relaxed),
            "previewNoFrameReasons": reasons,
        })
    }
}

pub(crate) static PREVIEW_GAUGES: PreviewGauges = PreviewGauges::new();
