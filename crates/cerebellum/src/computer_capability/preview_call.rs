//! What one `computer_use` call's badge does with the background-mode
//! preview, and what the call's reply says about it.
//!
//! In background mode an action's badge is drawn inside its agent's preview
//! of the window it acts in; in foreground mode it is drawn on the screen as
//! it always was. `Badges` makes that choice for every badge an action
//! schedules, from the call's mode, and `PreviewCall` carries back what the
//! reply must say when the preview did not track the action
//! (`preview: "not_synchronized"` or `"not_shown_capacity"`) and when the
//! action has settled, so the preview refreshes once more.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};

use cerebellum_computer::app_state::source::AppStateSource;
use cerebellum_computer::cursor::CursorKind;
use cerebellum_computer::platform::ProcessGrant;

use super::cursor::{Arrival, Coordinator, Identity, PreviewAim, ReadAim, WindowChoice};
use super::preview::{PreviewPlane, PreviewWorker};

tokio::task_local! {
    /// The preview state of the `computer_use` call this task serves.
    static CALL_PREVIEW: Arc<PreviewCall>;
}

/// Run `work` as a call whose badges report into `call`.
pub(crate) async fn scope<F: std::future::Future>(call: Arc<PreviewCall>, work: F) -> F::Output {
    CALL_PREVIEW.scope(call, work).await
}

/// The preview state of the call this task serves, if it serves one.
fn current() -> Option<Arc<PreviewCall>> {
    CALL_PREVIEW.try_with(Arc::clone).ok()
}

const NOTHING: u8 = 0;
const NOT_SYNCHRONIZED: u8 = 1;
const NOT_SHOWN_CAPACITY: u8 = 2;

/// One call's preview: what its reply says about it, and the preview its
/// actions showed, which is told the action settled once the last holder of
/// this (the call itself, its badges' tasks and its waits) lets go.
#[derive(Default)]
pub(crate) struct PreviewCall {
    note: AtomicU8,
    shown: Mutex<Option<(Arc<PreviewWorker>, String)>>,
}

impl PreviewCall {
    /// The badge's wait reached its cap before the badge arrived: the
    /// action went ahead of it.
    pub(crate) fn note_not_synchronized(&self) {
        let _ = self.note.compare_exchange(
            NOTHING,
            NOT_SYNCHRONIZED,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
    }

    /// Three other agents' previews were showing: this one was not shown.
    pub(crate) fn note_not_shown_capacity(&self) {
        self.note.store(NOT_SHOWN_CAPACITY, Ordering::SeqCst);
    }

    /// The reply's `preview` value, if the preview did not track the call.
    pub(crate) fn reply_value(&self) -> Option<&'static str> {
        match self.note.load(Ordering::SeqCst) {
            NOT_SYNCHRONIZED => Some("not_synchronized"),
            NOT_SHOWN_CAPACITY => Some("not_shown_capacity"),
            _ => None,
        }
    }

    /// The call's action is showing the agent's preview: it refreshes at
    /// most twice a second until the call settles.
    pub(crate) fn showing(&self, worker: &Arc<PreviewWorker>, agent: &str) {
        worker.action_started(agent);
        let mut shown = self
            .shown
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if shown.is_none() {
            *shown = Some((worker.clone(), agent.to_owned()));
        }
    }
}

impl Drop for PreviewCall {
    /// The call has settled: its preview refreshes once, then waits.
    fn drop(&mut self) {
        let shown = self
            .shown
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some((worker, agent)) = shown {
            worker.action_settled(&agent);
        }
    }
}

/// Schedules one call's badges, on the screen or in the preview as the
/// call's mode says. Built on the call's own task, which knows the mode and
/// the call; it can then be carried to a blocking thread.
#[derive(Clone)]
pub(crate) struct Badges {
    pub(crate) cursor: Coordinator,
    pub(crate) source: Arc<dyn AppStateSource>,
    pub(crate) preview: Arc<PreviewPlane>,
    /// Background previews share the app-use-fronting review gate.
    pub(crate) app_use_fronting_admitted: bool,
    /// The call runs in background mode.
    pub(crate) background: bool,
    /// The application's name, shown on the preview.
    pub(crate) app: String,
    pub(crate) call: Option<Arc<PreviewCall>>,
}

impl Badges {
    /// For the call this task serves.
    pub(crate) fn for_call(
        cursor: Coordinator,
        source: Arc<dyn AppStateSource>,
        preview: Arc<PreviewPlane>,
        app_use_fronting_admitted: bool,
        app: String,
    ) -> Self {
        Self {
            cursor,
            source,
            preview,
            app_use_fronting_admitted,
            background: super::app_use::call_mode()
                .unwrap_or(cerebellum_core::config::AppUse::Background)
                == cerebellum_core::config::AppUse::Background,
            app,
            call: current(),
        }
    }

    /// Schedule an action's badge: in background mode inside the agent's
    /// preview of the window `window` names, in foreground mode on the
    /// screen. With the agent cursor off nothing is drawn and nothing waited
    /// for.
    ///
    /// The mode is the call's, so a change applies at the agent's next
    /// action: a foreground action of an agent whose preview is showing
    /// hides it first (and with it the badge in it) and draws the badge on
    /// the screen again; a background action after foreground ones shows
    /// the preview.
    pub(crate) fn schedule(
        &self,
        identity: Identity,
        kind: CursorKind,
        grant: ProcessGrant,
        aim: ReadAim,
        point: Option<[f64; 2]>,
        window: WindowChoice,
    ) -> Arrival {
        if !self.cursor.enabled() {
            return Arrival::none();
        }
        if !self.background {
            let preview_is_shown = self
                .preview
                .running()
                .is_some_and(|worker| worker.has_preview(identity.badge()));
            if preview_is_shown {
                self.cursor.end(identity.badge());
            }
        }
        if !self.background || !self.app_use_fronting_admitted {
            return self.cursor.schedule_with_fallback(
                identity,
                kind,
                grant,
                self.source.clone(),
                aim,
                point,
            );
        }
        self.cursor.schedule_in_preview(
            identity,
            kind,
            grant,
            self.source.clone(),
            aim,
            point,
            PreviewAim {
                worker: self.preview.worker(&self.cursor),
                window,
                app: self.app.clone(),
                frontmost: self.preview.frontmost(),
                bundle: self.preview.bundle(),
                call: self.call.clone(),
            },
        )
    }
}
