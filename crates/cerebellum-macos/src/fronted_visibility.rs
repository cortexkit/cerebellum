//! Certify one prepared window before and after a fronted picture.

use std::time::Instant;

use super::dock_overlay::{DockOverlayWitness, WitnessFence};
use crate::window_image::VisibilityScope;
use crate::window_visibility::{
    fronted_frame_matches, visibility_with_cover, Rect, VisibilityRule, Window, WindowVisibility,
};

pub type VisibilityDecision = (WindowVisibility, VisibilityRule);
type Snapshot = (Vec<Window>, Vec<Rect>);

const UNKNOWN: VisibilityDecision = (WindowVisibility::Unknown, VisibilityRule::MissingData);
const VISIBLE: VisibilityDecision = (
    WindowVisibility::FullyVisible,
    VisibilityRule::NoLayerZeroOverlap,
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DockExemption {
    pub window_id: u32,
    pub sample_count: usize,
}

#[derive(Clone, Copy)]
struct DockWindow {
    pid: u32,
    id: u32,
    bounds: Rect,
}

struct FrontedWindow {
    pid: u32,
    id: u32,
    bounds: Rect,
}

/// The window certified for this acquisition. `PreparedWindowCapture` must
/// match its cached ScreenCaptureKit filter's owner, window ID and frame to
/// this proof before requesting pixels.
pub struct FrontedWindowProof {
    pid: u32,
    generation: u64,
    id: u32,
    bounds: Rect,
}

impl FrontedWindowProof {
    pub(super) fn matches(&self, pid: u32, id: u32, frame: [f64; 4]) -> bool {
        self.pid == pid
            && self.id == id
            && self.bounds == Rect::from_frame(frame)
            && crate::process_start_time_micros(pid) == Some(self.generation)
    }
}

impl FrontedWindow {
    fn observe_before(
        &self,
        mut snapshot: impl FnMut(VisibilityScope) -> Option<Snapshot>,
        mut current_dock: impl FnMut() -> Option<DockWindow>,
        sample: impl FnOnce() -> Option<(usize, usize)>,
    ) -> (VisibilityDecision, Option<DockExemption>, bool) {
        let Some((windows, displays)) = snapshot(VisibilityScope::ThroughTarget) else {
            return (UNKNOWN, None, false);
        };
        let mut attempted_witness = false;
        let (verdict, exemption) = self.before(&windows, &displays, current_dock(), || {
            attempted_witness = true;
            sample()
        });
        if exemption.is_none() {
            return (verdict, None, attempted_witness);
        }
        // Focus or cover can change while ScreenCaptureKit samples the Dock
        // window's alpha. Recheck before acquiring the target's pixels.
        let verdict = snapshot(VisibilityScope::ThroughTarget)
            .map_or(UNKNOWN, |(windows, displays)| {
                self.after(&windows, &displays, current_dock(), exemption)
            });
        (verdict, exemption, false)
    }

    fn observe_after(
        &self,
        snapshot: impl FnOnce(VisibilityScope) -> Option<Snapshot>,
        current_dock: impl FnOnce() -> Option<DockWindow>,
        exemption: Option<DockExemption>,
    ) -> VisibilityDecision {
        // Only a new list, read after the pixels arrive, can certify the
        // target is still frontmost and the cover has not changed.
        snapshot(VisibilityScope::AllOnScreen).map_or(UNKNOWN, |(windows, displays)| {
            self.after(&windows, &displays, current_dock(), exemption)
        })
    }

    fn inspect(
        &self,
        windows: &[Window],
        displays: &[Rect],
        dock: Option<DockWindow>,
    ) -> (VisibilityDecision, bool) {
        // Use the same live window order as the fronting bracket, not AppKit's
        // cached frontmost app. Require the exact prepared picture window too.
        if !fronted_frame_matches(windows, self.pid, self.id, self.bounds) {
            return (UNKNOWN, false);
        }
        let mut cover = Vec::new();
        let verdict = visibility_with_cover(self.pid, self.id, windows, displays, &mut cover);
        let sole_dock = dock.is_some_and(|dock| {
            let [slot] = cover.as_slice() else {
                return false;
            };
            let window = &windows[*slot];
            window.pid == Some(dock.pid)
                && window.id == Some(dock.id)
                && window.layer == Some(20)
                && window.bounds == Some(dock.bounds)
                && displays.contains(&dock.bounds)
        });
        (verdict, sole_dock)
    }

    fn before(
        &self,
        windows: &[Window],
        displays: &[Rect],
        dock: Option<DockWindow>,
        sample: impl FnOnce() -> Option<(usize, usize)>,
    ) -> (VisibilityDecision, Option<DockExemption>) {
        let (verdict, sole_dock) = self.inspect(windows, displays, dock);
        if let Some(dock) = dock.filter(|_| sole_dock) {
            if let Some((total, 0)) = sample().filter(|(total, _)| *total > 0) {
                return (
                    VISIBLE,
                    Some(DockExemption {
                        window_id: dock.id,
                        sample_count: total,
                    }),
                );
            }
        }
        (verdict, None)
    }

    fn after(
        &self,
        windows: &[Window],
        displays: &[Rect],
        dock: Option<DockWindow>,
        evidence: Option<DockExemption>,
    ) -> VisibilityDecision {
        let (verdict, sole_dock) = self.inspect(windows, displays, dock);
        if sole_dock
            && dock
                .zip(evidence)
                .is_some_and(|(dock, exemption)| dock.id == exemption.window_id)
        {
            VISIBLE
        } else {
            verdict
        }
    }
}

/// A closed, text-free reason visibility preparation stopped before fronting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrontedVisibilityPrepareError {
    WindowNotOnScreen,
    DockWorkspaceLookup,
    DockMultipleProcesses,
    DockProcessGeneration,
    DockDisplayBounds,
    DockWindowList,
    DockRaster,
    DockWorkerStart,
    DockWorkerWait,
    DockCaptureLookup,
    DockCaptureOwner,
    DockCaptureIdentityOrFrame,
}

impl FrontedVisibilityPrepareError {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WindowNotOnScreen => "window_not_on_screen",
            Self::DockWorkspaceLookup => "dock_workspace_lookup",
            Self::DockMultipleProcesses => "dock_multiple_processes",
            Self::DockProcessGeneration => "dock_process_generation",
            Self::DockDisplayBounds => "dock_display_bounds",
            Self::DockWindowList => "dock_window_list",
            Self::DockRaster => "dock_raster",
            Self::DockWorkerStart => "dock_worker_start",
            Self::DockWorkerWait => "dock_worker_wait",
            Self::DockCaptureLookup => "dock_capture_lookup",
            Self::DockCaptureOwner => "dock_capture_owner",
            Self::DockCaptureIdentityOrFrame => "dock_capture_identity_or_frame",
        }
    }
}

/// Why preparing the Dock check failed. That check proves the macOS 27 Dock's
/// invisible full-screen window is fully transparent before a covered window's
/// picture is trusted. The desk probe (`dock_overlay_probe`) prints `message`
/// to the person running it; production replies and health counters carry only
/// the closed `kind`, so no OS error text leaves the module.
#[derive(Debug)]
pub(crate) struct DockPrepareFailure {
    kind: FrontedVisibilityPrepareError,
    message: String,
}

impl DockPrepareFailure {
    pub(crate) fn new(kind: FrontedVisibilityPrepareError, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

impl From<DockPrepareFailure> for String {
    fn from(error: DockPrepareFailure) -> Self {
        error.message
    }
}

/// The exact target and optional single-window Dock witness prepared before any
/// front request. Neither preparation nor a failed visibility check reads pixels.
pub struct PreparedFrontedVisibility {
    target: FrontedWindow,
    generation: u64,
    dock: Option<DockOverlayWitness>,
    exemption: Option<DockExemption>,
}

impl PreparedFrontedVisibility {
    pub fn prepare(
        pid: u32,
        generation: u64,
        window_id: u32,
    ) -> Result<Self, FrontedVisibilityPrepareError> {
        let frame = crate::window_image::visible_window_frame(pid, window_id)
            .ok_or(FrontedVisibilityPrepareError::WindowNotOnScreen)?;
        let dock = DockOverlayWitness::prepare_for_rect(frame, true).map_err(|error| error.kind)?;
        Ok(Self {
            target: FrontedWindow {
                pid,
                id: window_id,
                bounds: Rect::from_frame(frame),
            },
            generation,
            dock,
            exemption: None,
        })
    }

    fn snapshot(&self, scope: VisibilityScope) -> Option<Snapshot> {
        #[cfg(feature = "desk-probe")]
        let _step = crate::picture_probe_timing::Step::new(
            crate::picture_probe_timing::token(self.target.id),
            "visibility_snapshot_started",
            "visibility_snapshot_returned",
        );
        if crate::process_start_time_micros(self.target.pid) != Some(self.generation) {
            return None;
        }
        crate::window_image::fronted_visibility_snapshot(self.target.pid, self.target.id, scope)
    }

    fn current_dock(&self) -> Option<DockWindow> {
        let witness = self
            .dock
            .as_ref()
            .filter(|witness| witness.same_generation())?;
        Some(DockWindow {
            pid: witness.dock_pid,
            id: witness.window_id,
            bounds: Rect::from_frame(witness.window_rect),
        })
    }

    pub fn check_before(
        &mut self,
        until: Option<Instant>,
        fence: &WitnessFence,
    ) -> (VisibilityDecision, Option<FrontedWindowProof>, bool) {
        let (verdict, exemption, dock_witness_failed) = self.target.observe_before(
            |scope| self.snapshot(scope),
            || self.current_dock(),
            || {
                #[cfg(feature = "desk-probe")]
                let _step = crate::picture_probe_timing::Step::new(
                    crate::picture_probe_timing::token(self.target.id),
                    "dock_witness_started",
                    "dock_witness_returned",
                );
                let sample = self.dock.as_ref()?.sample(until?, fence.clone()).ok()?;
                Some((sample.total, sample.nonzero))
            },
        );
        self.exemption = exemption;
        let proof = (verdict.0 == WindowVisibility::FullyVisible).then_some(FrontedWindowProof {
            pid: self.target.pid,
            generation: self.generation,
            id: self.target.id,
            bounds: self.target.bounds,
        });
        (verdict, proof, dock_witness_failed)
    }

    pub fn check_after(&self) -> VisibilityDecision {
        #[cfg(feature = "desk-probe")]
        let _step = crate::picture_probe_timing::Step::new(
            crate::picture_probe_timing::token(self.target.id),
            "visibility_recheck_started",
            "visibility_recheck_returned",
        );
        self.target.observe_after(
            |scope| self.snapshot(scope),
            || self.current_dock(),
            self.exemption,
        )
    }

    pub fn exemption(&self) -> Option<DockExemption> {
        self.exemption
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macos::dock_overlay::is_dock_bundle;
    use std::cell::Cell;

    const DOCK: u32 = 1133;
    const TARGET: u32 = 92466;
    const TARGET_WINDOW: u32 = 7207;
    const DOCK_WINDOW: u32 = 37;
    const PIXELS: usize = 276_832;
    const COVERED: VisibilityDecision = (
        WindowVisibility::Covered,
        VisibilityRule::HigherLayerUnionCoverage,
    );

    struct RecordedWindowList {
        target: FrontedWindow,
        windows: Vec<Window>,
        display: Rect,
        dock_bundle: &'static str,
        nonzero_samples: usize,
        sample_calls: Cell<usize>,
    }

    impl RecordedWindowList {
        fn textedit_with_dock_overlay() -> Self {
            let display = Rect::from_frame([0.0, 0.0, 2560.0, 1440.0]);
            let bounds = Rect::from_frame([309.0, 103.0, 656.0, 422.0]);
            Self {
                target: FrontedWindow {
                    pid: TARGET,
                    id: TARGET_WINDOW,
                    bounds,
                },
                windows: vec![
                    entry(DOCK, DOCK_WINDOW, 20, display),
                    entry(TARGET, TARGET_WINDOW, 0, bounds),
                    entry(69_489, 55, 0, bounds),
                ],
                display,
                dock_bundle: "com.apple.dock",
                nonzero_samples: 0,
                sample_calls: Cell::new(0),
            }
        }

        fn prepared_dock(&self) -> Option<DockWindow> {
            is_dock_bundle(self.dock_bundle).then_some(DockWindow {
                pid: DOCK,
                id: DOCK_WINDOW,
                bounds: self.display,
            })
        }

        fn before(&self) -> (VisibilityDecision, Option<DockExemption>) {
            self.target
                .before(&self.windows, &[self.display], self.prepared_dock(), || {
                    self.sample_calls.set(self.sample_calls.get() + 1);
                    Some((PIXELS, self.nonzero_samples))
                })
        }

        fn after(&self, evidence: Option<DockExemption>) -> VisibilityDecision {
            self.target.after(
                &self.windows,
                &[self.display],
                self.prepared_dock(),
                evidence,
            )
        }

        fn lose_front(&mut self) {
            // This other app does not overlap the target; it changes focus only.
            self.windows.insert(
                1,
                entry(
                    69_489,
                    10,
                    0,
                    Rect::from_frame([1550.0, 400.0, 100.0, 200.0]),
                ),
            );
        }

        fn snapshot(mut self, scope: VisibilityScope) -> Snapshot {
            if scope == VisibilityScope::ThroughTarget {
                let target = self
                    .windows
                    .iter()
                    .position(|window| window.id == Some(TARGET_WINDOW))
                    .unwrap();
                self.windows.truncate(target + 1);
            }
            (self.windows, vec![self.display])
        }
    }

    fn entry(pid: u32, id: u32, layer: i64, bounds: Rect) -> Window {
        Window {
            cursor_picture: false,
            id: Some(id),
            pid: Some(pid),
            bounds: Some(bounds),
            alpha: Some(1.0),
            layer: Some(layer),
        }
    }

    fn exact_match_control() {
        let windows = RecordedWindowList::textedit_with_dock_overlay();
        let evidence = Some(DockExemption {
            window_id: DOCK_WINDOW,
            sample_count: PIXELS,
        });
        assert_eq!(windows.before(), (VISIBLE, evidence));
        assert_eq!(windows.sample_calls.get(), 1);
        assert_eq!(windows.after(evidence), VISIBLE);
    }

    #[test]
    fn dock_exemption_accepts_only_the_exact_transparent_overlay() {
        exact_match_control();
    }

    #[test]
    fn dock_exemption_refuses_the_wrong_bundle_even_with_the_same_window_metadata() {
        let mut windows = RecordedWindowList::textedit_with_dock_overlay();
        windows.dock_bundle = "com.example.dock";
        assert_eq!(windows.before(), (COVERED, None));
        assert_eq!(windows.sample_calls.get(), 0);
        exact_match_control();
    }

    #[test]
    fn dock_exemption_refuses_the_wrong_layer() {
        let mut windows = RecordedWindowList::textedit_with_dock_overlay();
        windows.windows[0].layer = Some(21);
        assert_eq!(windows.before(), (COVERED, None));
        assert_eq!(windows.sample_calls.get(), 0);
        exact_match_control();
    }

    #[test]
    fn dock_exemption_refuses_a_window_larger_than_the_display() {
        let mut windows = RecordedWindowList::textedit_with_dock_overlay();
        windows.windows[0].bounds.as_mut().unwrap().width += 1.0;
        assert_eq!(windows.before(), (COVERED, None));
        assert_eq!(windows.sample_calls.get(), 0);
        exact_match_control();
    }

    #[test]
    fn dock_exemption_refuses_a_second_covering_window() {
        let mut windows = RecordedWindowList::textedit_with_dock_overlay();
        windows.windows.insert(
            1,
            entry(69_489, 10, 1, Rect::from_frame([350.0, 150.0, 100.0, 50.0])),
        );
        assert_eq!(windows.before(), (COVERED, None));
        assert_eq!(windows.sample_calls.get(), 0);
        exact_match_control();
    }

    #[test]
    fn dock_exemption_refuses_one_nontransparent_pixel() {
        let mut windows = RecordedWindowList::textedit_with_dock_overlay();
        windows.nonzero_samples = 1;
        assert_eq!(windows.before(), (COVERED, None));
        assert_eq!(windows.sample_calls.get(), 1);
        exact_match_control();
    }

    #[test]
    fn dock_exemption_refuses_when_the_target_was_not_confirmed_frontmost() {
        let mut windows = RecordedWindowList::textedit_with_dock_overlay();
        windows.lose_front();
        assert_eq!(windows.before(), (UNKNOWN, None));
        assert_eq!(windows.sample_calls.get(), 0);
        exact_match_control();
    }

    #[test]
    fn dock_exemption_refuses_when_the_target_loses_front_after_capture() {
        let mut windows = RecordedWindowList::textedit_with_dock_overlay();
        let (state, evidence) = windows.before();
        assert_eq!(state, VISIBLE);
        assert!(evidence.is_some());
        windows.lose_front();
        assert_eq!(windows.after(evidence), UNKNOWN);
    }

    #[test]
    fn at_or_above_target_and_full_lists_agree_on_cover() {
        let recorded_scene = |kind| {
            let mut scene = RecordedWindowList::textedit_with_dock_overlay();
            match kind {
                "second cover" => scene.windows.insert(
                    1,
                    entry(69_489, 10, 1, Rect::from_frame([350.0, 150.0, 100.0, 50.0])),
                ),
                "Dock absent" => {
                    scene.windows.remove(0);
                }
                _ => {}
            }
            scene
        };
        for (kind, expected) in [
            ("sole Dock", (COVERED, true)),
            ("second cover", (COVERED, false)),
            ("Dock absent", (VISIBLE, false)),
        ] {
            for scope in [VisibilityScope::AllOnScreen, VisibilityScope::ThroughTarget] {
                let scene = recorded_scene(kind);
                let scoped = recorded_scene(kind).snapshot(scope);
                assert_eq!(
                    scene
                        .target
                        .inspect(&scoped.0, &scoped.1, scene.prepared_dock()),
                    expected,
                    "{kind}: {scope:?}",
                );
            }
        }
    }

    #[test]
    fn failed_dock_witness_keeps_the_same_covered_verdict() {
        let scene = RecordedWindowList::textedit_with_dock_overlay();
        let snapshot =
            |scope| Some(RecordedWindowList::textedit_with_dock_overlay().snapshot(scope));
        for failed_sample in [None, Some((0, 0)), Some((PIXELS, 1))] {
            assert_eq!(
                scene
                    .target
                    .observe_before(snapshot, || scene.prepared_dock(), || failed_sample),
                (COVERED, None, true)
            );
        }
        assert_eq!(
            scene
                .target
                .observe_before(snapshot, || None, || panic!("no matching Dock")),
            (COVERED, None, false)
        );
    }

    #[test]
    fn picture_only_reads_the_full_list_after_capture() {
        use VisibilityScope::{AllOnScreen, ThroughTarget};

        let scene = RecordedWindowList::textedit_with_dock_overlay();
        let pixels_arrived = Cell::new(false);
        let reads = std::cell::RefCell::new(Vec::new());
        let snapshot = |scope| {
            reads.borrow_mut().push((pixels_arrived.get(), scope));
            let mut live = RecordedWindowList::textedit_with_dock_overlay();
            if pixels_arrived.get() {
                live.lose_front();
            }
            Some(live.snapshot(scope))
        };
        let (before, evidence, dock_witness_failed) =
            scene
                .target
                .observe_before(snapshot, || scene.prepared_dock(), || Some((PIXELS, 0)));
        assert_eq!(before, VISIBLE);
        assert!(evidence.is_some());
        assert!(!dock_witness_failed);
        pixels_arrived.set(true);
        assert_eq!(
            scene
                .target
                .observe_after(snapshot, || scene.prepared_dock(), evidence),
            UNKNOWN,
            "focus lost after pixels arrived must withhold the image",
        );
        assert_eq!(
            reads.into_inner(),
            [
                (false, ThroughTarget),
                (false, ThroughTarget),
                (true, AllOnScreen)
            ],
        );
    }
}
