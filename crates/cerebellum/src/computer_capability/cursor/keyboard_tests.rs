use super::super::preview::{
    CaptureJob, NoFrameReason, PreviewCapturer, PreviewJpeg, PreviewPlane,
};
use super::*;
use cerebellum_computer::app_state::source::{
    AppStateReadError, RawAppState, RawElement, ReadBounds,
};

const AGENT: &str = "keyboard-badge";
const WINDOW: [f64; 4] = [100.0, 80.0, 800.0, 600.0];
const INPUT: [f64; 4] = [180.0, 500.0, 200.0, 30.0];
const CLICK: [f64; 2] = [200.0, 515.0];

struct Geometry {
    window: ElementHandle,
    window_frame: std::sync::Mutex<Option<[f64; 4]>>,
    focus: std::sync::Mutex<Option<[f64; 4]>>,
    caret: std::sync::Mutex<Option<[f64; 4]>>,
}

impl AppStateSource for Geometry {
    fn read_app_state(
        &self,
        _: &ProcessGrant,
        _: ReadBounds,
    ) -> Result<RawAppState, AppStateReadError> {
        Err(AppStateReadError::Unreadable)
    }

    fn cursor_label(&self, _: &ElementHandle) -> Option<(Option<String>, bool)> {
        Some((Some("Message".into()), false))
    }

    fn cursor_frame(&self, element: &ElementHandle) -> Option<[f64; 4]> {
        if element.same_element(self.window.as_ref()) {
            *self.window_frame.lock().unwrap()
        } else {
            *self.focus.lock().unwrap()
        }
    }

    fn cursor_caret_frame(&self, _: &ElementHandle) -> Option<[f64; 4]> {
        *self.caret.lock().unwrap()
    }

    fn cursor_window(&self, _: &ProcessGrant, _: Option<&ElementHandle>) -> Option<ElementHandle> {
        Some(self.window.clone())
    }

    fn element_window_number(&self, _: &ElementHandle) -> Option<u32> {
        Some(10)
    }

    fn window_minimized(&self, _: &ElementHandle) -> Option<bool> {
        Some(false)
    }

    fn application_hidden(&self, _: &ProcessGrant) -> Option<bool> {
        Some(false)
    }

    fn visible_cursor_point(
        &self,
        _: &ProcessGrant,
        point: Option<[f64; 2]>,
        frame: Option<[f64; 4]>,
    ) -> Option<[f64; 2]> {
        let [x, y, w, h] = frame.unwrap_or(WINDOW);
        Some(point.unwrap_or([x + w / 2.0, y + h / 2.0]))
    }
}

struct Capture;

impl PreviewCapturer for Capture {
    fn capture(&self, _: &CaptureJob) -> Result<PreviewJpeg, NoFrameReason> {
        Ok(PreviewJpeg {
            size: [4, 3],
            jpeg: vec![0xff, 0xd8, 0xff, 0xd9],
        })
    }
}

struct Rig {
    cursor: Coordinator,
    receiver: mpsc::Receiver<CursorLine>,
    geometry: Arc<Geometry>,
    preview: Option<Arc<PreviewWorker>>,
}

impl Rig {
    fn new(background: bool) -> Self {
        let (cursor, receiver) = Coordinator::channel();
        let preview = background.then(|| {
            PreviewPlane::new(
                Arc::new(Capture),
                true,
                Arc::new(|_| Some(10)),
                Arc::new(|_| None),
            )
            .worker(&cursor)
        });
        Self {
            cursor,
            receiver,
            geometry: Arc::new(Geometry {
                window: RawElement::fixture(100, "AXWindow").handle,
                window_frame: std::sync::Mutex::new(Some(WINDOW)),
                focus: std::sync::Mutex::new(Some(INPUT)),
                caret: std::sync::Mutex::new(None),
            }),
            preview,
        }
    }

    fn position(&self, [x, y]: [f64; 2]) -> [f64; 2] {
        if self.preview.is_some() {
            [(x - WINDOW[0]) / WINDOW[2], (y - WINDOW[1]) / WINDOW[3]]
        } else {
            [x, y]
        }
    }

    async fn picture(&mut self, kind: CursorKind, focused: bool) -> [f64; 2] {
        let identity = Identity::for_test(AGENT, None, None);
        let grant = ProcessGrant {
            bundle_identity: "fixture.app".into(),
            pid: 42,
            process_generation_evidence: "fixture-generation".into(),
        };
        let element = focused.then(|| RawElement::fixture(2, "AXTextField").handle);
        let point = (kind == CursorKind::Press).then_some(CLICK);
        if let Some(worker) = &self.preview {
            self.cursor.schedule_in_preview(
                identity,
                kind,
                grant,
                self.geometry.clone(),
                ReadAim {
                    preferred: element,
                    focused: None,
                },
                point,
                PreviewAim {
                    worker: worker.clone(),
                    app: "Chat".into(),
                    window: WindowChoice::Element,
                    frontmost: Arc::new(|_| Some(10)),
                    bundle: Arc::new(|_| None),
                    call: None,
                },
            );
        } else {
            self.cursor
                .schedule(identity, kind, grant, self.geometry.clone(), element, point);
        }
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match self.receiver.recv().await.expect("cursor channel") {
                    CursorLine::Picture(event) if self.preview.is_none() => {
                        if kind == CursorKind::Type {
                            assert_eq!(
                                event.label.as_deref(),
                                self.geometry
                                    .window_frame
                                    .lock()
                                    .unwrap()
                                    .map(|_| if focused {
                                        "Typing in Message"
                                    } else {
                                        "Typing in"
                                    })
                            );
                        }
                        let tip = self.cursor.drawn().tips[AGENT].place();
                        if event.resting {
                            return tip;
                        }
                        assert_eq!(tip, event.to);
                        return event.to;
                    }
                    CursorLine::PreviewMotion(motion) if self.preview.is_some() => {
                        assert_eq!(self.cursor.drawn().tips[AGENT].place(), motion.pmotion_to);
                        return motion.pmotion_to;
                    }
                    CursorLine::Preview(preview) if kind == CursorKind::Type => {
                        assert_eq!(
                            preview.preview_label.as_deref(),
                            Some(if focused {
                                "Typing in Message"
                            } else {
                                "Typing in"
                            })
                        );
                    }
                    _ => {}
                }
            }
        })
        .await
        .expect("keyboard badge was drawn")
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.cursor.shutdown();
    }
}

#[tokio::test]
async fn keyboard_without_a_caret_keeps_the_clicked_input_inside_a_web_area() {
    for background in [false, true] {
        for kind in [CursorKind::Type, CursorKind::Keys] {
            let mut rig = Rig::new(background);
            assert_eq!(
                rig.picture(CursorKind::Press, true).await,
                rig.position(CLICK)
            );
            *rig.geometry.focus.lock().unwrap() = Some(WINDOW);
            assert_eq!(
                rig.picture(kind, true).await,
                rig.position(CLICK),
                "{background}, {kind:?}"
            );
        }
    }
}

#[tokio::test]
async fn keyboard_without_a_caret_keeps_a_clicked_point_inside_a_small_field() {
    for background in [false, true] {
        for kind in [CursorKind::Type, CursorKind::Keys] {
            let mut rig = Rig::new(background);
            rig.picture(CursorKind::Press, true).await;
            assert_eq!(
                rig.picture(kind, true).await,
                rig.position(CLICK),
                "{background}, {kind:?}"
            );
        }
    }
}

#[tokio::test]
async fn keyboard_caret_wins_over_the_last_clicked_input() {
    for background in [false, true] {
        for kind in [CursorKind::Type, CursorKind::Keys] {
            let mut rig = Rig::new(background);
            rig.picture(CursorKind::Press, true).await;
            *rig.geometry.focus.lock().unwrap() = Some(WINDOW);
            *rig.geometry.caret.lock().unwrap() = Some([220.0, 507.0, 0.0, 16.0]);
            assert_eq!(
                rig.picture(kind, true).await,
                rig.position([220.0, 515.0]),
                "{background}, {kind:?}"
            );
        }
    }
}

#[tokio::test]
async fn keyboard_follows_a_small_field_when_tab_moves_focus() {
    for background in [false, true] {
        for kind in [CursorKind::Type, CursorKind::Keys] {
            let mut rig = Rig::new(background);
            rig.picture(CursorKind::Press, true).await;
            *rig.geometry.focus.lock().unwrap() = Some([500.0, 200.0, 200.0, 30.0]);
            assert_eq!(
                rig.picture(kind, true).await,
                rig.position([600.0, 215.0]),
                "{background}, {kind:?}"
            );
        }
    }
}

#[tokio::test]
async fn keyboard_with_unreadable_focus_keeps_the_clicked_input() {
    for background in [false, true] {
        for kind in [CursorKind::Type, CursorKind::Keys] {
            for focused in [false, true] {
                let mut rig = Rig::new(background);
                rig.picture(CursorKind::Press, true).await;
                *rig.geometry.focus.lock().unwrap() = None;
                assert_eq!(
                    rig.picture(kind, focused).await,
                    rig.position(CLICK),
                    "{background}, {kind:?}, {focused}"
                );
            }
        }
    }
}

#[tokio::test]
async fn keyboard_without_a_prior_press_aims_at_a_small_field() {
    for background in [false, true] {
        for kind in [CursorKind::Type, CursorKind::Keys] {
            let mut rig = Rig::new(background);
            assert_eq!(
                rig.picture(kind, true).await,
                rig.position([280.0, 515.0]),
                "{background}, {kind:?}"
            );
        }
    }
}

#[tokio::test]
async fn keyboard_can_aim_at_a_small_field_without_window_bounds() {
    for kind in [CursorKind::Type, CursorKind::Keys] {
        for clicked in [false, true] {
            let mut rig = Rig::new(false);
            if clicked {
                rig.picture(CursorKind::Press, true).await;
            }
            *rig.geometry.window_frame.lock().unwrap() = None;
            *rig.geometry.focus.lock().unwrap() = Some([500.0, 200.0, 200.0, 30.0]);
            assert_eq!(
                rig.picture(kind, true).await,
                [600.0, 215.0],
                "{kind:?}, {clicked}"
            );
        }
    }
}

#[tokio::test]
async fn keyboard_does_not_retarget_to_a_large_container_elsewhere() {
    for background in [false, true] {
        for kind in [CursorKind::Type, CursorKind::Keys] {
            for frame in [[500.0, 90.0, 300.0, 350.0], [100.0, 90.0, 800.0, 155.0]] {
                let mut rig = Rig::new(background);
                rig.picture(CursorKind::Press, true).await;
                *rig.geometry.focus.lock().unwrap() = Some(frame);
                assert_eq!(
                    rig.picture(kind, true).await,
                    rig.position(CLICK),
                    "{background}, {kind:?}, {frame:?}"
                );
            }
        }
    }
}

#[tokio::test]
async fn keyboard_invalid_carets_do_not_override_the_last_clicked_input() {
    for background in [false, true] {
        for kind in [CursorKind::Type, CursorKind::Keys] {
            for caret in [[20.0, 20.0, 0.0, 16.0], [220.0, 507.0, f64::NAN, 16.0]] {
                let mut rig = Rig::new(background);
                rig.picture(CursorKind::Press, true).await;
                *rig.geometry.focus.lock().unwrap() = Some(WINDOW);
                *rig.geometry.caret.lock().unwrap() = Some(caret);
                assert_eq!(
                    rig.picture(kind, true).await,
                    rig.position(CLICK),
                    "{background}, {kind:?}, {caret:?}"
                );
            }
        }
    }
}
