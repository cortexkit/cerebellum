//! Window-server visibility facts, separate from the caller's image policy.

/// How much of the window the window server can establish is visible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowVisibility {
    FullyVisible,
    Covered,
    Unknown,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Rect {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

impl Rect {
    fn valid(self) -> bool {
        [
            self.x,
            self.y,
            self.width,
            self.height,
            self.x + self.width,
            self.y + self.height,
        ]
        .iter()
        .all(|v| v.is_finite())
            && self.width > 0.0
            && self.height > 0.0
    }

    fn intersection(self, other: Self) -> Option<Self> {
        let x = self.x.max(other.x);
        let y = self.y.max(other.y);
        let width = (self.x + self.width).min(other.x + other.width) - x;
        let height = (self.y + self.height).min(other.y + other.height) - y;
        (width > 0.0 && height > 0.0).then_some(Self {
            x,
            y,
            width,
            height,
        })
    }
}

/// A list entry may lack bounds; omitting it would falsely prove visibility.
pub(crate) struct Window {
    /// Trusted helper generation, not a title or an app-supplied window name.
    pub cursor_picture: bool,
    pub id: Option<u32>,
    pub pid: Option<u32>,
    pub bounds: Option<Rect>,
    pub alpha: Option<f64>,
    pub layer: Option<i64>,
}

/// A floating cursor cannot supply the frontmost normal application's pid.
pub(crate) fn frontmost_from_windows(windows: &[Window]) -> Option<i32> {
    windows.iter().find_map(|window| {
        if window.layer != Some(0) {
            return None;
        }
        i32::try_from(window.pid?).ok().filter(|pid| *pid > 0)
    })
}

/// A standard title bar's height. A picture with nothing to point at appears
/// below it, never over the window's close and minimise buttons.
const TITLE_BAR: f64 = 28.0;

/// Where the cursor picture's tip goes in the granted app's window. An exact
/// point wins. An element frame gives the centre of the part of the frame that
/// lies inside the window, so a half-scrolled element still gets a visible
/// point. With neither, the middle of the window's content. Any of these
/// covered by another app's normal window gives no point at all.
pub(crate) fn cursor_point_from_windows(
    pid: u32,
    point: Option<[f64; 2]>,
    frame: Option<[f64; 4]>,
    windows: &[Window],
) -> Option<[f64; 2]> {
    let inside = |rect: Rect, p: [f64; 2]| {
        rect.valid()
            && p.iter().all(|v| v.is_finite())
            && p[0] >= rect.x
            && p[0] < rect.x + rect.width
            && p[1] >= rect.y
            && p[1] < rect.y + rect.height
    };
    let frame = frame
        .map(|[x, y, width, height]| Rect {
            x,
            y,
            width,
            height,
        })
        .filter(|frame| frame.valid());
    for (index, target) in windows.iter().enumerate() {
        if target.pid != Some(pid)
            || target.layer != Some(0)
            || target.alpha.is_none_or(|v| v <= 0.0 || !v.is_finite())
        {
            continue;
        }
        let bounds = target.bounds?;
        let p = match (point, frame) {
            (Some(p), _) => p,
            (None, Some(frame)) => match frame.intersection(bounds) {
                Some(seen) => [seen.x + seen.width / 2.0, seen.y + seen.height / 2.0],
                None => continue,
            },
            (None, None) => {
                let title = if bounds.height > 2.0 * TITLE_BAR {
                    TITLE_BAR
                } else {
                    0.0
                };
                [
                    bounds.x + bounds.width / 2.0,
                    bounds.y + title + (bounds.height - title) / 2.0,
                ]
            }
        };
        if !inside(bounds, p) {
            continue;
        }
        for above in &windows[..index] {
            if above.pid == Some(pid) || above.alpha == Some(0.0) {
                continue;
            }
            let layer = above.layer?;
            if layer == 0 && inside(above.bounds?, p) {
                return None;
            }
        }
        return Some(p);
    }
    None
}

/// The deciding rule, suitable for a text-free image journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VisibilityRule {
    MissingData,
    TargetAbsent,
    TargetTransparent,
    OutsideDisplays,
    OverlappingWindow,
    HigherLayerUnionCoverage,
    NoLayerZeroOverlap,
}

/// Remove a rectangle from a region represented by disjoint rectangles.
fn subtract(remaining: Vec<Rect>, cover: Rect) -> Vec<Rect> {
    remaining
        .into_iter()
        .flat_map(|rect| {
            let Some(overlap) = rect.intersection(cover) else {
                return vec![rect];
            };
            [
                Rect {
                    height: overlap.y - rect.y,
                    ..rect
                },
                Rect {
                    y: overlap.y + overlap.height,
                    height: rect.y + rect.height - overlap.y - overlap.height,
                    ..rect
                },
                Rect {
                    y: overlap.y,
                    width: overlap.x - rect.x,
                    height: overlap.height,
                    ..rect
                },
                Rect {
                    x: overlap.x + overlap.width,
                    y: overlap.y,
                    width: rect.x + rect.width - overlap.x - overlap.width,
                    height: overlap.height,
                },
            ]
            .into_iter()
            .filter(|r| r.valid())
            .collect()
        })
        .collect()
}

/// Ordered front to back, including windows from the target's own process.
pub(crate) fn visibility_from_windows(
    pid: u32,
    id: u32,
    windows: &[Window],
    displays: &[Rect],
) -> (WindowVisibility, VisibilityRule) {
    use VisibilityRule::*;
    use WindowVisibility::*;
    let Some(index) = windows.iter().position(|window| window.id == Some(id)) else {
        return (Covered, TargetAbsent);
    };
    let window = &windows[index];
    if window.pid != Some(pid) {
        return (Unknown, MissingData);
    }
    let Some(bounds) = window.bounds.filter(|rect| rect.valid()) else {
        return (Unknown, MissingData);
    };
    if window.alpha.is_none_or(|alpha| !alpha.is_finite()) {
        return (Unknown, MissingData);
    }
    if window.alpha == Some(0.0) {
        return (Covered, TargetTransparent);
    }
    if window.layer.is_none() {
        return (Unknown, MissingData);
    }
    if displays.is_empty() || displays.iter().any(|rect| !rect.valid()) {
        return (Unknown, MissingData);
    }
    // Subtract the union of displays: a window spanning adjacent displays is
    // visible, but a strip off screen or in a gap between displays is not.
    let mut remaining = vec![bounds];
    for display in displays {
        remaining = subtract(remaining, *display);
    }
    if !remaining.is_empty() {
        return (Covered, OutsideDisplays);
    }
    let mut above_windows = Vec::new();
    for above in &windows[..index] {
        if above.cursor_picture {
            continue;
        }
        if above.alpha == Some(0.0) {
            continue;
        }
        let Some(other) = above.bounds.filter(|rect| rect.valid()) else {
            return (Unknown, MissingData);
        };
        let Some(other_layer) = above.layer else {
            return (Unknown, MissingData);
        };
        if above.alpha.is_none_or(|alpha| !alpha.is_finite()) {
            return (Unknown, MissingData);
        }
        above_windows.push((other, other_layer));
    }
    for (other, layer) in &above_windows {
        if *layer == 0 && bounds.intersection(*other).is_some() {
            return (Covered, OverlappingWindow);
        }
    }
    // Occlusion, not global frontmost status, determines whether a normal window
    // keeps drawing. Floating bars only withhold its image when their union
    // covers the entire frame, even if another display has a normal window above.
    let mut remaining = vec![bounds];
    for (other, layer) in above_windows {
        if layer != 0 {
            remaining = subtract(remaining, other);
        }
    }
    if remaining.is_empty() {
        return (Covered, HigherLayerUnionCoverage);
    }
    (FullyVisible, NoLayerZeroOverlap)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_picture_cannot_cover_even_a_tiny_target_window() {
        let target = || {
            window(
                1,
                Some(Rect {
                    x: 20.0,
                    y: 20.0,
                    width: 60.0,
                    height: 24.0,
                }),
            )
        };
        let picture = Window {
            cursor_picture: true,
            pid: Some(99),
            ..layered(
                2,
                3,
                Rect {
                    x: 20.0,
                    y: 20.0,
                    width: 120.0,
                    height: 48.0,
                },
            )
        };
        assert_eq!(
            visibility_from_windows(7, 1, &[picture, target()], &[rect(0.0, 1000.0)]),
            visibility_from_windows(7, 1, &[target()], &[rect(0.0, 1000.0)])
        );
    }

    #[test]
    fn cursor_floating_picture_does_not_change_frontmost_or_coverage() {
        let target = || window(1, Some(rect(0.0, 1000.0)));
        let overlay = Window {
            pid: Some(99),
            ..layered(
                2,
                3,
                Rect {
                    x: 20.0,
                    y: 20.0,
                    width: 120.0,
                    height: 48.0,
                },
            )
        };
        let before = [target()];
        let after = [overlay, target()];
        assert_eq!(frontmost_from_windows(&before), Some(7));
        assert_eq!(frontmost_from_windows(&after), Some(7));
        assert_eq!(
            visibility_from_windows(7, 1, &before, &[rect(0.0, 1000.0)]),
            visibility_from_windows(7, 1, &after, &[rect(0.0, 1000.0)])
        );
    }

    #[test]
    fn cursor_visible_point_ignores_floating_but_not_other_normal_windows() {
        let target = || window(1, Some(rect(0.0, 1000.0)));
        let cover = |layer| Window {
            pid: Some(99),
            ..layered(2, layer, rect(20.0, 120.0))
        };
        assert_eq!(
            cursor_point_from_windows(7, Some([40.0, 40.0]), None, &[cover(3), target()]),
            Some([40.0, 40.0])
        );
        assert_eq!(
            cursor_point_from_windows(7, Some([40.0, 40.0]), None, &[cover(0), target()]),
            None
        );
        assert_eq!(
            cursor_point_from_windows(7, Some([1200.0, 40.0]), None, &[target()]),
            None
        );
    }

    #[test]
    fn cursor_without_an_element_appears_mid_content_below_the_title_bar() {
        // A 1000x100 window: the title bar takes the top 28 points, and the
        // picture appears in the middle of what is left, not at the corner
        // where the window buttons are.
        let target = window(1, Some(rect(0.0, 1000.0)));
        assert_eq!(
            cursor_point_from_windows(7, None, None, &[target]),
            Some([500.0, 64.0])
        );
        let short = window(
            1,
            Some(Rect {
                x: 10.0,
                y: 10.0,
                width: 40.0,
                height: 40.0,
            }),
        );
        assert_eq!(
            cursor_point_from_windows(7, None, None, &[short]),
            Some([30.0, 30.0])
        );
    }

    #[test]
    fn cursor_element_point_is_the_centre_of_the_frame_s_visible_part() {
        let target = || window(1, Some(rect(0.0, 1000.0)));
        assert_eq!(
            cursor_point_from_windows(7, None, Some([100.0, 20.0, 200.0, 40.0]), &[target()]),
            Some([200.0, 40.0])
        );
        // Half scrolled out of the bottom of the window: the centre of what is
        // still visible, not the frame's own centre outside the window.
        assert_eq!(
            cursor_point_from_windows(7, None, Some([100.0, 80.0, 200.0, 60.0]), &[target()]),
            Some([200.0, 90.0])
        );
        // An exact point wins over the frame.
        assert_eq!(
            cursor_point_from_windows(
                7,
                Some([110.0, 30.0]),
                Some([100.0, 20.0, 200.0, 40.0]),
                &[target()]
            ),
            Some([110.0, 30.0])
        );
        assert_eq!(
            cursor_point_from_windows(7, None, Some([2000.0, 20.0, 50.0, 40.0]), &[target()]),
            None
        );
    }

    fn rect(x: f64, width: f64) -> Rect {
        Rect {
            x,
            y: 0.0,
            width,
            height: 100.0,
        }
    }
    fn window(id: u32, bounds: Option<Rect>) -> Window {
        Window {
            cursor_picture: false,
            id: Some(id),
            pid: Some(7),
            bounds,
            alpha: Some(1.0),
            layer: Some(0),
        }
    }

    #[test]
    fn visibility_uses_order_overlap_and_display_coverage() {
        let target = || window(1, Some(rect(0.0, 100.0)));
        assert_eq!(
            visibility_from_windows(7, 1, &[target()], &[rect(0.0, 100.0)]),
            (
                WindowVisibility::FullyVisible,
                VisibilityRule::NoLayerZeroOverlap
            )
        );
        assert_eq!(
            visibility_from_windows(
                7,
                1,
                &[window(2, Some(rect(99.0, 100.0))), target()],
                &[rect(0.0, 200.0)]
            ),
            (WindowVisibility::Covered, VisibilityRule::OverlappingWindow)
        );
        assert_eq!(
            visibility_from_windows(7, 1, &[target(), window(2, None)], &[rect(0.0, 100.0)]),
            (
                WindowVisibility::FullyVisible,
                VisibilityRule::NoLayerZeroOverlap
            )
        );
        assert_eq!(
            visibility_from_windows(7, 1, &[window(2, None), target()], &[rect(0.0, 100.0)]),
            (WindowVisibility::Unknown, VisibilityRule::MissingData)
        );
        assert_eq!(
            visibility_from_windows(7, 1, &[target()], &[rect(1.0, 100.0)]),
            (WindowVisibility::Covered, VisibilityRule::OutsideDisplays)
        );
        assert_eq!(
            visibility_from_windows(7, 1, &[], &[rect(0.0, 100.0)]),
            (WindowVisibility::Covered, VisibilityRule::TargetAbsent)
        );
        assert_eq!(
            visibility_from_windows(7, 1, &[target()], &[]),
            (WindowVisibility::Unknown, VisibilityRule::MissingData)
        );
        assert_eq!(
            visibility_from_windows(7, 1, &[target()], &[rect(0.0, 50.0), rect(50.0, 50.0)]),
            (
                WindowVisibility::FullyVisible,
                VisibilityRule::NoLayerZeroOverlap
            )
        );
        assert_eq!(
            visibility_from_windows(
                7,
                1,
                &[window(2, Some(rect(100.0, 50.0))), target()],
                &[rect(0.0, 100.0)]
            ),
            (
                WindowVisibility::FullyVisible,
                VisibilityRule::NoLayerZeroOverlap
            )
        );
    }

    fn layered(id: u32, layer: i64, bounds: Rect) -> Window {
        Window {
            layer: Some(layer),
            ..window(id, Some(bounds))
        }
    }

    #[test]
    fn fence_sidebar_bars_leave_frontmost_frame_visible() {
        let display = Rect {
            x: -1728.0,
            y: 0.0,
            width: 1728.0,
            height: 1440.0,
        };
        let target = Window {
            pid: Some(753),
            ..layered(
                69,
                0,
                Rect {
                    x: -1728.0,
                    y: 355.0,
                    width: 1728.0,
                    height: 1085.0,
                },
            )
        };
        let menu = layered(
            2,
            24,
            Rect {
                x: 0.0,
                y: 0.0,
                width: 1728.0,
                height: 30.0,
            },
        );
        let bar2 = layered(
            3,
            2,
            Rect {
                x: -1728.0,
                y: 1387.0,
                width: 1728.0,
                height: 53.0,
            },
        );
        let bar3 = layered(
            4,
            3,
            Rect {
                x: -1728.0,
                y: 1373.0,
                width: 1728.0,
                height: 67.0,
            },
        );
        assert_eq!(
            visibility_from_windows(
                753,
                69,
                &[menu, bar3, bar2, target],
                &[display, rect(0.0, 1728.0)]
            ),
            (
                WindowVisibility::FullyVisible,
                VisibilityRule::NoLayerZeroOverlap
            )
        );
    }

    #[test]
    fn fence_other_process_layer_zero_overlap_covers() {
        let above = Window {
            pid: Some(8),
            ..layered(2, 0, rect(99.0, 100.0))
        };
        assert_eq!(
            visibility_from_windows(
                7,
                1,
                &[above, window(1, Some(rect(0.0, 100.0)))],
                &[rect(0.0, 200.0)]
            ),
            (WindowVisibility::Covered, VisibilityRule::OverlappingWindow)
        );
    }

    #[test]
    fn fence_other_display_layer_zero_with_floating_bar_stays_visible() {
        assert_eq!(
            visibility_from_windows(
                7,
                1,
                &[
                    layered(2, 0, rect(100.0, 100.0)),
                    layered(3, 3, rect(99.0, 100.0)),
                    window(1, Some(rect(0.0, 100.0))),
                ],
                &[rect(0.0, 100.0), rect(100.0, 100.0)]
            ),
            (
                WindowVisibility::FullyVisible,
                VisibilityRule::NoLayerZeroOverlap
            )
        );
    }

    #[test]
    fn fence_layer_zero_overlap_with_floating_bar_covers() {
        for pid in [7, 8] {
            let normal = Window {
                pid: Some(pid),
                ..layered(2, 0, rect(99.0, 100.0))
            };
            assert_eq!(
                visibility_from_windows(
                    7,
                    1,
                    &[
                        layered(3, 3, rect(99.0, 100.0)),
                        normal,
                        window(1, Some(rect(0.0, 100.0))),
                    ],
                    &[rect(0.0, 200.0)]
                ),
                (WindowVisibility::Covered, VisibilityRule::OverlappingWindow)
            );
        }
    }

    #[test]
    fn fence_higher_layer_union_full_frame_covers() {
        for overlays in [
            vec![layered(2, 3, rect(0.0, 100.0))],
            vec![
                layered(2, 2, rect(0.0, 50.0)),
                layered(3, 3, rect(50.0, 50.0)),
            ],
        ] {
            let mut windows = overlays;
            windows.push(window(1, Some(rect(0.0, 100.0))));
            assert_eq!(
                visibility_from_windows(7, 1, &windows, &[rect(0.0, 100.0)]),
                (
                    WindowVisibility::Covered,
                    VisibilityRule::HigherLayerUnionCoverage
                )
            );
        }
    }

    #[test]
    fn fence_missing_overlay_data_is_unknown() {
        let overlay = || layered(2, 3, rect(99.0, 100.0));
        for above in [
            Window {
                layer: None,
                ..overlay()
            },
            Window {
                bounds: None,
                ..overlay()
            },
            Window {
                bounds: Some(rect(0.0, f64::NAN)),
                ..overlay()
            },
            Window {
                alpha: Some(f64::NAN),
                ..overlay()
            },
            Window {
                alpha: Some(f64::INFINITY),
                ..overlay()
            },
            Window {
                alpha: None,
                ..overlay()
            },
        ] {
            assert_eq!(
                visibility_from_windows(
                    7,
                    1,
                    &[above, window(1, Some(rect(0.0, 100.0)))],
                    &[rect(0.0, 100.0)]
                ),
                (WindowVisibility::Unknown, VisibilityRule::MissingData)
            );
        }
    }

    #[test]
    fn transparent_overlays_ignore_missing_data_and_layer_zero() {
        let above = Window {
            alpha: Some(0.0),
            layer: None,
            ..window(2, None)
        };
        assert_eq!(
            visibility_from_windows(
                7,
                1,
                &[above, window(1, Some(rect(0.0, 100.0)))],
                &[rect(0.0, 100.0)]
            ),
            (
                WindowVisibility::FullyVisible,
                VisibilityRule::NoLayerZeroOverlap
            )
        );
        let above = Window {
            alpha: Some(0.0),
            ..window(2, Some(rect(0.0, 100.0)))
        };
        assert_eq!(
            visibility_from_windows(
                7,
                1,
                &[above, window(1, Some(rect(0.0, 100.0)))],
                &[rect(0.0, 100.0)]
            ),
            (
                WindowVisibility::FullyVisible,
                VisibilityRule::NoLayerZeroOverlap
            )
        );
    }
}
