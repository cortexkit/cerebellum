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
    pub id: Option<u32>,
    pub pid: Option<u32>,
    pub bounds: Option<Rect>,
    pub alpha: Option<f64>,
}

/// Ordered front to back, including windows from the target's own process.
pub(crate) fn visibility_from_windows(
    pid: u32,
    id: u32,
    windows: &[Window],
    displays: &[Rect],
) -> WindowVisibility {
    let Some(index) = windows.iter().position(|window| window.id == Some(id)) else {
        return WindowVisibility::Covered;
    };
    let window = &windows[index];
    if window.pid != Some(pid) {
        return WindowVisibility::Unknown;
    }
    let Some(bounds) = window.bounds.filter(|rect| rect.valid()) else {
        return WindowVisibility::Unknown;
    };
    if window.alpha.is_none_or(|alpha| !alpha.is_finite()) {
        return WindowVisibility::Unknown;
    }
    if window.alpha == Some(0.0) {
        return WindowVisibility::Covered;
    }
    if displays.is_empty() || displays.iter().any(|rect| !rect.valid()) {
        return WindowVisibility::Unknown;
    }
    // Subtract the union of displays: a window spanning adjacent displays is
    // visible, but a strip off screen or in a gap between displays is not.
    let mut remaining = vec![bounds];
    for display in displays {
        remaining = remaining
            .into_iter()
            .flat_map(|rect| {
                let Some(overlap) = rect.intersection(*display) else {
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
            .collect();
    }
    if !remaining.is_empty() {
        return WindowVisibility::Covered;
    }
    for above in &windows[..index] {
        if above.alpha == Some(0.0) {
            continue;
        }
        let Some(other) = above.bounds.filter(|rect| rect.valid()) else {
            return WindowVisibility::Unknown;
        };
        if bounds.intersection(other).is_some() {
            return WindowVisibility::Covered;
        }
    }
    WindowVisibility::FullyVisible
}

#[cfg(test)]
mod tests {
    use super::*;

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
            id: Some(id),
            pid: Some(7),
            bounds,
            alpha: Some(1.0),
        }
    }

    #[test]
    fn visibility_uses_order_overlap_and_display_coverage() {
        let target = || window(1, Some(rect(0.0, 100.0)));
        assert_eq!(
            visibility_from_windows(7, 1, &[target()], &[rect(0.0, 100.0)]),
            WindowVisibility::FullyVisible
        );
        assert_eq!(
            visibility_from_windows(
                7,
                1,
                &[window(2, Some(rect(99.0, 100.0))), target()],
                &[rect(0.0, 200.0)]
            ),
            WindowVisibility::Covered
        );
        assert_eq!(
            visibility_from_windows(7, 1, &[target(), window(2, None)], &[rect(0.0, 100.0)]),
            WindowVisibility::FullyVisible
        );
        assert_eq!(
            visibility_from_windows(7, 1, &[window(2, None), target()], &[rect(0.0, 100.0)]),
            WindowVisibility::Unknown
        );
        assert_eq!(
            visibility_from_windows(7, 1, &[target()], &[rect(1.0, 100.0)]),
            WindowVisibility::Covered
        );
        assert_eq!(
            visibility_from_windows(7, 1, &[], &[rect(0.0, 100.0)]),
            WindowVisibility::Covered
        );
        assert_eq!(
            visibility_from_windows(7, 1, &[target()], &[]),
            WindowVisibility::Unknown
        );
        assert_eq!(
            visibility_from_windows(7, 1, &[target()], &[rect(0.0, 50.0), rect(50.0, 50.0)]),
            WindowVisibility::FullyVisible
        );
        assert_eq!(
            visibility_from_windows(
                7,
                1,
                &[window(2, Some(rect(100.0, 50.0))), target()],
                &[rect(0.0, 100.0)]
            ),
            WindowVisibility::FullyVisible
        );
    }
}
