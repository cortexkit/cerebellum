use super::{ReadError, ReadResult};
use crate::platform::windows::identity::{frame_proof, FrameProof};
use cerebellum_windows::{
    desktop_window_numbers, gui_thread_windows, input_desktop_name, retain_image_process,
    window_identity_facts, window_state_facts, GuiThreadWindows, ProcessHandleError,
    ProcessStartTime, RetainedProcessHandle, SessionProvenance, UiaRectangle, WindowIdentityFacts,
    WindowStateFacts,
};
use std::{collections::BTreeSet, time::Instant};

const WS_EX_TOOLWINDOW: u32 = 0x0000_0080;
const WS_EX_NOACTIVATE: u32 = 0x0800_0000;

pub(in crate::platform::windows) fn is_default_desktop() -> bool {
    require_default_desktop().is_ok()
}

pub(super) fn require_default_desktop() -> ReadResult<()> {
    desktop_admission(
        cerebellum_windows::current_session_provenance(),
        input_desktop_name,
    )
}

fn desktop_admission(
    session: SessionProvenance,
    name: impl FnOnce() -> std::io::Result<String>,
) -> ReadResult<()> {
    if matches!(session, SessionProvenance::Console { .. })
        && name().is_ok_and(|name| name == "Default")
    {
        Ok(())
    } else {
        Err(ReadError::NotInspectable)
    }
}

pub(in crate::platform::windows) fn retain(
    pid: u32,
    generation: u64,
) -> ReadResult<RetainedProcessHandle> {
    require_default_desktop()?;
    let process = retain_image_process(pid).map_err(|err| match err {
        ProcessHandleError::NoSuchProcess => ReadError::Gone,
        ProcessHandleError::AccessDenied => ReadError::Permission,
        ProcessHandleError::Unclassified(_) => ReadError::Unreadable,
    })?;
    current(&process, generation)?;
    // SECURITY_MANDATORY_MEDIUM_RID. Unknown token evidence never passes.
    if !process
        .token_facts()
        .is_some_and(|token| !token.elevated && token.integrity_rid <= 0x2000)
    {
        return Err(ReadError::NotInspectable);
    }
    Ok(process)
}

pub(in crate::platform::windows) fn current(
    process: &RetainedProcessHandle,
    expected: u64,
) -> ReadResult<()> {
    if !process.process_wait_pending() {
        return Err(ReadError::Gone);
    }
    match process.creation_time() {
        ProcessStartTime::Started(generation) if generation == expected => Ok(()),
        ProcessStartTime::Started(_) => Err(ReadError::Replaced),
        ProcessStartTime::NoSuchProcess => Err(ReadError::Gone),
        ProcessStartTime::AccessDenied => Err(ReadError::Permission),
        ProcessStartTime::Unclassified(_) => Err(ReadError::Unreadable),
    }
}

fn ordinary_class(class: &str) -> bool {
    !matches!(
        class.to_ascii_lowercase().as_str(),
        "tooltips_class32" | "ime" | "msctfime ui" | "systooltips_class32"
    )
}

fn within_bounds(rect: UiaRectangle) -> bool {
    rect.left < rect.right && rect.top < rect.bottom
}

fn state_is_eligible(state: WindowStateFacts) -> bool {
    !state.cloaked
        && within_bounds(state.bounds)
        && state.extended_style & (WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE) == 0
}

pub(in crate::platform::windows) fn eligible_state(
    root: &WindowIdentityFacts,
) -> std::io::Result<Option<WindowStateFacts>> {
    if !root.visible_style || !ordinary_class(&root.class) {
        return Ok(None);
    }
    let state = window_state_facts(root.number)?;
    Ok(state_is_eligible(state).then_some(state))
}

#[derive(Clone, Debug)]
pub(in crate::platform::windows) struct BoundWindow {
    pub root: WindowIdentityFacts,
    pub state: WindowStateFacts,
    pub proof: FrameProof,
}

impl BoundWindow {
    pub fn content(&self) -> u32 {
        self.proof.content_window_and_thread().0
    }
    fn thread(&self) -> u32 {
        self.proof.content_window_and_thread().1
    }
}

pub(in crate::platform::windows) fn bound_window(
    process: &RetainedProcessHandle,
    pid: u32,
    number: u32,
) -> ReadResult<Option<BoundWindow>> {
    let root = window_identity_facts(number).map_err(|_| ReadError::Unreadable)?;
    if root.pid != pid && root.class != "ApplicationFrameWindow" {
        return Ok(None);
    }
    let Some(state) = eligible_state(&root).map_err(|_| ReadError::Unreadable)? else {
        return Ok(None);
    };
    let Some(proof) = frame_proof(process, pid, number).map_err(|_| ReadError::Unreadable)? else {
        return Ok(None);
    };
    let now = window_identity_facts(number).map_err(|_| ReadError::Unreadable)?;
    if (now.pid, now.tid, now.class, now.visible_style)
        != (root.pid, root.tid, root.class.clone(), root.visible_style)
    {
        return Err(ReadError::Unreadable);
    }
    Ok(Some(BoundWindow { root, state, proof }))
}

pub(super) fn same_binding(
    process: &RetainedProcessHandle,
    pid: u32,
    window: &BoundWindow,
) -> ReadResult<()> {
    if !is_default_desktop() {
        return Err(ReadError::NotInspectable);
    }
    match bound_window(process, pid, window.root.number)? {
        Some(now) if now.proof == window.proof => Ok(()),
        _ => Err(ReadError::Gone),
    }
}

pub(in crate::platform::windows) struct Windows {
    pub eligible: Vec<BoundWindow>,
    pub unreadable: usize,
}

pub(in crate::platform::windows) fn windows(
    process: &RetainedProcessHandle,
    pid: u32,
    end: Instant,
) -> ReadResult<Windows> {
    let mut result = Windows {
        eligible: Vec::new(),
        unreadable: 0,
    };
    for number in desktop_window_numbers().map_err(|_| ReadError::Unreadable)? {
        if Instant::now() >= end {
            return Err(ReadError::Deadline);
        }
        match bound_window(process, pid, number) {
            Ok(Some(window)) => result.eligible.push(window),
            Ok(None) => (),
            Err(_) => result.unreadable += 1,
        }
    }
    Ok(result)
}

pub(in crate::platform::windows) fn active_window(
    windows: &Windows,
) -> ReadResult<Option<(&BoundWindow, GuiThreadWindows)>> {
    if windows.unreadable != 0 {
        return Err(ReadError::Unreadable);
    }
    let bindings: Vec<_> = windows
        .eligible
        .iter()
        .map(|window| (window.root.number, window.content(), window.thread()))
        .collect();
    Ok(active_binding(&bindings, |tid| {
        gui_thread_windows(tid).map_err(|_| ReadError::Unreadable)
    })?
    .map(|(index, info)| (&windows.eligible[index], info)))
}

pub(in crate::platform::windows) fn image_window(
    windows: &Windows,
) -> ReadResult<Option<&BoundWindow>> {
    if windows.unreadable != 0 {
        return Err(ReadError::Unreadable);
    }
    let mut active = None;
    let threads: BTreeSet<_> = windows.eligible.iter().map(BoundWindow::thread).collect();
    for tid in threads {
        let info = gui_thread_windows(tid).map_err(|_| ReadError::Unreadable)?;
        if let Some(window) = windows.eligible.iter().find(|window| {
            window.thread() == tid
                && (info.active == Some(window.root.number)
                    || info.active == Some(window.content()))
        }) {
            if active.replace(window).is_some() {
                return Err(ReadError::Unreadable);
            }
        }
    }
    if active.is_some() || windows.eligible.is_empty() {
        return Ok(active);
    }
    let stack = cerebellum_windows::desktop_z_order().map_err(|_| ReadError::Unreadable)?;
    stack
        .into_iter()
        .find_map(|number| {
            windows
                .eligible
                .iter()
                .find(|window| window.root.number == number)
        })
        .map(Some)
        .ok_or(ReadError::Unreadable)
}

fn active_binding(
    windows: &[(u32, u32, u32)],
    mut query: impl FnMut(u32) -> ReadResult<GuiThreadWindows>,
) -> ReadResult<Option<(usize, GuiThreadWindows)>> {
    let threads: BTreeSet<_> = windows.iter().map(|&(_, _, thread)| thread).collect();
    let mut active = None;
    for tid in threads {
        let info = query(tid)?;
        let Some(hwnd) = info.active else { continue };
        let window = windows
            .iter()
            .position(|&(root, content, thread)| thread == tid && (root == hwnd || content == hwnd))
            .ok_or(ReadError::Unreadable)?;
        if active.replace((window, info)).is_some() {
            return Err(ReadError::Unreadable);
        }
    }
    Ok(active)
}

pub(super) fn contains(rect: UiaRectangle, point: (f64, f64)) -> bool {
    let (x, y) = point;
    x >= f64::from(rect.left)
        && x < f64::from(rect.right)
        && y >= f64::from(rect.top)
        && y < f64::from(rect.bottom)
}

pub(in crate::platform::windows) fn frame(rect: UiaRectangle) -> [f64; 4] {
    [
        f64::from(rect.left),
        f64::from(rect.top),
        f64::from(rect.right) - f64::from(rect.left),
        f64::from(rect.bottom) - f64::from(rect.top),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_input_desktop_refuses_before_a_window_read() {
        let console = SessionProvenance::Console { session_id: 1 };
        assert_eq!(desktop_admission(console, || Ok("Default".into())), Ok(()));
        assert_eq!(
            desktop_admission(console, || Ok("Winlogon".into())),
            Err(ReadError::NotInspectable)
        );
        assert_eq!(
            desktop_admission(console, || Err(std::io::ErrorKind::PermissionDenied.into())),
            Err(ReadError::NotInspectable)
        );
        let service = SessionProvenance::OtherSession {
            session_id: 0,
            console_session_id: 1,
        };
        assert_eq!(
            desktop_admission(service, || panic!(
                "a non-console process must not open the desktop"
            )),
            Err(ReadError::NotInspectable)
        );
    }

    #[test]
    fn active_window_requires_exactly_one_eligible_thread_binding() {
        let windows = [(10, 10, 100), (20, 21, 200), (22, 22, 200)];
        let inactive = GuiThreadWindows {
            active: None,
            focus: None,
        };
        let second = GuiThreadWindows {
            active: Some(20),
            focus: Some(201),
        };
        let first = GuiThreadWindows {
            active: Some(10),
            focus: Some(101),
        };
        let mut calls = Vec::new();
        assert_eq!(
            active_binding(&windows, |tid| {
                calls.push(tid);
                Ok(if tid == 200 { second } else { inactive })
            }),
            Ok(Some((1, second)))
        );
        assert_eq!(calls, [100, 200]);
        assert_eq!(active_binding(&windows, |_| Ok(inactive)), Ok(None));
        assert_eq!(
            active_binding(&windows, |tid| Ok(if tid == 100 { first } else { second })),
            Err(ReadError::Unreadable)
        );
        assert_eq!(
            active_binding(&windows, |tid| if tid == 100 {
                Ok(first)
            } else {
                Err(ReadError::Unreadable)
            }),
            Err(ReadError::Unreadable)
        );
        assert_eq!(
            active_binding(&windows, |_| Ok(first)),
            Err(ReadError::Unreadable)
        );
    }

    #[test]
    fn eligibility_requires_nonempty_uncloaked_ordinary_bounds() {
        let plain = WindowStateFacts {
            cloaked: false,
            bounds: UiaRectangle {
                left: -50,
                top: -30,
                right: 10,
                bottom: 30,
            },
            extended_style: 0,
        };
        assert!(state_is_eligible(plain));
        assert!(!state_is_eligible(WindowStateFacts {
            cloaked: true,
            ..plain
        }));
        for style in [WS_EX_TOOLWINDOW, WS_EX_NOACTIVATE] {
            assert!(!state_is_eligible(WindowStateFacts {
                extended_style: style,
                ..plain
            }));
        }
        assert!(!state_is_eligible(WindowStateFacts {
            bounds: UiaRectangle {
                right: -50,
                ..plain.bounds
            },
            ..plain
        }));
        assert!(!ordinary_class("tooltips_class32"));
        assert!(!ordinary_class("MSCTFIME UI"));
        assert!(ordinary_class("#32770"));
    }
}
