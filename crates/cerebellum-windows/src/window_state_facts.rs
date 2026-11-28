//! Window geometry, stacking, input desktop, and thread-window readings.

use std::{collections::HashSet, io, mem::size_of, ptr::null_mut};
use windows_sys::Win32::{
    Foundation::{GetLastError, SetLastError, HWND, RECT},
    Graphics::Dwm::{DwmGetWindowAttribute, DWMWA_CLOAKED, DWMWA_EXTENDED_FRAME_BOUNDS},
    System::StationsAndDesktops::{
        CloseDesktop, GetUserObjectInformationW, OpenInputDesktop, DESKTOP_READOBJECTS, HDESK,
        UOI_NAME,
    },
    UI::WindowsAndMessaging::{
        GetAncestor, GetForegroundWindow, GetGUIThreadInfo, GetTopWindow, GetWindow,
        GetWindowLongW, GetWindowThreadProcessId, SetForegroundWindow, GA_ROOT, GUITHREADINFO,
        GWL_EXSTYLE, GW_HWNDNEXT,
    },
};

use crate::UiaRectangle;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowStateFacts {
    pub cloaked: bool,
    pub bounds: UiaRectangle,
    pub extended_style: u32,
}

pub fn window_owner(number: u32) -> io::Result<(u32, u32)> {
    let mut pid = 0;
    // SAFETY: The HWND is an opaque value and the process ID output is writable.
    let tid = unsafe { GetWindowThreadProcessId(number as usize as HWND, &mut pid) };
    if tid == 0 || pid == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((pid, tid))
}

pub fn window_state_facts(number: u32) -> io::Result<WindowStateFacts> {
    let hwnd = number as usize as HWND;
    let mut cloak = 0_u32;
    let mut rect = RECT::default();
    // SAFETY: Both buffers match the requested DWM attribute's documented type.
    unsafe {
        let hr = DwmGetWindowAttribute(
            hwnd,
            DWMWA_CLOAKED as u32,
            (&mut cloak as *mut u32).cast(),
            4,
        );
        if hr < 0 {
            return Err(io::Error::other(format!("DWM cloak HRESULT {hr:#x}")));
        }
        let hr = DwmGetWindowAttribute(
            hwnd,
            DWMWA_EXTENDED_FRAME_BOUNDS as u32,
            (&mut rect as *mut RECT).cast(),
            size_of::<RECT>() as u32,
        );
        if hr < 0 {
            return Err(io::Error::other(format!("DWM bounds HRESULT {hr:#x}")));
        }
        // A zero style is a valid response; a nonzero last error distinguishes failure.
        SetLastError(0);
        let style = GetWindowLongW(hwnd, GWL_EXSTYLE);
        if style == 0 && GetLastError() != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(WindowStateFacts {
            cloaked: cloak != 0,
            bounds: UiaRectangle {
                left: rect.left,
                top: rect.top,
                right: rect.right,
                bottom: rect.bottom,
            },
            extended_style: style as u32,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuiThreadWindows {
    pub active: Option<u32>,
    pub focus: Option<u32>,
}

fn number(hwnd: HWND) -> Option<u32> {
    (!hwnd.is_null()).then_some(hwnd as usize as u32)
}

pub fn gui_thread_windows(tid: u32) -> io::Result<GuiThreadWindows> {
    if tid == 0 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut info = GUITHREADINFO {
        cbSize: size_of::<GUITHREADINFO>() as u32,
        ..Default::default()
    };
    // SAFETY: The structure's size is set and the output remains writable.
    if unsafe { GetGUIThreadInfo(tid, &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(GuiThreadWindows {
        active: number(info.hwndActive),
        focus: number(info.hwndFocus),
    })
}

pub fn foreground_window_number() -> Option<u32> {
    // SAFETY: This call takes no input and returns a borrowed HWND value.
    number(unsafe { GetForegroundWindow() })
}

/// Return the result of the single Win32 foreground request. The caller must
/// independently read which window is in the foreground.
pub fn set_foreground_window(number: u32) -> bool {
    // SAFETY: The HWND is an opaque value; the function borrows no memory.
    unsafe { SetForegroundWindow(number as usize as HWND) != 0 }
}

pub fn root_window_number(window: u32) -> Option<u32> {
    // SAFETY: The HWND is an opaque value; GetAncestor does not transfer ownership.
    number(unsafe { GetAncestor(window as usize as HWND, GA_ROOT) })
}

pub fn desktop_z_order() -> io::Result<Vec<u32>> {
    // SAFETY: A null HWND asks for the topmost top-level window.
    let mut hwnd = unsafe { GetTopWindow(null_mut()) };
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    while let Some(id) = number(hwnd) {
        if !seen.insert(id) || result.len() == 16_384 {
            return Err(io::Error::other("window stack did not terminate"));
        }
        result.push(id);
        // SAFETY: HWND is an opaque value. No borrowed memory is dereferenced.
        hwnd = unsafe { GetWindow(hwnd, GW_HWNDNEXT) };
    }
    Ok(result)
}

struct Desktop(HDESK);

impl Drop for Desktop {
    fn drop(&mut self) {
        // SAFETY: This wrapper owns the handle returned by OpenInputDesktop.
        unsafe { CloseDesktop(self.0) };
    }
}

pub fn input_desktop_name() -> io::Result<String> {
    // SAFETY: No borrowed pointers are passed; a successful open transfers ownership.
    let desktop = unsafe { OpenInputDesktop(0, 0, DESKTOP_READOBJECTS) };
    if desktop.is_null() {
        return Err(io::Error::last_os_error());
    }
    let desktop = Desktop(desktop);
    let mut name = [0_u16; 256];
    let mut bytes = 0;
    // SAFETY: The buffer size is given in bytes and the size output is writable.
    if unsafe {
        GetUserObjectInformationW(
            desktop.0,
            UOI_NAME,
            name.as_mut_ptr().cast(),
            size_of::<[u16; 256]>() as u32,
            &mut bytes,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let end = name
        .iter()
        .position(|unit| *unit == 0)
        .ok_or(io::ErrorKind::InvalidData)?;
    String::from_utf16(&name[..end]).map_err(|_| io::ErrorKind::InvalidData.into())
}
