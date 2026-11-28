//! Cursor and window-manager readings for the physical desktop.

use std::{io, mem::size_of};
use windows_sys::Win32::{
    Foundation::POINT,
    UI::WindowsAndMessaging::{
        GetCursorPos, GetGUIThreadInfo, GetSystemMetrics, SystemParametersInfoW, WindowFromPoint,
        GUITHREADINFO, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN,
        SM_YVIRTUALSCREEN, SPI_GETMOUSEWHEELROUTING,
    },
};

pub fn cursor_position() -> io::Result<(i32, i32)> {
    let mut point = POINT::default();
    // SAFETY: GetCursorPos writes one initialized POINT through the supplied pointer.
    if unsafe { GetCursorPos(&mut point) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((point.x, point.y))
}

pub fn window_at_point((x, y): (i32, i32)) -> Option<u32> {
    // SAFETY: WindowFromPoint takes a POINT by value and returns a borrowed HWND.
    let hwnd = unsafe { WindowFromPoint(POINT { x, y }) };
    (!hwnd.is_null()).then_some(hwnd as usize as u32)
}

pub fn gui_thread_capture(tid: u32) -> io::Result<Option<u32>> {
    let mut info = GUITHREADINFO {
        cbSize: size_of::<GUITHREADINFO>() as u32,
        ..Default::default()
    };
    // SAFETY: The initialized structure has the required size. A zero tid reads the
    // foreground thread, as documented by GetGUIThreadInfo.
    if unsafe { GetGUIThreadInfo(tid, &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((!info.hwndCapture.is_null()).then_some(info.hwndCapture as usize as u32))
}

pub fn mouse_wheel_routing() -> io::Result<u32> {
    let mut routing = 0_u32;
    // SAFETY: SPI_GETMOUSEWHEELROUTING writes a UINT to pvParam.
    if unsafe {
        SystemParametersInfoW(
            SPI_GETMOUSEWHEELROUTING,
            0,
            (&mut routing as *mut u32).cast(),
            0,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(routing)
}

pub fn virtual_screen() -> [i32; 4] {
    // SAFETY: Each metric reading takes a constant and returns an integer.
    unsafe {
        [
            GetSystemMetrics(SM_XVIRTUALSCREEN),
            GetSystemMetrics(SM_YVIRTUALSCREEN),
            GetSystemMetrics(SM_CXVIRTUALSCREEN),
            GetSystemMetrics(SM_CYVIRTUALSCREEN),
        ]
    }
}
