use std::io;
use std::path::PathBuf;
use windows_sys::Win32::{
    Foundation::{HWND, LPARAM},
    System::SystemInformation::GetSystemDirectoryW,
    UI::WindowsAndMessaging::{
        EnumChildWindows, EnumWindows, GetClassNameW, GetWindowTextW, GetWindowThreadProcessId,
        IsWindowVisible,
    },
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowIdentityFacts {
    pub number: u32,
    pub pid: u32,
    pub tid: u32,
    pub class: String,
    pub title: String,
    pub visible_style: bool,
}

unsafe extern "system" fn window_number(hwnd: HWND, data: LPARAM) -> i32 {
    // The enumeration functions invoke this callback synchronously with a
    // pointer to the caller's live vector.
    unsafe { &mut *(data as *mut Vec<u32>) }.push(hwnd as usize as u32);
    1
}

pub fn desktop_window_numbers() -> io::Result<Vec<u32>> {
    let mut windows = Vec::new();
    // This stack pointer lives until enumeration returns.
    if unsafe {
        EnumWindows(
            Some(window_number),
            (&mut windows as *mut Vec<u32>) as LPARAM,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(windows)
}

pub fn child_window_numbers(parent: u32) -> Vec<u32> {
    let mut windows = Vec::new();
    // The handle is a Win32 HWND value. A missing root is detected by a
    // separate owner reading; EnumChildWindows does not report that error.
    unsafe {
        EnumChildWindows(
            parent as usize as HWND,
            Some(window_number),
            (&mut windows as *mut Vec<u32>) as LPARAM,
        )
    };
    windows
}

pub fn window_identity_facts(number: u32) -> io::Result<WindowIdentityFacts> {
    let hwnd = number as usize as HWND;
    let mut pid = 0;
    // The output is a writable process ID. Invalid HWNDs return zero.
    let tid = unsafe { GetWindowThreadProcessId(hwnd, &mut pid) };
    if tid == 0 || pid == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut class = [0; 257];
    let mut title = [0; 1024];
    // The two buffers are writable UTF-16 strings, with explicit lengths.
    let class_len = unsafe { GetClassNameW(hwnd, class.as_mut_ptr(), class.len() as i32) };
    if class_len == 0 {
        return Err(io::Error::last_os_error());
    }
    let title_len = unsafe { GetWindowTextW(hwnd, title.as_mut_ptr(), title.len() as i32) }.max(0);
    let visible_style = unsafe { IsWindowVisible(hwnd) } != 0;
    let mut now_pid = 0;
    if unsafe { GetWindowThreadProcessId(hwnd, &mut now_pid) } != tid || pid != now_pid {
        return Err(io::Error::other("window owner changed"));
    }
    Ok(WindowIdentityFacts {
        number,
        pid,
        tid,
        class: String::from_utf16(&class[..class_len as usize])
            .map_err(|_| io::ErrorKind::InvalidData)?,
        title: String::from_utf16_lossy(&title[..title_len as usize]),
        visible_style,
    })
}

pub fn windows_system_directory() -> io::Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    let mut path = vec![0; 32768];
    // The buffer is writable and includes space for the terminator.
    let len = unsafe { GetSystemDirectoryW(path.as_mut_ptr(), path.len() as u32) } as usize;
    if len == 0 || len >= path.len() {
        return Err(io::Error::last_os_error());
    }
    Ok(PathBuf::from(std::ffi::OsString::from_wide(&path[..len])))
}
