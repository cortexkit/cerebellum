//! Live check: the agent's Chrome, spawned through cerebellum's production
//! launch path, is its own macOS responsible process, so it can't use this
//! module's Screen Recording, Accessibility or Input Monitoring grants.
//!
//! Starts a throwaway Google Chrome with no window (`--no-startup-window`)
//! and a scratch profile under `/tmp`, asks macOS which process it holds
//! responsible for that Chrome, and stops it. Uses only read-only calls, so
//! it can't raise a privacy prompt. Runs on a desk with the operator's
//! approval; never in CI.

#[cfg(target_os = "macos")]
fn main() {
    use std::ffi::{c_int, c_void, OsString};
    use std::os::fd::AsRawFd;
    use std::path::Path;

    extern "C" {
        fn dlsym(handle: *mut c_void, symbol: *const std::ffi::c_char) -> *mut c_void;
    }
    type ResponsiblePid = unsafe extern "C" fn(c_int) -> c_int;
    // SAFETY: libSystem's `pid_t responsibility_get_pid_responsible_for_pid(pid_t)`
    // from the private header responsibility.h; Darwin's `pid_t` is `c_int`.
    let symbol = unsafe {
        dlsym(
            (-2isize) as *mut c_void,
            c"responsibility_get_pid_responsible_for_pid".as_ptr(),
        )
    };
    assert!(!symbol.is_null(), "responsibility query unavailable");
    let responsible_for = |pid: u32| unsafe {
        std::mem::transmute::<*mut c_void, ResponsiblePid>(symbol)(pid as c_int)
    };

    let chrome = Path::new("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
    let mut all_own = true;
    for run in 1..=2 {
        let profile = format!("/tmp/ck-disclaim-check-{}-{run}", std::process::id());
        std::fs::create_dir_all(&profile).expect("scratch profile");
        let (command_read, _command_write) = std::io::pipe().expect("command pipe");
        let (_response_read, response_write) = std::io::pipe().expect("response pipe");
        let arguments: Vec<OsString> = [
            "--remote-debugging-pipe",
            "--no-startup-window",
            "--no-first-run",
            "--no-default-browser-check",
            &format!("--user-data-dir={profile}"),
        ]
        .iter()
        .map(OsString::from)
        .collect();
        let child = cerebellum_macos::spawn_barred(
            chrome,
            &arguments,
            &[],
            command_read.as_raw_fd(),
            response_write.as_raw_fd(),
        )
        .expect("spawn through the production path");
        let pid = child.generation().pid;
        let released = child.release().expect("release the barred child");
        std::thread::sleep(std::time::Duration::from_secs(3));
        let responsible = responsible_for(pid);
        let launcher = responsible_for(std::process::id());
        let own = responsible == pid as c_int;
        all_own &= own;
        println!(
            "run {run}: chrome pid {pid}, responsible {responsible} (own: {own}); \
             this probe's responsible process {launcher}"
        );
        released.terminate_and_reap().expect("stop chrome");
        let _ = std::fs::remove_dir_all(&profile);
    }
    println!("{}", if all_own { "PASS" } else { "FAIL" });
    std::process::exit(if all_own { 0 } else { 1 });
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("macOS only");
}
