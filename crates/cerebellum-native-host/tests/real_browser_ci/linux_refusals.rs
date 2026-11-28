use super::*;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::ptr;

pub(super) fn trace_me() -> io::Result<()> {
    // SAFETY: TRACEME ignores the remaining arguments.
    let result = unsafe {
        libc::ptrace(
            libc::PTRACE_TRACEME,
            0,
            ptr::null_mut::<()>(),
            ptr::null_mut::<()>(),
        )
    };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub(super) fn stop_after_browser_exec(child: u32) {
    let pid = i32::try_from(child).unwrap();
    let status = || {
        wait_for("a stop in the owned browser fixture", || {
            let mut status = 0;
            // SAFETY: status is writable, and pid is the direct fixture child.
            let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG | libc::__WALL) };
            assert!(result >= 0, "waitpid: {}", io::Error::last_os_error());
            (result == pid).then_some(status)
        })
    };
    let command = |request, data: usize| {
        // SAFETY: these requests act only on the already-stopped child and
        // take immediate numeric options, not borrowed memory.
        let result = unsafe { libc::ptrace(request, pid, ptr::null_mut::<()>(), data) };
        assert_eq!(
            result,
            0,
            "ptrace {request}: {}",
            io::Error::last_os_error()
        );
    };
    let initial = status();
    assert!(libc::WIFSTOPPED(initial) && libc::WSTOPSIG(initial) == libc::SIGTRAP);
    command(
        libc::PTRACE_SETOPTIONS,
        (libc::PTRACE_O_TRACEEXEC | libc::PTRACE_O_EXITKILL) as usize,
    );
    command(libc::PTRACE_CONT, 0);
    let exec = status();
    assert!(
        libc::WIFSTOPPED(exec) && exec >> 16 == libc::PTRACE_EVENT_EXEC,
        "expected fixture image exec, got {exec:#x}"
    );
}

#[test]
#[ignore = "requires the runner's real packaged Chrome or Chromium files"]
fn ubuntu_package_crashpad_image_is_refused() {
    let (browser, kind, _) = browser_under_test();
    assert_eq!(kind, LinuxBrowser::GoogleChrome);
    let helper = browser.with_file_name("chrome_crashpad_handler");
    // Stop the process at exec so a short-lived package helper can be observed.
    let fixture = Fixture::start(&helper, &[], true);
    assert_eq!(
        fixture.step1().unwrap_err(),
        "running browser is outside the allowed package paths"
    );
}

#[test]
#[ignore = "requires the runner's real packaged Chrome or Chromium files"]
fn copied_browser_image_is_refused() {
    let (browser, _, _) = browser_under_test();
    let scratch = Scratch::new();
    let copied = scratch.join(browser.file_name().unwrap().to_str().unwrap());
    fs::copy(browser, &copied).unwrap();
    let fixture = Fixture::start(&copied, &[], true);
    assert_eq!(
        fixture.step1().unwrap_err(),
        "running browser is outside the allowed package paths"
    );
}

#[test]
#[ignore = "requires Ubuntu's apt chromium-browser snap"]
fn ubuntu_snap_chromium_is_refused() {
    let status = Command::new("dpkg-query")
        .args(["--show", "--showformat=${Status}", "chromium-browser"])
        .output()
        .unwrap();
    assert!(status.status.success());
    assert_eq!(status.stdout, b"install ok installed");
    let snap = fs::canonicalize("/snap/chromium/current/usr/lib/chromium-browser/chrome")
        .expect("installed Chromium snap executable");
    assert!(snap.starts_with("/snap/chromium"));
    let fixture = Fixture::start(&snap, &[], true);
    assert_eq!(
        fixture.step1().unwrap_err(),
        "running browser is outside the allowed package paths"
    );
}

struct StatusFile {
    before: String,
    mode: u32,
}

impl StatusFile {
    const PATH: &'static str = "/var/lib/dpkg/status";

    fn open() -> Self {
        assert_eq!(
            std::env::var("CK_IMAGE_TEST_DPKG_DISPOSABLE").as_deref(),
            Ok("1")
        );
        assert_eq!(
            std::env::var("CK_IMAGE_TEST_DISTRO").as_deref(),
            Ok("debian")
        );
        Self {
            before: fs::read_to_string(Self::PATH).unwrap(),
            mode: fs::metadata(Self::PATH).unwrap().permissions().mode(),
        }
    }

    fn replace(&self, contents: &str) {
        let scratch = format!("{}.ck-browser-{}", Self::PATH, std::process::id());
        fs::write(&scratch, contents).unwrap();
        fs::set_permissions(&scratch, fs::Permissions::from_mode(self.mode)).unwrap();
        fs::rename(scratch, Self::PATH).unwrap();
    }

    fn replace_field(&self, field: &str, value: &str) {
        let (start, stanza) = self
            .before
            .match_indices("Package: chromium\n")
            .next()
            .unwrap();
        assert!(!stanza.is_empty());
        let end = start + self.before[start..].find("\n\n").unwrap();
        let record = &self.before[start..end];
        let old = record.lines().find(|line| line.starts_with(field)).unwrap();
        let new = record.replacen(old, &format!("{field} {value}"), 1);
        self.replace(&format!(
            "{}{new}{}",
            &self.before[..start],
            &self.before[end..]
        ));
    }
}

impl Drop for StatusFile {
    fn drop(&mut self) {
        self.replace(&self.before);
    }
}

#[test]
#[ignore = "changes dpkg status only in the disposable Debian container"]
fn debian_package_state_and_version_change_are_refused() {
    let (image, _, _) = browser_under_test();
    let profile = Scratch::new();
    {
        let fixture = Fixture::new(image, &browser_args(&profile.0));
        let status = StatusFile::open();
        status.replace_field("Status:", "deinstall ok config-files");
        assert_eq!(
            fixture.step1().unwrap_err(),
            "no installed dpkg record lists the browser"
        );
    }
    let profile = Scratch::new();
    let mut fixture = Fixture::new(image, &browser_args(&profile.0));
    fixture
        .step1()
        .expect("accept the unchanged package before replacing its version");
    let status = StatusFile::open();
    status.replace_field("Version:", "999:1.0-cki");
    assert_eq!(
        fixture.finish().unwrap_err(),
        "Linux parent attestation does not match observed evidence"
    );
}

struct RestoreImage<'a> {
    path: &'a Path,
    saved: PathBuf,
}

impl Drop for RestoreImage<'_> {
    fn drop(&mut self) {
        fs::rename(&self.saved, self.path).unwrap();
    }
}

#[test]
#[ignore = "replaces the browser inode only in the disposable Debian container"]
fn debian_live_image_replaced_by_upgrade_is_refused() {
    assert_eq!(
        std::env::var("CK_IMAGE_TEST_DPKG_DISPOSABLE").as_deref(),
        Ok("1")
    );
    let (image, browser, _) = browser_under_test();
    assert_eq!(browser, LinuxBrowser::Chromium);
    let profile = Scratch::new();
    let fixture = Fixture::new(image, &browser_args(&profile.0));
    let saved = image.with_file_name(format!("chromium.ck-browser-{}", std::process::id()));
    fs::hard_link(image, &saved).unwrap();
    let restore = RestoreImage { path: image, saved };
    fs::remove_file(image).unwrap();
    fs::copy(&restore.saved, image).unwrap();
    assert_eq!(
        fixture.step1().unwrap_err(),
        "launching executable was deleted"
    );
}
