//! Does the capture's session-verification tab behave in a real Chrome the way
//! `browser.capture_login` assumes?
//!
//! The capture checks a sign-in by loading the holder's `fetch_url` in a
//! hidden background tab of the capture browser
//! (`CdpNavigationDriver::load_in_background_tab`). Its tests drive a scripted
//! pipe. This probe checks the two assumptions a script cannot:
//!
//! 1. Chrome reports the main document's HTTP status on the tab's own frame
//!    id, so the probe's `status` is `Some` for a real page.
//! 2. Opening, loading and closing the tab never brings Chrome forward and
//!    never replaces the person's tab.
//!
//! It launches Chrome as the capture does (the same launch arguments and the
//! same suspended spawn), opens a "person" tab on example.com and fronts it as
//! the capture fronts its sign-in page, then hands focus back to the app that
//! was in front. It then runs one verification per URL while a recorder
//! samples the frontmost process every 100 ms. Every probe prints the final
//! URL, the status, whether a credential field showed, and the capture's own
//! verdict for that load. Chrome must never be frontmost during the
//! verifications, and the person's tab must still be on example.com afterwards.
//!
//! It opens a visible Chrome window on a throwaway profile under the temp
//! directory and signs in nowhere, but run it only with the operator's
//! permission:
//!
//! ```text
//! cargo run -p cerebellum --example verification_tab_probe
//! ```

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("this probe launches macOS Chrome and has nothing to run here");
}

#[cfg(target_os = "macos")]
fn main() {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use cerebellum::browser::navigation::CdpNavigationDriver;
    use cerebellum::browser::Tracker;
    use cerebellum::browser_launch_readiness::UnixCdpPipe;
    use cerebellum::browser_session::NavigationWait;
    use cerebellum::cdp::{CdpFrameDecoder, CdpTransport};
    use cerebellum::login_capture::session_verified;

    const CONTEXT: &str = "browser.capture_login";
    const PERSON_URL: &str = "https://example.com/";
    // Each pair is the URL loaded and the verdict the capture should reach.
    const CASES: [(&str, &str); 4] = [
        // A page served at the requested URL.
        ("https://example.com/", "verified"),
        // A redirect to another host: iana.org sends visitors to www.iana.org.
        ("https://iana.org/domains/example", "off_origin"),
        // A page that needs a session redirects to a sign-in page on its own
        // origin when there is none, as GitHub does with no session.
        ("https://github.com/settings/profile", "sign_in_page"),
        // A missing page answers with an error status.
        (
            "https://www.iana.org/this-page-does-not-exist-cereb-probe",
            "status",
        ),
    ];

    let chrome = PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
    if !chrome.is_file() {
        println!("skipped: no Chrome at {}", chrome.display());
        return;
    }
    let front_before = cerebellum_macos::frontmost_process_id();
    let profile = std::env::temp_dir().join(format!("ck-verify-probe-{}", std::process::id()));
    std::fs::create_dir_all(&profile).expect("profile dir");
    let arguments = cerebellum::browser_launch_service::browser_launch_arguments(
        &profile,
        &profile.join("crash-dumps"),
    );
    let (command_child, command_parent) = UnixStream::pair().expect("command pair");
    let (response_parent, response_child) = UnixStream::pair().expect("response pair");
    let barred = cerebellum_macos::spawn_barred(
        &chrome,
        &arguments,
        &[],
        command_child.as_raw_fd(),
        response_child.as_raw_fd(),
    )
    .expect("spawn barred");
    let released = barred.release().expect("release");
    let chrome_pid = released.generation().pid as i32;
    drop(command_child);
    drop(response_child);
    let pipe = UnixCdpPipe::new(command_parent, response_parent).expect("pipe");
    let mut driver =
        CdpNavigationDriver::new(pipe, CdpTransport::new(), CdpFrameDecoder::default());

    let mut tracker = Tracker::default();
    driver
        .navigate(
            CONTEXT,
            PERSON_URL,
            NavigationWait::None,
            20_000,
            &mut tracker,
        )
        .expect("person tab navigate");
    driver.present(CONTEXT, 10_000).expect("present");
    std::thread::sleep(Duration::from_millis(1_500));
    println!(
        "after present: frontmost={:?} chrome_pid={chrome_pid} (present is meant to front Chrome)",
        cerebellum_macos::frontmost_process_id()
    );

    // Hand focus back to the app that was in front, standing in for the person
    // switching away while the capture waits.
    if let Some(pid) = front_before.filter(|pid| *pid != chrome_pid) {
        let _ = std::process::Command::new("/usr/bin/osascript")
            .args([
                "-e",
                &format!(
                    "tell application \"System Events\" to set frontmost of (first process whose unix id is {pid}) to true"
                ),
            ])
            .status();
        std::thread::sleep(Duration::from_millis(1_000));
    }
    let front_during_baseline = cerebellum_macos::frontmost_process_id();
    println!("before verifications: frontmost={front_during_baseline:?}");

    let recording = Arc::new(AtomicBool::new(true));
    let samples = Arc::new(Mutex::new(Vec::<(u128, Option<i32>)>::new()));
    let recorder = {
        let recording = Arc::clone(&recording);
        let samples = Arc::clone(&samples);
        let started = Instant::now();
        std::thread::spawn(move || {
            while recording.load(Ordering::Acquire) {
                samples.lock().unwrap().push((
                    started.elapsed().as_millis(),
                    cerebellum_macos::frontmost_process_id(),
                ));
                std::thread::sleep(Duration::from_millis(100));
            }
        })
    };

    let mut all_expected = true;
    for (url, expected) in CASES {
        let started = Instant::now();
        let result = driver.load_in_background_tab(url, 10_000);
        let elapsed = started.elapsed().as_millis();
        match result {
            Ok(probe) => {
                let verdict = match session_verified(url, &probe) {
                    Ok(()) => "verified".to_string(),
                    Err(failure) => format!("{failure:?}"),
                };
                let matches = match expected {
                    "verified" => verdict == "verified",
                    "off_origin" => verdict == "OffOrigin",
                    "sign_in_page" => verdict == "SignInPage",
                    "status" => verdict.starts_with("Status(Some("),
                    _ => false,
                };
                all_expected &= matches && probe.status.is_some();
                println!(
                    "{url}\n    final_url={} status={:?} credential_field={} verdict={verdict} expected={expected} {} ({elapsed} ms)",
                    probe.final_url,
                    probe.status,
                    probe.credential_field,
                    if matches { "OK" } else { "MISMATCH" }
                );
            }
            Err(error) => {
                all_expected = false;
                println!("{url}\n    load failed: {error:?} ({elapsed} ms)");
            }
        }
    }

    recording.store(false, Ordering::Release);
    recorder.join().expect("recorder");
    let samples = samples.lock().unwrap().clone();
    let chrome_front = samples
        .iter()
        .filter(|(_, pid)| *pid == Some(chrome_pid))
        .count();
    let person_url = driver.main_frame_url(CONTEXT, 5_000);
    println!(
        "focus: {} samples, Chrome frontmost in {chrome_front}; first={:?} last={:?}",
        samples.len(),
        samples.first(),
        samples.last()
    );
    println!("person tab after verifications: {person_url:?}");
    let person_ok = person_url
        .as_deref()
        .is_ok_and(|url| url.starts_with(PERSON_URL));
    let focus_ok = chrome_front == 0 || front_during_baseline == Some(chrome_pid);
    println!(
        "VERDICT: statuses_and_verdicts={} focus_kept={} person_tab_kept={}",
        if all_expected { "ok" } else { "MISMATCH" },
        if front_during_baseline == Some(chrome_pid) {
            "unmeasurable (Chrome was already front before the loads)".to_string()
        } else {
            focus_ok.to_string()
        },
        person_ok
    );

    let _ = released.terminate_and_reap();
    let _ = std::fs::remove_dir_all(&profile);
}
