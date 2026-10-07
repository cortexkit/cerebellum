//! Manual desk probe. This draws on the operator's screen: never run in a gate.
//! Usage: cargo run -p cerebellum --example agent_cursor_focus -- /path/to/ck-cerebellum 200,200 600,400

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("SKIPPED: the cursor helper is macOS-only");
}

#[cfg(target_os = "macos")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use cerebellum_computer::cursor::{CursorEvent, CursorKind};
    use std::io::Write;
    use std::process::Command;
    use std::time::{Duration, Instant};
    if cerebellum_macos::screen_is_locked() != Some(false) {
        return Err("the screen must be unlocked for this manual probe".into());
    }
    let mut args = std::env::args().skip(1);
    let executable = std::path::PathBuf::from(
        args.next()
            .ok_or("supply a ck-cerebellum binary and x,y screen points")?,
    )
    .canonicalize()?;
    let points = args
        .map(|s| {
            let (x, y) = s.split_once(',').ok_or("a point must be x,y")?;
            Ok::<_, Box<dyn std::error::Error>>([x.parse::<f64>()?, y.parse::<f64>()?])
        })
        .collect::<Result<Vec<_>, _>>()?;
    if points.is_empty() || points.iter().flatten().any(|v| !v.is_finite()) {
        return Err("supply finite screen points".into());
    }
    let (barred, pipe) =
        cerebellum_macos::spawn_barred_stdin(&executable, &["--agent-cursor".into()])
            .map_err(|e| format!("spawn failed: {e:?}"))?;
    let pid = barred.generation().pid;
    let child = barred
        .release()
        .map_err(|e| format!("release failed: {e:?}"))?;
    let mut pipe = std::fs::File::from(pipe);
    let mut samples = 0;
    let mut failures = Vec::new();
    for point in points {
        let event = CursorEvent {
            agent: "Focus probe".into(),
            initial: 'F',
            to: point,
            width: 24.0,
            label: Some("Focus probe".into()),
            kind: CursorKind::Press,
        };
        pipe.write_all(&event.encode_line().ok_or("invalid pipe event")?)?;
        let until = Instant::now() + Duration::from_secs(2);
        while Instant::now() < until {
            let front = Command::new("/usr/bin/lsappinfo").arg("front").output()?;
            if !front.status.success() {
                return Err("lsappinfo front failed".into());
            }
            let asn = String::from_utf8(front.stdout)?.trim().to_owned();
            let info = Command::new("/usr/bin/lsappinfo")
                .args(["info", "-only", "pid", &asn])
                .output()?;
            if !info.status.success() {
                return Err("lsappinfo could not resolve the active app pid".into());
            }
            let info = String::from_utf8(info.stdout)?;
            let active = info
                .split_once('=')
                .and_then(|(_, value)| value.trim().trim_matches('"').parse::<u32>().ok());
            let normal =
                cerebellum_macos::frontmost_process_id().and_then(|pid| u32::try_from(pid).ok());
            samples += 1;
            println!("sample {samples}: lsappinfo front={asn} active_pid={active:?} frontmost_normal_pid={normal:?} helper_pid={pid}");
            if active.is_none() || normal.is_none() || active == Some(pid) || normal == Some(pid) {
                failures.push(samples);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    drop(pipe); // EOF ends the helper even when it has idle pictures.
    child
        .wait()
        .map_err(|e| format!("helper wait failed: {e:?}"))?;
    if failures.is_empty() && samples > 0 {
        println!(
            "PASS: {samples} active-app and normal-window samples never named helper pid {pid}"
        );
        Ok(())
    } else {
        Err(format!("FAIL: missing reading or helper frontmost at samples {failures:?}").into())
    }
}
