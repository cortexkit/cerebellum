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
    // `lsappinfo front` names the active application's session number. Field
    // reads (`info -only pid`) come back NULL from a shell that disclaimed its
    // responsible process, so the check compares the front session number with
    // the one taken before the helper drew anything: any activation changes it.
    let front_asn = || -> Result<String, Box<dyn std::error::Error>> {
        let front = Command::new("/usr/bin/lsappinfo").arg("front").output()?;
        if !front.status.success() {
            return Err("lsappinfo front failed".into());
        }
        Ok(String::from_utf8(front.stdout)?.trim().to_owned())
    };
    let before = front_asn()?;
    for point in points {
        let event = CursorEvent {
            serial: 0,
            avatar_rgba: None,
            avatar_update: false,
            avatar_tint: None,
            agent: "Focus probe".into(),
            initial: 'F',
            to: point,
            target: None,
            resting: false,
            label: Some("Focus probe".into()),
            kind: CursorKind::Press,
        };
        pipe.write_all(&event.encode_line().ok_or("invalid pipe event")?)?;
        let until = Instant::now() + Duration::from_secs(2);
        while Instant::now() < until {
            let asn = front_asn()?;
            let normal =
                cerebellum_macos::frontmost_process_id().and_then(|pid| u32::try_from(pid).ok());
            samples += 1;
            println!("sample {samples}: lsappinfo front={asn} frontmost_normal_pid={normal:?} helper_pid={pid}");
            if asn.is_empty() || asn != before || normal.is_none() || normal == Some(pid) {
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
            "PASS: {samples} samples kept the front application {before} and never named helper pid {pid}"
        );
        Ok(())
    } else {
        Err(format!("FAIL: missing reading or helper frontmost at samples {failures:?}").into())
    }
}
