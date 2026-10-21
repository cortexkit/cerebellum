//! The launch nonce: the one-time secret the subc daemon gives this process when
//! it spawns it, which HELLO presents to prove the connection comes from the
//! process the daemon started.
//!
//! On Unix the daemon hands it over through a pipe on descriptor 3. On Windows
//! it serves it once on a named pipe it creates before starting the module,
//! named in `SUBC_LAUNCH_NONCE_PIPE`. During the transition it also passes the
//! nonce as the `SUBC_LAUNCH_NONCE` environment variable. All of these are read
//! by `subc_os::launch_nonce()` and nothing else: that accessor reads the pipe
//! once, closes it, and caches the value and where it came from for the life of
//! the process. A second, independent reader would find descriptor 3 reused by
//! some unrelated socket or file and read and close that instead.
//!
//! Two consequences for the rest of the module live here as well:
//!
//! - The accessor has to run before the module spawns anything. Until it
//!   reads, the Unix pipe is an ordinary inheritable descriptor (it has to be,
//!   to survive the daemon's exec), and a child spawned earlier would inherit it.
//! - A child must not see the nonce through the environment either. The
//!   accessor deliberately leaves the environment alone (changing it in a
//!   multi-threaded process is unsound), so every `std::process::Command` the
//!   module runs removes every launch-nonce variable through
//!   [`without_launch_nonce`]. The browser launchers in the platform crates need
//!   no such step: they hand the browser an explicit environment built from
//!   scratch, never this process's.

use std::process::Command;

use subc_protocol::manifest::LaunchNonceSource as ProvenanceSource;

/// Read the launch nonce now, so the pipe is closed before anything is spawned.
///
/// The result is cached by the accessor, so it is not needed here: HELLO reads
/// the same cached answer through [`for_hello`] and reports an error there,
/// where it stops the module registering. A failed read is harmless to spawn
/// after: every descriptor the accessor leaves open is one holding no nonce
/// (an empty pipe, or one that is not the daemon's).
pub(crate) fn read_before_any_spawn() {
    let _ = subc_os::launch_nonce();
}

/// The nonce to present in HELLO, or `None` when the daemon gave none (the
/// module was started by hand). A descriptor that is named but unusable is an
/// error, never a silent fallback to the environment copy.
pub(crate) fn for_hello() -> Result<Option<String>, subc_os::LaunchNonceError> {
    Ok(subc_os::launch_nonce()?.map(|nonce| nonce.value().to_string()))
}

/// The nonce to present as `consumer_identity` when this module opens a route
/// of its own (today only the vault deposit after a granted capture card).
///
/// The same cached answer HELLO used: the accessor read the pipe once at
/// startup and this never reads it again. Without it the daemon stamps the
/// route `Direct`, and the vault refuses a direct caller. `None` when the
/// daemon gave no nonce (the module was started by hand) or the read failed;
/// a failed read already stopped HELLO, so a registered module never sees it.
pub(crate) fn for_consumer_identity() -> Option<String> {
    subc_os::launch_nonce()
        .ok()
        .flatten()
        .map(|nonce| nonce.value().to_string())
}

/// Where this process read its nonce from, as module provenance reports it
/// (`fd`, `pipe` or `env`). `None` when there is no nonce or it could not be
/// read: then there is no source to claim.
pub(crate) fn provenance_source() -> Option<ProvenanceSource> {
    provenance_source_from(
        subc_os::launch_nonce()
            .ok()
            .flatten()
            .map(|nonce| nonce.source()),
    )
}

/// The accessor's source in provenance's own vocabulary. Converted by name
/// rather than by an exhaustive match because both enums may grow: a source
/// this build does not know is passed on as the name the accessor gave it,
/// which is what provenance's forward-compatible variant exists to carry.
fn provenance_source_from(source: Option<subc_os::LaunchNonceSource>) -> Option<ProvenanceSource> {
    source.map(|source| ProvenanceSource::from_wire_name(source.as_str()))
}

/// Keep every launch-nonce variable out of a child's environment.
///
/// A child that inherited `SUBC_LAUNCH_NONCE` could present it and be admitted
/// as this module. The other three carry no secret. `SUBC_LAUNCH_NONCE_FD` and
/// `SUBC_LAUNCH_NONCE_PIPE` only say where the nonce was delivered, and a child
/// that inherits them would try to read a descriptor or pipe it was never given.
/// `SUBC_LAUNCH_NONCE_PIPE_FALLBACK` only permits the environment copy, and
/// subc-os requires it to be removed together with that copy. Dropping all four
/// means a child sees no sign of a nonce at all.
pub(crate) fn without_launch_nonce(command: &mut Command) -> &mut Command {
    command
        .env_remove(subc_os::LAUNCH_NONCE_ENV)
        .env_remove(subc_os::LAUNCH_NONCE_FD_ENV)
        .env_remove(subc_os::LAUNCH_NONCE_PIPE_ENV)
        .env_remove(subc_os::LAUNCH_NONCE_PIPE_FALLBACK_ENV)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provenance_names_the_source_the_accessor_reported() {
        assert_eq!(
            provenance_source_from(Some(subc_os::LaunchNonceSource::Fd)),
            Some(ProvenanceSource::Fd)
        );
        assert_eq!(
            provenance_source_from(Some(subc_os::LaunchNonceSource::Env)),
            Some(ProvenanceSource::Env)
        );
        assert_eq!(
            provenance_source_from(Some(subc_os::LaunchNonceSource::Pipe)),
            Some(ProvenanceSource::Pipe)
        );
        assert_eq!(provenance_source_from(None), None);
    }

    /// The probe tests below run this test binary again as a child with a
    /// launch nonce, the way the daemon starts the module. This is the child
    /// side; run normally it finds no probe mode and does nothing.
    const PROBE_MODE: &str = "CEREBELLUM_LAUNCH_NONCE_PROBE";
    const PROBE_TEST: &str = "launch_nonce::tests::launch_nonce_probe_child";
    const PROBE_NONCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// What the grandchild reports: whether descriptor 3 is open in it, then
    /// its whole environment. `/usr/bin/env` rather than a copied fixture:
    /// a binary under `$TMPDIR` can hang on macOS system policy checks.
    #[cfg(unix)]
    fn run_grandchild() -> String {
        let output = without_launch_nonce(&mut Command::new("/bin/sh"))
            .args([
                "-c",
                "if [ -e /dev/fd/3 ]; then echo fd3=open; else echo fd3=closed; fi; exec /usr/bin/env",
            ])
            .current_dir("/tmp")
            .output()
            .expect("run the grandchild");
        assert!(output.status.success(), "grandchild failed: {output:?}");
        String::from_utf8(output.stdout).expect("grandchild output is UTF-8")
    }

    #[test]
    fn launch_nonce_probe_child() {
        let Some(mode) = std::env::var_os(PROBE_MODE) else {
            return;
        };
        #[cfg(unix)]
        {
            let spawn_first = mode == "spawn-first";
            let early = spawn_first.then(run_grandchild);
            read_before_any_spawn();
            let late = run_grandchild();
            let grandchild = early.unwrap_or(late);
            let provenance = crate::manifest::build("cerebellum")
                .provenance
                .and_then(|provenance| provenance.launch_nonce_source)
                .map_or_else(
                    || "none".to_string(),
                    |source| source.wire_name().to_string(),
                );
            println!("probe:source={provenance}");
            println!(
                "probe:hello_nonce_matches={}",
                for_hello().ok().flatten().as_deref() == Some(PROBE_NONCE)
            );
            for line in grandchild.lines() {
                println!("probe:grandchild:{line}");
            }
        }
        #[cfg(not(unix))]
        let _ = mode;
    }

    /// Start this test binary as the daemon would start the module: with the
    /// environment copy of the nonce, and, when `pipe` is set, with the pipe on
    /// descriptor 3. Returns the probe's report lines.
    #[cfg(unix)]
    fn probe(mode: &str, pipe: bool) -> Vec<String> {
        let mut command = Command::new(std::env::current_exe().expect("test binary"));
        command
            .args([PROBE_TEST, "--exact", "--nocapture", "--test-threads=1"])
            .env(PROBE_MODE, mode)
            .env(subc_os::LAUNCH_NONCE_ENV, PROBE_NONCE)
            .env_remove(subc_os::LAUNCH_NONCE_FD_ENV)
            // The Windows delivery variables, which a Unix accessor never
            // reads. They are set so the removal check covers them too.
            .env(
                subc_os::LAUNCH_NONCE_PIPE_ENV,
                r"\\.\pipe\cerebellum-probe-unused",
            )
            .env(subc_os::LAUNCH_NONCE_PIPE_FALLBACK_ENV, "env");
        if pipe {
            let handoff = subc_os::LaunchNonceHandoff::new(PROBE_NONCE).expect("nonce pipe");
            command.env(subc_os::LAUNCH_NONCE_FD_ENV, handoff.fd_env_value());
            handoff.install_last(&mut command);
        }
        let output = command.output().expect("run the probe");
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        assert!(
            output.status.success(),
            "probe failed: {stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        stdout
            .lines()
            // Searched for rather than stripped from the start: the test
            // harness prints `test <name> ... ` without a newline before the
            // probe's first line, so that line does not begin with the prefix.
            .filter_map(|line| line.find("probe:").map(|at| line[at + 6..].to_string()))
            .collect()
    }

    #[cfg(unix)]
    fn has(report: &[String], line: &str) -> bool {
        report.iter().any(|reported| reported == line)
    }

    /// The HELLO nonce and the provenance source come from the same read of the
    /// pipe, and the manifest the module sends says `fd`.
    #[cfg(unix)]
    #[test]
    fn provenance_reports_fd_when_the_nonce_came_through_the_pipe() {
        let report = probe("read-first", true);
        assert!(has(&report, "source=fd"), "{report:#?}");
        assert!(has(&report, "hello_nonce_matches=true"), "{report:#?}");
    }

    #[cfg(unix)]
    #[test]
    fn provenance_reports_env_when_only_the_environment_copy_was_given() {
        let report = probe("read-first", false);
        assert!(has(&report, "source=env"), "{report:#?}");
        assert!(has(&report, "hello_nonce_matches=true"), "{report:#?}");
    }

    /// A process the module spawns sees none of the launch-nonce variables,
    /// although the module itself was started with all four. The probe mode
    /// variable reaching the grandchild shows the environment was inherited at
    /// all, so the absence of the others is the removal and not an empty
    /// environment.
    #[cfg(unix)]
    #[test]
    fn a_spawned_child_sees_no_launch_nonce_variable() {
        let report = probe("read-first", true);
        assert!(
            has(&report, &format!("grandchild:{PROBE_MODE}=read-first")),
            "the grandchild did not inherit the environment at all: {report:#?}"
        );
        for name in [
            subc_os::LAUNCH_NONCE_ENV,
            subc_os::LAUNCH_NONCE_FD_ENV,
            subc_os::LAUNCH_NONCE_PIPE_ENV,
            subc_os::LAUNCH_NONCE_PIPE_FALLBACK_ENV,
        ] {
            assert!(
                !report
                    .iter()
                    .any(|line| line.starts_with(&format!("grandchild:{name}="))),
                "{name} reached the grandchild: {report:#?}"
            );
        }
    }

    /// Once the nonce is read, a spawned child has nothing at descriptor 3.
    /// The spawn-first run is the control: a child started before the read
    /// does see the pipe there, so the check can see an inherited pipe and the
    /// read-first answer is the read closing it, not a blind check.
    #[cfg(unix)]
    #[test]
    fn a_child_spawned_after_the_read_does_not_inherit_the_pipe() {
        let control = probe("spawn-first", true);
        assert!(
            has(&control, "grandchild:fd3=open"),
            "a child spawned before the read should have inherited the pipe: {control:#?}"
        );
        let report = probe("read-first", true);
        assert!(has(&report, "grandchild:fd3=closed"), "{report:#?}");
    }
}
