//! Offline doctor entry point. Module settings and state come from the runner's
//! `XDG_CONFIG_HOME` and `XDG_DATA_HOME`, never from the user's home directory.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use cortexkit_doctor::module::{self, CheckError, FixOutcome, FixRefusal, PreflightError};
use cortexkit_doctor::{Evidence, Finding, FindingId, Fix, Severity};
use rustix::fs::{open, Mode, OFlags};
use serde::Deserialize;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub(crate) use linux::AppliedBrowser;

const MANIFEST: &str = include_str!("../doctor-manifest.json");
const CONFIG_LIMIT: u64 = 1024 * 1024;

/// Handle `doctor` before the runtime, registration, or stores are opened.
pub fn run(args: &[impl AsRef<OsStr>]) -> ExitCode {
    module::run(
        args,
        |_| with_doctor(|doctor| doctor.check()),
        |finding| {
            let Some(doctor) = Doctor::from_env() else {
                return Err(PreflightError::Failed);
            };
            doctor.preflight(finding)
        },
        |finding| match Doctor::from_env() {
            Some(doctor) => doctor.fix(finding),
            None => fix_failed(),
        },
        MANIFEST,
    )
}

fn with_doctor(
    check: impl FnOnce(Doctor) -> io::Result<Vec<Finding>>,
) -> Result<Vec<Finding>, CheckError> {
    let doctor = Doctor::from_env().ok_or(CheckError)?;
    check(doctor).map_err(|_| CheckError)
}

struct Doctor {
    config_path: PathBuf,
    #[cfg(target_os = "linux")]
    applied_path: PathBuf,
}

impl Doctor {
    fn from_env() -> Option<Self> {
        fn home(name: &str) -> Option<PathBuf> {
            let path = PathBuf::from(std::env::var_os(name)?);
            path.is_absolute().then_some(path)
        }
        Some(Self::new(
            &home("XDG_CONFIG_HOME")?,
            &home("XDG_DATA_HOME")?,
        ))
    }

    fn new(config_home: &Path, data_home: &Path) -> Self {
        #[cfg(not(target_os = "linux"))]
        let _ = data_home;
        Self {
            config_path: config_home.join("cortexkit/cerebellum.jsonc"),
            #[cfg(target_os = "linux")]
            applied_path: linux::applied_path(data_home),
        }
    }

    fn check(&self) -> io::Result<Vec<Finding>> {
        let text = match read_text(&self.config_path, CONFIG_LIMIT) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(vec![]),
            Err(error) => return Err(error),
        };
        let settings = BrowserSettings::parse(&text)?;
        let Some(path) = settings.executable_path.as_deref() else {
            return Ok(vec![]);
        };
        if !path.is_file() {
            return Ok(vec![finding(
                "browser.executable_missing",
                Severity::Warning,
                "The configured browser program is missing; reinstall Chrome or clear the browser program setting.",
                vec![],
                Fix::none(false),
            )]);
        }
        #[cfg(target_os = "linux")]
        return Ok(linux::identity_finding(
            &settings,
            self.applied().as_ref(),
            linux::ImageTrust::System,
        )
        .into_iter()
        .map(|identity| identity.finding)
        .collect());
        #[cfg(not(target_os = "linux"))]
        Ok(vec![])
    }

    fn preflight(&self, finding: &Finding) -> Result<(), PreflightError> {
        #[cfg(target_os = "linux")]
        return self.check_edit_lock(finding);
        #[cfg(not(target_os = "linux"))]
        {
            let _ = finding;
            Err(PreflightError::Failed)
        }
    }

    fn fix(&self, finding: Finding) -> FixOutcome {
        #[cfg(target_os = "linux")]
        return self.apply(finding, linux::ImageTrust::System);
        #[cfg(not(target_os = "linux"))]
        {
            let _ = finding;
            FixOutcome::refused(FixRefusal::PlanChanged)
        }
    }
}

#[derive(Default, Deserialize)]
struct BrowserSettings {
    executable_path: Option<PathBuf>,
    #[cfg(target_os = "linux")]
    expected_identity: Option<String>,
}

impl BrowserSettings {
    fn parse(text: &str) -> io::Result<Self> {
        #[derive(Deserialize)]
        struct Config {
            #[serde(default)]
            browser: BrowserSettings,
        }
        let json = subc_jsonc::jsonc_to_json(text).map_err(io::Error::other)?;
        let mut browser = serde_json::from_str::<Config>(&json)?.browser;
        browser.executable_path = browser
            .executable_path
            .filter(|path| !path.as_os_str().is_empty());
        if browser
            .executable_path
            .as_ref()
            .is_some_and(|path| !path.is_absolute())
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(browser)
    }
}

fn open_regular(path: &Path) -> io::Result<File> {
    // Reject special files, and don't block on open if a FIFO races that check.
    if !std::fs::symlink_metadata(path)?.is_file() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let file = File::from(open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )?);
    if !file.metadata()?.is_file() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(file)
}

fn read_text(path: &Path, limit: u64) -> io::Result<String> {
    read_open_text(&open_regular(path)?, limit)
}

fn read_open_text(file: &File, limit: u64) -> io::Result<String> {
    let mut text = String::new();
    file.take(limit + 1).read_to_string(&mut text)?;
    if text.len() as u64 > limit {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(text)
}

fn finding(id: &str, level: Severity, summary: &str, evidence: Vec<Evidence>, fix: Fix) -> Finding {
    Finding::new(
        FindingId::new(id).expect("fixed doctor id"),
        level,
        summary,
        evidence,
        fix,
    )
    .expect("valid doctor finding")
}

fn fix_failed() -> FixOutcome {
    FixOutcome::failed("settings_write_failed", vec![]).expect("valid fix failure code")
}

#[cfg(target_os = "linux")]
fn code(name: &str, value: &str) -> Evidence {
    Evidence::new(
        name,
        cortexkit_doctor::EvidenceValue::Code(value.to_owned()),
    )
    .expect("valid doctor code")
}
