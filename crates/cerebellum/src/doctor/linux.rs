use super::*;

use std::fs::{self, Metadata};
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

use cortexkit_doctor::{EvidenceValue, PathCategory};
use rustix::fs::{accessat, Access, AtFlags, CWD};
use rustix::io::Errno;
use serde::Serialize;
use sha2::{Digest, Sha256};

mod edit;

const IDENTITY_CHANGED: &str = "browser.identity_changed";
const APPLIED_LIMIT: u64 = 16 * 1024;
const RESTART_TO_IDENTIFY: &str = "The agent browser's applied identity is unknown; restart Cerebellum so it can identify the browser program.";
const PIN_NOT_IN_USE: &str = "The agent browser is pinned, not yet in use; the new pin applies after phone approval or a module restart, whichever this install needs.";
const CHANGED: &str = "The agent browser is off: the Chrome it runs changed since it was pinned, usually by an update.";
const UNSAFE: &str = "The agent browser's pin changed; the fix is unavailable because the image or a parent folder is not root-owned or can be changed by your account.";

// Diagnostic cache, not a backup source or an authority to start the browser.
#[derive(Deserialize, Serialize)]
pub(crate) struct AppliedBrowser {
    pub(super) stamped: bool,
    pub(crate) executable_path: Option<PathBuf>,
    pub(crate) expected_identity: Option<String>,
    pub(crate) final_image_path: Option<PathBuf>,
}

impl AppliedBrowser {
    pub(crate) fn new(stamped: bool) -> Self {
        Self {
            stamped,
            executable_path: None,
            expected_identity: None,
            final_image_path: None,
        }
    }

    pub(crate) fn record(&self) {
        if let Some(home) = cerebellum_core::platform_dirs::data_home() {
            let _ = self.write(&applied_path(&home));
        }
    }

    fn write(&self, path: &Path) -> io::Result<()> {
        let bytes = serde_json::to_vec(self)?;
        crate::private_content::write_atomically(path, &bytes)
    }
}

pub(super) fn applied_path(home: &Path) -> PathBuf {
    cerebellum_core::format_floor::module_directory(home).join("browser-applied.json")
}

impl Doctor {
    pub(super) fn applied(&self) -> Option<AppliedBrowser> {
        let text = read_text(&self.applied_path, APPLIED_LIMIT).ok()?;
        serde_json::from_str(&text).ok()
    }
}

struct Image {
    path: PathBuf,
    sha256: String,
    metadata: Metadata,
}

impl Image {
    fn read(path: &Path) -> io::Result<Self> {
        // Hash the file, never execute it. Leave time for document validation and
        // output before the runner's ten-second wall-clock deadline.
        let deadline = Instant::now() + Duration::from_secs(8);
        let mut file = open_regular(path)?;
        let metadata = file.metadata()?;
        let mut hasher = Sha256::new();
        let mut buffer = [0; 64 * 1024];
        loop {
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
        let image = Self {
            path: path.to_owned(),
            sha256: format!("{:x}", hasher.finalize()),
            metadata,
        };
        if !image.unchanged() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(image)
    }

    fn unchanged(&self) -> bool {
        fs::symlink_metadata(&self.path).is_ok_and(|metadata| same_file(&self.metadata, &metadata))
    }
}

fn same_file(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.mode() == after.mode()
        && before.size() == after.size()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

#[derive(Clone, Copy)]
pub(super) enum ImageTrust {
    System,
    #[cfg(test)]
    Fixture,
}

impl ImageTrust {
    fn allows(self, path: &Path) -> bool {
        match self {
            Self::System => trusted_image(path),
            #[cfg(test)]
            Self::Fixture => true,
        }
    }
}

fn trusted_image(path: &Path) -> bool {
    // Check every component without accepting symlinks. The observed image is
    // a resolved path; a symlink at any component means the tree was replaced.
    path.is_absolute()
        && fs::canonicalize(path).is_ok_and(|resolved| resolved == path)
        && path.ancestors().enumerate().all(|(depth, component)| {
            fs::symlink_metadata(component).is_ok_and(|metadata| {
                metadata.uid() == 0
                    && (if depth == 0 {
                        metadata.is_file()
                    } else {
                        metadata.is_dir()
                    })
                    && accessat(CWD, component, Access::WRITE_OK, AtFlags::EACCESS)
                        == Err(Errno::ACCESS)
            })
        })
}

pub(super) struct IdentityFinding {
    pub(super) finding: Finding,
    image: Option<Image>,
}

pub(super) fn identity_finding(
    settings: &BrowserSettings,
    applied: Option<&AppliedBrowser>,
    trust: ImageTrust,
) -> Option<IdentityFinding> {
    let pin = settings
        .expected_identity
        .as_deref()
        .filter(|pin| pin.len() == 64 && pin.bytes().all(|byte| byte.is_ascii_hexdigit()))?;
    let no_plan = |summary: &str, evidence| IdentityFinding {
        finding: finding(
            IDENTITY_CHANGED,
            Severity::Error,
            summary,
            evidence,
            Fix::none(false),
        ),
        image: None,
    };
    let Some((applied, final_path)) = applied
        .filter(|state| state.executable_path == settings.executable_path)
        .and_then(|state| Some((state, state.final_image_path.as_deref()?)))
        .filter(|(_, path)| path.is_absolute())
    else {
        return Some(no_plan(
            RESTART_TO_IDENTIFY,
            vec![code("applied_state", "unknown")],
        ));
    };
    let Ok(image) = Image::read(final_path) else {
        return Some(no_plan(
            RESTART_TO_IDENTIFY,
            vec![code("applied_state", "unknown")],
        ));
    };
    let path_evidence = |name: &str, path: &Path| {
        Evidence::new(
            name,
            EvidenceValue::Path {
                category: PathCategory::Other,
                path: path.to_string_lossy().into_owned(),
            },
        )
    };
    let ref_evidence = |name: &str, value: &str| {
        Evidence::new(name, EvidenceValue::Ref(value.to_owned())).expect("valid digest evidence")
    };
    let mut evidence = vec![ref_evidence("observed_digest", &image.sha256)];
    let Ok(path) = path_evidence("final_image_path", final_path) else {
        return Some(no_plan(
            RESTART_TO_IDENTIFY,
            vec![code("applied_state", "unknown")],
        ));
    };
    evidence.push(path);
    if image.sha256.eq_ignore_ascii_case(pin) {
        return (!applied
            .expected_identity
            .as_ref()
            .is_some_and(|old| old.eq_ignore_ascii_case(pin)))
        .then(|| no_plan(PIN_NOT_IN_USE, evidence));
    }
    if !trust.allows(final_path) || !image.unchanged() {
        return Some(no_plan(UNSAFE, evidence));
    }
    // These also bind the settings the person approved changing, not just the
    // target digest. A concurrent edit to either setting invalidates the fix.
    let Ok(launcher) = path_evidence("executable_path", settings.executable_path.as_deref()?)
    else {
        return Some(no_plan(
            RESTART_TO_IDENTIFY,
            vec![code("applied_state", "unknown")],
        ));
    };
    evidence.push(launcher);
    evidence.push(ref_evidence("previous_digest", pin));
    let id = FindingId::new(IDENTITY_CHANGED).expect("fixed doctor id");
    let fix = Fix::safe(
        &id,
        false,
        vec!["Pin the Chrome program now installed as the agent browser.".to_owned()],
        10_000,
    )
    .expect("valid browser re-pin plan");
    Some(IdentityFinding {
        finding: Finding::new(id, Severity::Error, CHANGED, evidence, fix)
            .expect("valid browser finding"),
        image: Some(image),
    })
}

fn applies(applied: Option<&AppliedBrowser>) -> Evidence {
    code(
        "applies",
        match applied {
            Some(applied) if applied.stamped => "awaiting_approval",
            Some(_) => "module_restart",
            None => "unknown",
        },
    )
}

#[cfg(test)]
mod tests;
