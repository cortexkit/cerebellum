use super::*;

use std::io::Write;
use std::os::unix::fs::PermissionsExt;

use rustix::fs::{flock, FlockOperation};

#[derive(Debug)]
enum EditError {
    Busy,
    Changed,
    Io,
}

impl From<io::Error> for EditError {
    fn from(_: io::Error) -> Self {
        Self::Io
    }
}

impl Doctor {
    pub(in crate::doctor) fn check_edit_lock(
        &self,
        finding: &Finding,
    ) -> Result<(), PreflightError> {
        if finding.id().as_str() != IDENTITY_CHANGED {
            return Err(PreflightError::Failed);
        }
        lock_settings(&self.config_path)
            .map(drop)
            .map_err(|error| match error {
                EditError::Busy => PreflightError::FilesInUse,
                _ => PreflightError::Failed,
            })
    }

    pub(in crate::doctor) fn apply(&self, confirmed: Finding, trust: ImageTrust) -> FixOutcome {
        match self.apply_checked(confirmed, trust) {
            Ok(evidence) => FixOutcome::fixed(vec![evidence]).expect("valid browser fix outcome"),
            Err(EditError::Busy) => FixOutcome::refused(FixRefusal::FilesInUse),
            Err(EditError::Changed) => FixOutcome::refused(FixRefusal::PlanChanged),
            Err(EditError::Io) => fix_failed(),
        }
    }

    fn apply_checked(&self, confirmed: Finding, trust: ImageTrust) -> Result<Evidence, EditError> {
        let file = lock_settings(&self.config_path)?;
        let metadata = file.metadata()?;
        let original = read_open_text(&file, CONFIG_LIMIT)?;
        let settings = BrowserSettings::parse(&original).map_err(|_| EditError::Changed)?;
        let applied = self.applied();
        // Before calling a fix, `cortexkit_doctor::module::run` rechecks only the
        // finding's summary and plan, not its evidence (the new digest). So
        // recompute the whole finding here, under the file lock, and require it
        // to equal the one the person confirmed.
        let current =
            identity_finding(&settings, applied.as_ref(), trust).ok_or(EditError::Changed)?;
        let image = current
            .image
            .filter(|_| current.finding == confirmed)
            .ok_or(EditError::Changed)?;
        let pin = settings
            .expected_identity
            .as_deref()
            .ok_or(EditError::Changed)?;
        let edited = replace_pin(&original, pin, &image.sha256).ok_or(EditError::Changed)?;
        replace_settings(&self.config_path, &metadata, &edited, || {
            // When the person declines a settings change, the daemon restores
            // the previous document if the bytes still match what it reviewed,
            // without taking any file lock. Recheck our snapshot before replacing the
            // file so we don't knowingly overwrite that restore or an editor's save.
            image.unchanged()
                && trust.allows(&image.path)
                && open_regular(&self.config_path).is_ok_and(|current| {
                    current
                        .metadata()
                        .is_ok_and(|now| same_file(&metadata, &now))
                        && read_open_text(&current, CONFIG_LIMIT).is_ok_and(|text| text == original)
                        && fs::symlink_metadata(&self.config_path)
                            .is_ok_and(|now| same_file(&metadata, &now))
                })
        })?;
        drop(file);
        Ok(applies(applied.as_ref()))
    }
}

fn lock_settings(path: &Path) -> Result<File, EditError> {
    let file = open_regular(path).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::InvalidData => EditError::Changed,
        _ => EditError::Io,
    })?;
    match flock(&file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(file),
        Err(Errno::WOULDBLOCK) => Err(EditError::Busy),
        Err(_) => Err(EditError::Io),
    }
}

fn replace_settings(
    path: &Path,
    metadata: &Metadata,
    edited: &str,
    still_current: impl FnOnce() -> bool,
) -> Result<(), EditError> {
    let directory = path.parent().ok_or(EditError::Io)?;
    let directory_handle = File::open(directory)?;
    let mut nonce = [0; 16];
    getrandom::getrandom(&mut nonce).map_err(|_| EditError::Io)?;
    let temporary = directory.join(format!(
        ".cerebellum-doctor-{:032x}.tmp",
        u128::from_ne_bytes(nonce)
    ));
    let mut file = cerebellum_core::private_fs::create_new_file(&temporary)?;
    let result = (|| {
        file.write_all(edited.as_bytes())?;
        file.set_permissions(fs::Permissions::from_mode(metadata.mode() & 0o7777))?;
        file.sync_all()?;
        if !still_current() {
            return Err(EditError::Changed);
        }
        fs::rename(&temporary, path)?;
        directory_handle.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn replace_pin(text: &str, old: &str, new: &str) -> Option<String> {
    // The shared JSONC parser locates the member, including separators. Walk
    // only its key and value tokens so that comments inside the member survive.
    let span = subc_jsonc::jsonc_member_span(text, &["browser", "expected_identity"]).ok()??;
    let member = trivia(&text[span.clone()])?;
    let key = trivia(member.strip_prefix(',').unwrap_or(member))?;
    let (_, key_len) = string_token(key)?;
    let colon = trivia(&key[key_len..])?;
    let literal = trivia(colon.strip_prefix(':')?)?;
    let (value, value_len) = string_token(literal)?;
    if value != old {
        return None;
    }
    let start = span.end - literal.len();
    let mut edited = text.to_owned();
    edited.replace_range(start..start + value_len, &serde_json::to_string(new).ok()?);
    Some(edited)
}

fn string_token(text: &str) -> Option<(String, usize)> {
    let mut tokens = serde_json::Deserializer::from_str(text).into_iter::<String>();
    let value = tokens.next()?.ok()?;
    Some((value, tokens.byte_offset()))
}

fn trivia(mut text: &str) -> Option<&str> {
    loop {
        text = text.trim_start_matches([' ', '\t', '\r', '\n']);
        if let Some(comment) = text.strip_prefix("//") {
            text = comment.split_once('\n')?.1;
        } else if let Some(comment) = text.strip_prefix("/*") {
            text = comment.split_once("*/")?.1;
        } else {
            return Some(text);
        }
    }
}
