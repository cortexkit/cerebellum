use super::*;

use std::os::unix::fs::PermissionsExt;

use cortexkit_doctor::FixClass;
use rustix::fs::{flock, FlockOperation};

struct Fixture {
    root: PathBuf,
    doctor: Doctor,
    launcher: PathBuf,
    image: PathBuf,
    pin: String,
}

impl Fixture {
    fn new(stamped: bool) -> Self {
        let mut nonce = [0; 16];
        getrandom::getrandom(&mut nonce).unwrap();
        let root = PathBuf::from(format!(
            "/tmp/cerebellum-doctor-test-{:032x}",
            u128::from_ne_bytes(nonce)
        ));
        cerebellum_core::private_fs::create_dir(&root).unwrap();
        let launcher = root.join("launcher");
        let image = root.join("chrome");
        fs::copy("/bin/sleep", &image).unwrap();
        fs::set_permissions(&image, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(
            &launcher,
            format!(
                "#!/bin/sh\ntouch '{}'\nexec '{}' 30\n",
                root.join("executed").display(),
                image.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&launcher, fs::Permissions::from_mode(0o700)).unwrap();
        let pin = digest(&image);
        let doctor = Doctor::new(&root.join("config"), &root.join("data"));
        fs::create_dir_all(doctor.config_path.parent().unwrap()).unwrap();
        fs::write(&doctor.config_path, config(&launcher, &pin)).unwrap();
        fs::set_permissions(&doctor.config_path, fs::Permissions::from_mode(0o640)).unwrap();
        let fixture = Self {
            root,
            doctor,
            launcher,
            image,
            pin,
        };
        fixture.record(stamped, &fixture.pin);
        fixture
    }

    fn record(&self, stamped: bool, pin: &str) {
        AppliedBrowser {
            stamped,
            executable_path: Some(self.launcher.clone()),
            expected_identity: Some(pin.to_owned()),
            final_image_path: Some(self.image.clone()),
        }
        .write(&self.doctor.applied_path)
        .unwrap();
    }

    fn modify(&self, tail: &[u8]) -> String {
        let mut bytes = fs::read("/bin/sleep").unwrap();
        bytes.extend_from_slice(tail);
        fs::write(&self.image, bytes).unwrap();
        digest(&self.image)
    }

    fn confirm_fixture(&self) -> Finding {
        let text = fs::read_to_string(&self.doctor.config_path).unwrap();
        let finding = identity_finding(
            &BrowserSettings::parse(&text).unwrap(),
            self.doctor.applied().as_ref(),
            ImageTrust::Fixture,
        )
        .unwrap()
        .finding;
        assert_eq!(finding.fix().class(), FixClass::Safe);
        finding
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

fn digest(path: &Path) -> String {
    format!("{:x}", Sha256::digest(fs::read(path).unwrap()))
}

fn config(launcher: &Path, pin: &str) -> String {
    format!(
        r#"// expected_identity is an unrelated comment
{{
  "unrelated": {{ "expected_identity": "{pin}" }},
  "browser": {{
    "executable_path": "{}", /* after previous separator */
    "expected_\u0069dentity" /* before colon */ : /* before value π */ "{pin}", // after value
  }},
}}
"#,
        launcher.display()
    )
}

#[test]
fn a_changed_image_is_diagnosed_and_the_fix_changes_only_the_pin() {
    let fixture = Fixture::new(false);
    assert!(fixture.doctor.check().unwrap().is_empty());
    let next_pin = fixture.modify(b"first update");
    let confirmed = fixture.confirm_fixture();
    assert_eq!(
        confirmed.evidence()[0].value(),
        &EvidenceValue::Ref(next_pin.clone())
    );
    assert_eq!(
        confirmed.evidence()[1].value(),
        &EvidenceValue::Path {
            category: PathCategory::Other,
            path: fixture.image.to_str().unwrap().to_owned(),
        }
    );
    assert!(!confirmed
        .summary()
        .contains(fixture.image.to_str().unwrap()));
    let output = fixture.doctor.apply(confirmed, ImageTrust::Fixture);
    assert_eq!(
        output,
        FixOutcome::fixed(vec![code("applies", "module_restart")]).unwrap()
    );
    let expected = config(&fixture.launcher, &fixture.pin).replace(
        &format!("/* before value π */ \"{}\"", fixture.pin),
        &format!("/* before value π */ \"{next_pin}\""),
    );
    assert_eq!(
        fs::read_to_string(&fixture.doctor.config_path).unwrap(),
        expected
    );
    assert_eq!(
        fs::metadata(&fixture.doctor.config_path).unwrap().mode() & 0o777,
        0o640
    );
    let findings = fixture.doctor.check().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].summary(), PIN_NOT_IN_USE);
    assert_eq!(findings[0].fix().class(), FixClass::None);
    fixture.record(false, &next_pin);
    assert!(fixture.doctor.check().unwrap().is_empty());
    assert!(
        !fixture.root.join("executed").exists(),
        "doctor ran the configured launcher"
    );
}

#[test]
fn fix_refuses_if_the_confirmed_digest_changed() {
    let fixture = Fixture::new(false);
    fixture.modify(b"first update");
    let confirmed = fixture.confirm_fixture();
    fixture.modify(b"second update");
    let before = fs::metadata(&fixture.doctor.config_path).unwrap();
    assert_eq!(
        fixture.doctor.apply(confirmed, ImageTrust::Fixture),
        FixOutcome::refused(FixRefusal::PlanChanged)
    );
    assert_eq!(
        fs::read_to_string(&fixture.doctor.config_path).unwrap(),
        config(&fixture.launcher, &fixture.pin)
    );
    assert_eq!(
        fs::metadata(&fixture.doctor.config_path).unwrap().ino(),
        before.ino()
    );
}

#[test]
fn a_user_writable_image_is_never_offered_a_fix() {
    let fixture = Fixture::new(false);
    fixture.modify(b"first update");
    let findings = fixture.doctor.check().unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id().as_str(), IDENTITY_CHANGED);
    assert_eq!(findings[0].fix().class(), FixClass::None);
    assert!(findings[0].fix().plan().is_none());
    assert!(findings[0]
        .summary()
        .contains("can be changed by your account"));
    let confirmed = fixture.confirm_fixture();
    assert_eq!(
        fixture.doctor.fix(confirmed),
        FixOutcome::refused(FixRefusal::PlanChanged)
    );
}

#[test]
fn fix_refuses_if_another_process_holds_a_settings_lock() {
    let fixture = Fixture::new(true);
    fixture.modify(b"first update");
    let confirmed = fixture.confirm_fixture();
    let locked = open_regular(&fixture.doctor.config_path).unwrap();
    flock(&locked, FlockOperation::NonBlockingLockExclusive).unwrap();
    assert_eq!(
        fixture.doctor.preflight(&confirmed),
        Err(PreflightError::FilesInUse)
    );
    assert_eq!(
        fixture.doctor.apply(confirmed.clone(), ImageTrust::Fixture),
        FixOutcome::refused(FixRefusal::FilesInUse)
    );
    assert_eq!(
        fs::read_to_string(&fixture.doctor.config_path).unwrap(),
        config(&fixture.launcher, &fixture.pin)
    );
    drop(locked);
    assert_eq!(
        fixture.doctor.apply(confirmed, ImageTrust::Fixture),
        FixOutcome::fixed(vec![code("applies", "awaiting_approval")]).unwrap()
    );
}

#[test]
fn a_missing_record_or_moved_image_requires_restart_to_identify() {
    let fixture = Fixture::new(false);
    assert_eq!(
        fs::metadata(&fixture.doctor.applied_path).unwrap().mode() & 0o777,
        0o600
    );
    fs::remove_file(&fixture.doctor.applied_path).unwrap();
    assert_eq!(
        applies(fixture.doctor.applied().as_ref()).value(),
        &EvidenceValue::Code("unknown".to_owned())
    );
    for moved_image in [false, true] {
        if moved_image {
            fixture.record(false, &fixture.pin);
            fs::rename(&fixture.image, fixture.root.join("chrome-new-location")).unwrap();
        }
        let findings = fixture.doctor.check().unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].summary(), RESTART_TO_IDENTIFY);
        assert_eq!(findings[0].evidence(), [code("applied_state", "unknown")]);
        assert_eq!(findings[0].fix().class(), FixClass::None);
    }
    assert!(
        !fixture.root.join("executed").exists(),
        "doctor ran the configured launcher"
    );
}
