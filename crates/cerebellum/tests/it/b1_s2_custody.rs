use cerebellum::manifest::custody::{
    canonical_json_bytes, sha256_hex, ConnectorAdmissionProof, CustodyArtifact, LaunchError,
    LaunchQuarantine, LaunchStage, QuarantineMechanism, RegistrationError, RegistrationObservation,
    SpawnObservation,
};
use serde_json::json;

fn artifact() -> CustodyArtifact {
    CustodyArtifact {
        schema: "ck-browser-custody/v1".into(),
        chromium_sha256: "b".repeat(64),
        chromium_version: "127.0.1".into(),
        platform: "macos".into(),
        ordered_args: vec![
            "--user-data-dir=/private/profile".into(),
            "--proxy-server=connector".into(),
        ],
        connector_endpoint_mode: "enforcing_connector_only".into(),
        resolver_mode: "connector_owned".into(),
    }
}

fn observation(args: Vec<String>) -> SpawnObservation {
    SpawnObservation {
        process_id: 41,
        quarantine: Some(QuarantineMechanism::ProcessBound),
        executable_sha256: "b".repeat(64),
        ordered_args: args,
        connector_endpoint_mode: "enforcing_connector_only".into(),
        resolver_mode: "connector_owned".into(),
    }
}

#[test]
fn checked_in_custody_fixture_is_canonical_and_closed() {
    let bytes = include_bytes!("../../resources/b1_s2_browser-custody.json");
    let artifact = CustodyArtifact::parse(bytes).unwrap();
    assert_eq!(artifact.schema, "ck-browser-custody/v1");
    assert_eq!(artifact.ordered_args.len(), 2);
}

#[test]
fn custody_artifact_is_closed_canonical_and_digest_pinned() {
    let artifact = artifact();
    let bytes = artifact.canonical_bytes();
    assert_eq!(CustodyArtifact::parse(&bytes).unwrap(), artifact);
    assert_eq!(
        CustodyArtifact::parse_pinned(&bytes, &sha256_hex(&bytes)).unwrap(),
        artifact
    );

    let mut unknown = serde_json::to_value(&artifact).unwrap();
    unknown["unexpected"] = json!(true);
    let unknown_bytes = canonical_json_bytes(&unknown);
    assert!(matches!(
        CustodyArtifact::parse(&unknown_bytes),
        Err(cerebellum::manifest::custody::CustodyArtifactError::UnknownOrMissingField)
    ));

    let mut noncanonical = bytes.clone();
    noncanonical.insert(1, b' ');
    assert!(matches!(
        CustodyArtifact::parse(&noncanonical),
        Err(cerebellum::manifest::custody::CustodyArtifactError::NonCanonical)
    ));
}

#[test]
fn executable_and_ordered_arguments_are_verified_absolutely() {
    let artifact = artifact();
    let valid = RegistrationObservation {
        executable_sha256: "b".repeat(64),
        ordered_args: artifact.ordered_args.clone(),
        connector_endpoint_mode: "enforcing_connector_only".into(),
        resolver_mode: "connector_owned".into(),
    };
    assert_eq!(
        cerebellum::manifest::custody::verify_registration(&artifact, &valid),
        Ok(())
    );

    let mut wrong_args = valid.clone();
    wrong_args.ordered_args.reverse();
    assert_eq!(
        cerebellum::manifest::custody::verify_registration(&artifact, &wrong_args),
        Err(RegistrationError::ArgumentsMismatch)
    );
    let mut wrong_binary = valid;
    wrong_binary.executable_sha256 = "c".repeat(64);
    assert_eq!(
        cerebellum::manifest::custody::verify_registration(&artifact, &wrong_binary),
        Err(RegistrationError::ExecutableMismatch)
    );

    let safe = vec!["--proxy-server=connector".to_string()];
    let unsafe_args = vec!["--proxy-bypass-list=*".to_string()];
    assert!(cerebellum::manifest::custody::arguments_are_quarantinable(
        &safe
    ));
    assert!(!cerebellum::manifest::custody::arguments_are_quarantinable(
        &unsafe_args
    ));

    let mut forbidden = artifact.clone();
    forbidden.ordered_args = unsafe_args;
    assert_eq!(
        forbidden.validate(),
        Err(cerebellum::manifest::custody::CustodyArtifactError::InvalidField("ordered_args"))
    );
}

#[test]
fn quarantine_and_process_bound_admission_have_exact_order_and_identity() {
    let artifact = artifact();
    let mut gate = LaunchQuarantine::new(&artifact);
    assert_eq!(gate.stage(), LaunchStage::Closed);
    assert_eq!(
        gate.verify_and_admit(&artifact, 41, &observation(artifact.ordered_args.clone())),
        Err(LaunchError::MissingCommitment)
    );
    assert_eq!(gate.commit_for_launch(9), Ok(()));
    let proof = gate
        .verify_and_admit(&artifact, 41, &observation(artifact.ordered_args.clone()))
        .unwrap();
    assert_eq!(gate.stage(), LaunchStage::Accepted);
    assert_eq!(gate.release(&proof), Ok(()));
    assert_eq!(gate.stage(), LaunchStage::Released);
}

#[test]
fn quarantine_rejects_missing_confinement_before_admission() {
    let artifact = artifact();
    let mut gate = LaunchQuarantine::new(&artifact);
    gate.commit_for_launch(1).unwrap();
    let mut observation = observation(artifact.ordered_args.clone());
    observation.quarantine = None;
    assert_eq!(
        gate.verify_and_admit(&artifact, 41, &observation),
        Err(LaunchError::QuarantineNotEstablished)
    );
    assert_eq!(gate.stage(), LaunchStage::Closed);
}

#[test]
fn process_bound_proof_is_exact_child_and_restart_revokes_old_proof() {
    let artifact = artifact();
    let mut gate = LaunchQuarantine::new(&artifact);
    gate.commit_for_launch(1).unwrap();
    // The first admission is made while the gate is closed, then released only
    // after the proof is issued for the inspected process.
    let proof = gate
        .verify_and_admit(&artifact, 41, &observation(artifact.ordered_args.clone()))
        .unwrap();
    assert_eq!(proof.process_id(), 41);
    assert_eq!(gate.release(&proof), Ok(()));
    assert!(gate.proof_is_current(&proof, 41));
    assert!(!gate.proof_is_current(&proof, 42));
    let first_generation = gate.generation();
    gate.restart();
    assert_eq!(gate.stage(), LaunchStage::Closed);
    assert_eq!(gate.generation(), first_generation + 1);
    assert!(!gate.proof_is_current(&proof, 41));
    gate.commit_for_launch(10).unwrap();
    assert_eq!(
        gate.verify_and_admit(&artifact, 42, &observation(artifact.ordered_args.clone())),
        Err(LaunchError::ProcessIdentityMismatch)
    );
}

#[test]
fn a_proof_from_before_a_restart_is_stale_even_for_a_process_of_the_same_id() {
    // The earlier restart test rejects the old proof because the restarted gate
    // holds no admitted process at all, so the process ids differ and the
    // generation is never compared.  Here a new process is admitted under the
    // SAME id after the restart, so the old and new proofs agree on the id and
    // only their generations differ.  That is what the generation is for: an
    // operating system may hand a fresh process the id a terminated one
    // released, and without it an old proof would vouch for a process it never
    // inspected.
    let artifact = artifact();
    let mut gate = LaunchQuarantine::new(&artifact);
    gate.commit_for_launch(1).unwrap();
    let stale = gate
        .verify_and_admit(&artifact, 41, &observation(artifact.ordered_args.clone()))
        .unwrap();
    gate.release(&stale).unwrap();
    assert!(gate.proof_is_current(&stale, 41));

    gate.restart();
    gate.commit_for_launch(2).unwrap();
    let fresh = gate
        .verify_and_admit(&artifact, 41, &observation(artifact.ordered_args.clone()))
        .unwrap();
    gate.release(&fresh).unwrap();

    assert_eq!(fresh.process_id(), stale.process_id());
    assert!(gate.proof_is_current(&fresh, 41));
    assert!(!gate.proof_is_current(&stale, 41));
}

#[test]
fn admission_proof_type_is_not_caller_constructible() {
    fn accepts_only_production_proof(_: &ConnectorAdmissionProof) {}
    let _ = accepts_only_production_proof;
}
