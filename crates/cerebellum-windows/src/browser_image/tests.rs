use super::*;
use crate::{file_identity, retain_process_handle_for_image};

#[test]
fn retained_process_image_and_trailer_reader_use_the_opened_file() {
    let process = retain_process_handle_for_image(std::process::id()).unwrap();
    let image = OpenedProcessImage::open(&process).unwrap();
    let running_exe = std::env::current_exe().unwrap();
    let direct = File::open(running_exe).unwrap();
    let original_path = image.final_path.clone();
    let file = image.into_file();
    assert_eq!(final_path(&file).unwrap(), original_path);
    assert_eq!(
        file_identity(&file).unwrap(),
        file_identity(&direct).unwrap()
    );
}

#[test]
#[ignore = "requires a Windows runner where the catalog service is already inactive"]
fn native_cmd_refuses_inactive_catalog_service() {
    let cmd_path = system_directory().unwrap().join("cmd.exe");
    let cmd = OpenedProcessImage::open_path(&cmd_path).unwrap();
    let error = verify_system_cmd(&cmd).unwrap_err();
    assert!(matches!(error, ImageRefusal::CatalogServiceInactive));
    assert_eq!(
        error.to_string(),
        "Windows' Cryptographic Services is not running"
    );
}

#[test]
#[ignore = "requires the real Chrome Stable installation on the GitHub-hosted Windows runner"]
fn native_system_and_chrome_signers_are_isolated() {
    let cmd_path = system_directory().unwrap().join("cmd.exe");
    let cmd = OpenedProcessImage::open_path(&cmd_path).unwrap();
    verify_system_cmd(&cmd).expect("System32 cmd.exe has a Microsoft-rooted catalog signature");

    let chrome_path = [w!("ProgramFilesDir"), w!("ProgramFilesDir (x86)")]
        .into_iter()
        .filter_map(|value| program_files_directory(value).ok())
        .map(|root| root.join(CHROME_RELATIVE))
        .find(|candidate| candidate.is_file())
        .expect("Chrome Stable is installed in Program Files");
    let chrome = OpenedProcessImage::open_path(&chrome_path).unwrap();
    verify_installed_chrome(&chrome).expect("installed Chrome Stable satisfies its predicate");

    assert!(matches!(
        verify_system_cmd(&chrome),
        Err(ImageRefusal::UnexpectedPath)
    ));
    assert!(matches!(
        verify_installed_chrome(&cmd),
        Err(ImageRefusal::UnexpectedPath)
    ));
    // Bypass only the path gate. Both must still refuse the other's signer.
    assert!(matches!(
        trust::verify_catalog(&chrome),
        Err(ImageRefusal::CatalogNotFound(_))
    ));
    assert!(matches!(
        trust::verify_chrome(&cmd),
        Err(ImageRefusal::TrustStateMissing(_)
            | ImageRefusal::Trust { .. }
            | ImageRefusal::SignerSubject)
    ));
}
