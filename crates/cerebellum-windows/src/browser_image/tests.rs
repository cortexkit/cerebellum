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
