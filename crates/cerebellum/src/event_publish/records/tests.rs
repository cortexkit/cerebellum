use cortexkit_role_tool_display::DisplayKind;
use cortexkit_test_support::ScratchDir;

use super::*;

fn write(key: &str) -> (String, Vec<u8>) {
    let write = DisplayWrite::new(
        subc_protocol::Principal::Reserved {
            module_id: "thalamus-harness".into(),
        },
        key,
        DisplayKind::Record,
        "served-pin",
        json!({"outcome":"success", "plane":"browser", "action":"status", "durationMs":12, "queuedMs":0})
            .as_object().unwrap().clone(),
    );
    (
        display_identity(&write).unwrap(),
        serde_json::to_vec(&write).unwrap(),
    )
}

fn insert(records: &mut Records, key: &str, gauges: &Gauges) -> (String, bool) {
    let (id, bytes) = write(key);
    let now = records.now();
    let stored = records.insert(id.clone(), bytes, now, gauges).unwrap();
    (id, stored)
}

fn read(records: &mut Records, id: &str, gauges: &Gauges) -> Option<Vec<u8>> {
    records.read(id, records.now(), gauges).unwrap()
}

#[tokio::test(start_paused = true)]
async fn confirmed_display_record_expires_ten_minutes_after_first_read_across_restart() {
    let scratch = ScratchDir::new("display-confirmed-retention");
    let directory = scratch.path().join("display-records");
    let gauges = Gauges::default();
    let mut records = Records::open(directory.clone(), &gauges);
    let (id, stored) = insert(&mut records, "confirmed", &gauges);
    assert!(stored);
    tokio::time::advance(Duration::from_secs(15 * 60)).await;
    assert!(
        read(&mut records, &id, &gauges).is_some(),
        "read after a 15 minute outage"
    );
    let now = records.now();
    drop(records);
    let mut restarted = Records::open_at(directory, &gauges, now);
    tokio::time::advance(Duration::from_millis(CONFIRMED_MS - 1)).await;
    assert!(read(&mut restarted, &id, &gauges).is_some());
    assert!(
        insert(&mut restarted, "confirmed", &gauges).1,
        "a duplicate write preserves the first confirmation"
    );
    tokio::time::advance(Duration::from_millis(1)).await;
    assert!(read(&mut restarted, &id, &gauges).is_none());
    assert!(!restarted.path(&id).unwrap().exists());
    assert_eq!(gauges.display_held.load(Relaxed), 0);
}

#[tokio::test(start_paused = true)]
async fn unread_display_record_expires_after_twenty_four_hours() {
    let scratch = ScratchDir::new("display-unread-retention");
    let gauges = Gauges::default();
    let mut records = Records::open(scratch.path().join("display-records"), &gauges);
    let (id, stored) = insert(&mut records, "unread", &gauges);
    assert!(stored);
    tokio::time::advance(Duration::from_millis(UNREAD_MS - 1)).await;
    records.expire(records.now(), &gauges).unwrap();
    assert!(records.path(&id).unwrap().is_file());
    tokio::time::advance(Duration::from_millis(1)).await;
    assert!(read(&mut records, &id, &gauges).is_none());
    assert!(!records.path(&id).unwrap().exists());
}

#[tokio::test(start_paused = true)]
async fn disk_count_and_byte_bounds_preserve_protected_records() {
    let scratch = ScratchDir::new("display-disk-capacity");
    let sample_size = HEADER_BYTES + write("a").1.len();
    for (index, max_count, max_bytes) in [(1, 1, 2 * sample_size), (2, 2, sample_size)] {
        let gauges = Gauges::default();
        let directory = scratch.path().join(index.to_string());
        let mut records = Records {
            directory: Some(directory.clone()),
            ..Records::with_limits(max_count, max_bytes)
        };
        let (a, stored) = insert(&mut records, "a", &gauges);
        assert!(stored);
        tokio::time::advance(Duration::from_millis(UNREAD_MS - 1)).await;
        let (b, stored) = insert(&mut records, "b", &gauges);
        assert!(!stored);
        assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
        assert_eq!(
            fs::metadata(records.path(&a).unwrap()).unwrap().len(),
            sample_size as u64
        );
        assert!(!records.path(&b).unwrap().exists());
        assert!(read(&mut records, &a, &gauges).is_some());
        tokio::time::advance(Duration::from_millis(CONFIRMED_MS - 1)).await;
        assert!(
            !insert(&mut records, "b", &gauges).1,
            "read record remains protected"
        );
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(insert(&mut records, "b", &gauges).1);
        assert!(!records.path(&a).unwrap().exists());
        assert!(records.path(&b).unwrap().is_file());
    }
}

#[test]
fn startup_skips_damaged_display_file_and_loads_healthy_neighbor() {
    let scratch = ScratchDir::new("display-damaged-startup");
    let directory = scratch.path().join("display-records");
    let gauges = Gauges::default();
    assert!(!directory.exists(), "opening the store does not create it");
    let mut records = Records::open(directory.clone(), &gauges);
    assert!(!directory.exists());
    let (damaged, stored) = insert(&mut records, "damaged", &gauges);
    assert!(stored);
    let (invalid, stored) = insert(&mut records, "invalid-envelope", &gauges);
    assert!(stored);
    let (healthy, stored) = insert(&mut records, "healthy", &gauges);
    assert!(stored);
    fs::write(records.path(&damaged).unwrap(), b"torn record").unwrap();
    let invalid_path = records.path(&invalid).unwrap();
    let mut contents = fs::read(&invalid_path).unwrap();
    assert_eq!(contents.pop(), Some(b'}'));
    contents.extend_from_slice(br#", "unexpected": "must not be sent"}"#);
    fs::write(invalid_path, contents).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(records.path(&healthy).unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    drop(records);
    let mut loaded = Records::open(directory, &gauges);
    assert_eq!(gauges.display_damaged.load(Relaxed), 2);
    assert_eq!(gauges.display_loaded.load(Relaxed), 1);
    assert_eq!(gauges.display_held.load(Relaxed), 1);
    assert!(read(&mut loaded, &damaged, &gauges).is_none());
    assert!(read(&mut loaded, &invalid, &gauges).is_none());
    assert_eq!(
        read(&mut loaded, &healthy, &gauges),
        Some(write("healthy").1)
    );
}
