#[test]
fn bus_names_used_by_cerebellum_are_pinned() {
    use cortexkit_bus_naming::{AccountNames, EVENT_CONSUMERS, MODULE_BUCKETS};

    let names = AccountNames::derive("test").unwrap();
    assert_eq!(names.streams().event, "CK_TEST_EVENT");
    assert_eq!(
        names
            .live_subject("thalamus-harness", "turn_started", 1)
            .unwrap(),
        "ck.test.live.thalamus-harness.turn_started.v1"
    );
    assert_eq!(
        names
            .live_subject("thalamus-harness", "turn_ended", 1)
            .unwrap(),
        "ck.test.live.thalamus-harness.turn_ended.v1"
    );
    let consumers: Vec<_> = EVENT_CONSUMERS
        .iter()
        .filter(|entry| entry.module_id == "cerebellum")
        .collect();
    assert_eq!(consumers.len(), 1);
    assert_eq!(consumers[0].durable_name().unwrap(), "m_cerebellum");
    assert_eq!(
        consumers[0].filter_subjects,
        [
            "event.thalamus-harness.turn_started.v1",
            "event.thalamus-harness.turn_ended.v1",
        ]
    );
    for (reader, subject) in [
        (
            "broca",
            "ck.test.event.cerebellum.late_result_ready.v1.broca",
        ),
        (
            "prefrontal-core",
            "ck.test.event.cerebellum.late_result_ready.v1.prefrontal-core",
        ),
        (
            "prefrontal",
            "ck.test.event.cerebellum.late_result_ready.v1.prefrontal",
        ),
        (
            "thalamus-harness",
            "ck.test.event.cerebellum.late_result_ready.v1.thalamus-harness",
        ),
    ] {
        assert_eq!(
            super::Kind::LateResultReady {
                custodian_module: Some(reader.to_owned()),
            }
            .subject("test")
            .unwrap(),
            subject
        );
    }
    assert_eq!(
        super::Kind::DisplayRecordReady.subject("test").unwrap(),
        "ck.test.event.cerebellum.display_record_ready.v1"
    );
    let buckets: Vec<_> = MODULE_BUCKETS
        .iter()
        .filter(|bucket| bucket.owner == "cerebellum" && bucket.name == "views")
        .collect();
    assert_eq!(buckets.len(), 1);
    assert_eq!(
        names
            .module_bucket_name(buckets[0].owner, buckets[0].name)
            .unwrap(),
        "CK_TEST_CEREBELLUM_VIEWS"
    );
}
