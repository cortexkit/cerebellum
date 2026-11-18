use cortexkit_bus_naming::{participant_permissions, AccountNames, Operation};

pub(super) const KEY_HEADER: &str = "Nats-Msg-Id";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Started,
    Ended,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Started => "turn_started",
            Self::Ended => "turn_ended",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ThalamusNotice {
    pub(crate) module: &'static str,
    pub(crate) agent: String,
    pub(crate) session: String,
    pub(crate) seq: u64,
    pub(crate) kind: Kind,
}

pub(crate) enum Notice {
    Thalamus(ThalamusNotice),
    Broca(BrocaNotice),
}

pub(crate) struct BrocaNotice {
    pub(crate) session: String,
    pub(crate) epoch: String,
    pub(crate) seq: u64,
    pub(crate) ended: bool,
}

pub(super) enum Delivery {
    Notice(Notice),
    BrocaMissingSession,
    BrocaInvalidSequence,
}

/// The modules that publish turn hints. Pi heads moved into `thalamus-harness`,
/// and the retired `thalamus-pi` lost its bus permissions. The server refuses a
/// subscription to a subject the credential doesn't grant, and that refusal
/// fails the whole open, so a retired publisher left in this list disables
/// every hint.
const PUBLISHERS: [&str; 1] = ["thalamus-harness"];
const BROCA_ENDED: &str = "run.ended";
const BROCA_EVENTS: [&str; 3] = ["run.started", "run.paused", BROCA_ENDED];

pub(super) fn subjects(names: &AccountNames, reader: &str) -> Result<Vec<String>, String> {
    // The inbox component is irrelevant: we only check exact raw EVENT
    // subscriptions, not inbox access, durable reads or `live.` grants.
    let grants =
        participant_permissions(names, "unused", reader, &[]).map_err(|error| error.to_string())?;
    subjects_with_grant(names, |subject| {
        grants
            .iter()
            .any(|grant| grant.operation == Operation::Subscribe && grant.subject == subject)
    })
}

fn subjects_with_grant(
    names: &AccountNames,
    can_subscribe: impl Fn(&str) -> bool,
) -> Result<Vec<String>, String> {
    let mut subjects = Vec::with_capacity(PUBLISHERS.len() * 2 + BROCA_EVENTS.len());
    for module in PUBLISHERS {
        for kind in [Kind::Started, Kind::Ended] {
            subjects.push(
                names
                    .live_subject(module, kind.name(), 1)
                    .map_err(|error| error.to_string())?,
            );
        }
    }
    for event in BROCA_EVENTS {
        let subject = names
            .event_subject("broca", event, 1)
            .map_err(|error| error.to_string())?;
        if can_subscribe(&subject) {
            subjects.push(subject);
        }
    }
    Ok(subjects)
}

impl Delivery {
    pub(super) fn parse<'a>(
        names: &AccountNames,
        subject: &str,
        header: impl Fn(&str) -> Option<&'a str>,
    ) -> Option<Self> {
        if let Ok(event) = names.parse_event_subject(subject) {
            if event.module != "broca"
                || event.version != 1
                || event.reader.is_some()
                || !BROCA_EVENTS.contains(&event.event.as_str())
            {
                return None;
            }
            let Some(session) = header("session").filter(|session| !session.is_empty()) else {
                return Some(Self::BrocaMissingSession);
            };
            // Broca's Nats-Msg-Id is a digest, not a sortable sequence.
            let epoch = header("epoch").filter(|epoch| !epoch.is_empty());
            let seq = header("seq").and_then(sequence);
            let (Some(epoch), Some(seq)) = (epoch, seq) else {
                return Some(Self::BrocaInvalidSequence);
            };
            return Some(Self::Notice(Notice::Broca(BrocaNotice {
                session: session.to_owned(),
                epoch: epoch.to_owned(),
                seq,
                ended: event.event == BROCA_ENDED,
            })));
        }
        ThalamusNotice::parse(
            names,
            subject,
            header(KEY_HEADER),
            header("agent"),
            header("session_ref"),
        )
        .map(|notice| Self::Notice(Notice::Thalamus(notice)))
    }
}

fn sequence(value: &str) -> Option<u64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let seq: u64 = value.parse().ok()?;
    (seq.to_string() == value).then_some(seq)
}

impl ThalamusNotice {
    /// The authenticated publisher owns the subject. Its headers identify the
    /// agent/session for presentation; they do not authorize any action.
    pub(super) fn parse(
        names: &AccountNames,
        subject: &str,
        id: Option<&str>,
        agent: Option<&str>,
        session: Option<&str>,
    ) -> Option<Self> {
        let agent = agent.filter(|agent| !agent.is_empty())?;
        let session = session.filter(|session| {
            session.len() == 32
                && session
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        })?;
        let mut key = id?.split(':');
        if key.next()? != session {
            return None;
        }
        let event = key.next()?;
        let seq = sequence(key.next()?)?;
        if key.next().is_some() {
            return None;
        }
        for module in PUBLISHERS {
            for kind in [Kind::Started, Kind::Ended] {
                if event == kind.name()
                    && names.live_subject(module, event, 1).ok()?.as_str() == subject
                {
                    return Some(Self {
                        module,
                        agent: agent.to_owned(),
                        session: session.to_owned(),
                        seq,
                        kind,
                    });
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_hint_vectors_pin_headers_and_keys() {
        let names = AccountNames::derive("test").unwrap();
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/vectors/harness-turn-hints-v1/live-hints.json"
        ))
        .unwrap();
        for vector in vectors.as_array().unwrap() {
            let headers = &vector["headers"];
            let notice = ThalamusNotice::parse(
                &names,
                vector["subject"].as_str().unwrap(),
                headers[KEY_HEADER].as_str(),
                headers["agent"].as_str(),
                headers["session_ref"].as_str(),
            );
            assert_eq!(notice.is_some(), vector["accepted"].as_bool().unwrap());
            if let Some(notice) = notice {
                assert_eq!(notice.seq, vector["seq"].as_u64().unwrap());
            }
        }
    }

    #[test]
    fn keys_are_strict_and_subjects_are_account_scoped() {
        let names = AccountNames::derive("test").unwrap();
        let session = "0123456789abcdef0123456789abcdef";
        let subject = names
            .live_subject("thalamus-harness", "turn_ended", 1)
            .unwrap();
        for suffix in ["", "-1", "+1", "01", "1:2", "18446744073709551616"] {
            let id = format!("{session}:turn_ended:{suffix}");
            assert!(
                ThalamusNotice::parse(&names, &subject, Some(&id), Some("a"), Some(session))
                    .is_none()
            );
        }
        let foreign = AccountNames::derive("other")
            .unwrap()
            .live_subject("thalamus-harness", "turn_ended", 1)
            .unwrap();
        let id = format!("{session}:turn_ended:1");
        assert!(
            ThalamusNotice::parse(&names, &foreign, Some(&id), Some("a"), Some(session)).is_none()
        );
        let retired = names.live_subject("thalamus-pi", "turn_ended", 1).unwrap();
        assert!(
            ThalamusNotice::parse(&names, &retired, Some(&id), Some("a"), Some(session)).is_none()
        );
    }

    #[test]
    fn pinned_grants_subscribe_cerebellum_to_all_broca_run_events() {
        let names = AccountNames::derive("test").unwrap();
        assert_eq!(
            subjects(&names, "cerebellum").unwrap(),
            [
                "ck.test.live.thalamus-harness.turn_started.v1",
                "ck.test.live.thalamus-harness.turn_ended.v1",
                "ck.test.event.broca.run.started.v1",
                "ck.test.event.broca.run.paused.v1",
                "ck.test.event.broca.run.ended.v1",
            ]
        );
    }

    #[test]
    fn an_end_only_grant_enables_just_broca_run_ends() {
        let names = AccountNames::derive("test").unwrap();
        let thalamus_only = subjects_with_grant(&names, |_| false).unwrap();
        assert_eq!(thalamus_only.len(), 2);
        let end = names.event_subject("broca", "run.ended", 1).unwrap();
        let end_only = subjects_with_grant(&names, |subject| subject == end).unwrap();
        assert_eq!(end_only, [thalamus_only, vec![end]].concat());
    }
}
