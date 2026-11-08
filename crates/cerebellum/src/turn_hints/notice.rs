use cortexkit_bus_naming::AccountNames;

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
pub(crate) struct Notice {
    pub(crate) module: &'static str,
    pub(crate) agent: String,
    pub(crate) session: String,
    pub(crate) seq: u64,
    pub(crate) kind: Kind,
}

/// The modules that publish turn hints. Pi heads moved into `thalamus-harness`,
/// and the retired `thalamus-pi` lost its bus permissions. The server refuses a
/// subscription to a subject the credential doesn't grant, and that refusal
/// fails the whole open, so a retired publisher left in this list disables
/// every hint.
const PUBLISHERS: [&str; 1] = ["thalamus-harness"];

pub(super) fn subjects(names: &AccountNames) -> Result<Vec<String>, String> {
    let mut subjects = Vec::with_capacity(PUBLISHERS.len() * 2);
    for module in PUBLISHERS {
        for kind in [Kind::Started, Kind::Ended] {
            subjects.push(
                names
                    .live_subject(module, kind.name(), 1)
                    .map_err(|error| error.to_string())?,
            );
        }
    }
    Ok(subjects)
}

impl Notice {
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
        let sequence = key.next()?;
        if key.next().is_some()
            || sequence.is_empty()
            || !sequence.bytes().all(|byte| byte.is_ascii_digit())
        {
            return None;
        }
        let seq: u64 = sequence.parse().ok()?;
        if seq.to_string() != sequence {
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
            let notice = Notice::parse(
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
            assert!(Notice::parse(&names, &subject, Some(&id), Some("a"), Some(session)).is_none());
        }
        let foreign = AccountNames::derive("other")
            .unwrap()
            .live_subject("thalamus-harness", "turn_ended", 1)
            .unwrap();
        let id = format!("{session}:turn_ended:1");
        assert!(Notice::parse(&names, &foreign, Some(&id), Some("a"), Some(session)).is_none());
        assert_eq!(
            subjects(&names).unwrap(),
            [
                "ck.test.live.thalamus-harness.turn_started.v1",
                "ck.test.live.thalamus-harness.turn_ended.v1"
            ]
        );
        let retired = names.live_subject("thalamus-pi", "turn_ended", 1).unwrap();
        assert!(Notice::parse(&names, &retired, Some(&id), Some("a"), Some(session)).is_none());
    }
}
