# Harness live turn hints v1

`live-hints.json` pins the subject, header and key shape consumed by the badge
listener. These are plain core-NATS live hints, not JetStream `event` messages
and not `session.turn_ended` management requests. No payload body is read.

The two publishers are `thalamus-harness` and `thalamus-pi`. Their `turn_started`
and `turn_ended` v1 live subjects are derived with `AccountNames::live_subject`.
A hint needs `agent`, `session_ref`, and `Nats-Msg-Id` headers. The key is
`{session_ref}:{event_name}:{seq}`; its session and event must agree with the
header and subject. The sequence is a checked canonical unsigned decimal from
the runner's durable per-session event log, shared by starts and ends. It is
compared numerically, never by sorting the whole key.

An end below the latest observed sequence for that publisher, session and
agent is stale; an equal sequence is a redelivery. Missing agent/key, malformed
keys, different sessions in the key and header, and non-live subjects do not
end any badge. Headers remain publisher claims for presentation, never scope
stamps or permission to act. A missed live hint leaves the direct core call and
the existing badge idle fade as fallback.

`turn_hints::notice::tests::live_hint_vectors_pin_headers_and_keys` reads these
fixed examples. The lifecycle tests inject a transport and use no live bus,
operator configuration, journal or credentials.
