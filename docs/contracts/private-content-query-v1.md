# `private_content.query`, v1

This is the cerebellum receive-side contract for Broca, which asks — before a
model call — whether a scope has read private content. A wrong "no" sends
private content to a provider the person never approved, so every doubt answers
"yes, from every source". The executable examples are in
[`crates/cerebellum/tests/vectors/private-content-query-v1`](../../crates/cerebellum/tests/vectors/private-content-query-v1/).
They are exact request and reply bytes captured at cerebellum's production
`handle_frame_for_test` entry point (which delegates to `handle_frame`), not
reconstructed tool-result examples.

BROCA's first live call failed because it guessed the shape: it sent an extra
`owner` parameter and decoded the reply through a `result` wrapper. Both
guesses are wrong. The request takes no `owner` (an unknown field is refused),
and the success reply is a bare body with no `result` wrapper and no `outcome`
field. Anything with an `outcome` field is a refusal, and it means marked (see
[For callers](#for-callers)).

## Who may call

Only `reserved:broca`, on a management-surface route bound for `cerebellum`:

- A `reserved:broca` bind is admitted only on the management surface
  (`crates/cerebellum/src/private_content.rs`, `bind_admitted`, ~838-844). A
  bind anywhere else is refused before any request is served.
- On a management route, any caller that is not `reserved:broca` gets the
  route error `principal_denied` with
  "private-content queries need reserved:broca" (`handle`, ~859-870).
- `reserved:broca` on any other surface, or calling any other method, gets the
  route error `principal_denied` with
  "reserved:broca may call only private_content.query"
  (`crates/cerebellum/src/lib.rs`, `handle_route_request`, ~3882-3905). Its
  management route has no other authority.

A route error is an `Error` frame carrying `{"code","message"}` and no
`detail` (`crates/cerebellum/src/wire.rs`, `build_error_frame`, ~33-61). It is
not the refusal body below.

## Request

```json
{"method": "private_content.query", "params": {"scope_ref": "...", "parent_scope_ref": "..."}}
```

`parent_scope_ref` is optional; everything else is required. `params` is a
closed key set (`handle`, ~871-881): any other key is refused, and so is an
empty or non-string value. The top-level frame body takes only `method` and
`params`; any other top-level key is refused as `unknown_field` naming it, a
missing `method` is `missing_field`, and a body that is not a JSON object is
refused naming `$` (`lib.rs`, `handle_management_request_observed`,
~4121-4165).

| field | required | refused as |
|---|---|---|
| `params` | yes, an object | `wrong_type` when missing or not an object |
| `params.<anything else>` | never | `unknown_field`, naming the key (for example the `owner` the first live call sent) |
| `params.scope_ref` | yes, a non-empty string | `missing_field` when absent; `wrong_type` when not a string (including `null`); `empty_value` when `""` |
| `params.parent_scope_ref` | no; when present, a non-empty string | `wrong_type` when not a string (including `null`); `empty_value` when `""` |

## Success

The reply is a `Response` frame whose body is bare — exactly this object, with
no `result` wrapper and none of `outcome`, `context`, or `session`:

```json
{"private_content": true, "sources": ["signed_in_site"]}
```

or, when nothing is marked for the scope:

```json
{"private_content": false, "sources": []}
```

`private_content` is exactly `sources` being non-empty
(`private_content.rs`, `answer`, ~419-431). Each source is one of
`person_browser`, `desktop_app`, or `signed_in_site` — the snake-case
serialization of the `Source` enum, in its declaration order
(`Source`, `SOURCES`, ~38-50). The list is ordered and deduplicated: the
answer collects the scope's marks across runs and heads into a `BTreeSet`,
whose iteration follows the enum's derived order (`person_browser`,
`desktop_app`, `signed_in_site`), not alphabetical order. A scope marked from
both the person's browser and a desktop app answers
`["person_browser", "desktop_app"]`.

## Refusal

A malformed query is refused with a `Response` frame (not an `Error` frame)
carrying exactly this body (`lib.rs`, `send_invalid_request_response`,
~8292-8318):

```json
{"outcome":"invalid_request","context":null,"session":null,"detail":{"field":"scope_ref","reason_code":"missing_field"}}
```

(Key order on the wire is alphabetical — `context`, `detail`, `outcome`,
`session` — because the body serializes through an ordered map. The goldens
pin the exact bytes.)

`detail.field` names the offending field and `detail.reason_code` is one of:

- `missing_field`: `scope_ref` absent (or the top-level `method` absent).
- `wrong_type`: `params` missing or not an object; `scope_ref` or
  `parent_scope_ref` present but not a string; the top-level body not an
  object (field `$`).
- `empty_value`: `scope_ref` or `parent_scope_ref` present but `""`.
- `unknown_field`: any key outside the closed sets — a `params` key other
  than `scope_ref`/`parent_scope_ref`, or a top-level key other than
  `method`/`params` — naming that key.

## Rules

What marks a scope, and how long the mark lasts:

- **Union over the run, its head, and the named parent.** The answer unions
  the marks of the requested scope with the head of every live run with that
  scope ref (found through the route table's `run_head`) and with the parent
  scope ref each such run's stamp names (`handle`, ~906-929). When Broca
  names a `parent_scope_ref` — for a run that never opened a cerebellum
  route, for example after source was pasted from a head's read — that parent
  is propagated into and added to the union too (`handle`, ~930-936).
- **Parent propagation is head-kept.** Copying a run's marks to the parent
  Broca names records them under head retention, so the parent and its other
  runs inherit the mark; the answer never waits for the copy to reach the
  file (`propagate`, ~812-831).
- **Run marks expire after 24 hours; head marks never do.** Run marks lapse
  24 hours after their latest read; head marks are never pruned. A head keeps
  what it read in its context for its whole life, which is also why version 1
  stores are read as head marks (`Retention`, ~52-62; `prune`, ~602-608).
- **After an unclean stop, or with an unreadable store, every answer is
  marked.** The store fails closed — answering all three sources for every
  scope — while a write has failed or timed out, while its own in-use marker
  is missing, while the marks file cannot be read (corrupt, oversized, or of
  unknown version, in which case it is never written over), or while a
  previous process's in-use marker is still within its 24-hour window
  (`fails_closed`, ~265-270; `answer`, ~422-424). A process with no data home
  answers everything marked for good (`production`, ~298-313). Health reads
  `unreadable` for a failed store and `unclean_shutdown` inside an inherited
  window (`health`, ~359-370; `open_at`, ~322-351; `read_marker`, ~203-214).

What delivers a mark: a reply carrying page or app text, an image, a nested
read, or a non-empty `detail.hit_name` (the name of a click target the page
intercepted) (`carries_content`, ~612-624) marks the
calling scope (and its parent, for runs and flows) under the reply's plane
(`mark_delivered`, ~767-810; `mark_targets`, ~754-765; `retention`,
~737-746). Desktop replies mark unless they are refusals known to carry no
app text (`DESKTOP_REFUSALS_WITHOUT_APP_TEXT`,
`desktop_reply_is_content_free`, ~644-687). Own-browser replies mark as
`signed_in_site` only with login evidence for that profile; retained
own-browser replays always count as `signed_in_site` when they carry content
(`replay_plane`, ~708-718).

## For callers

- Treat anything you cannot decode, and any body carrying `outcome`, as
  **marked**. Success has no `outcome` field; every refusal does. Never treat an
  undecodable or refused answer as "no private content".
- Send exactly `scope_ref`, plus `parent_scope_ref` when the run has no
  cerebellum route. Never send `owner`, `result`, or any other wrapper: the
  closed key set refuses them, and a refused query answers nothing about the
  scope.
- Query the scope (and its Broca-known parent) before the model call, and
  route content accordingly when `private_content` is true.
