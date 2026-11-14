# Ability v1 wire vectors

These examples pin cerebellum's management wire, not native platform access.
`ability::tests::vector_tests::committed_vectors_match_handler_bytes_on_every_host`
builds every wire case through the real management dispatcher and ability
handler, then compares the pretty-printed bytes with these files. It selects
each platform's token set explicitly, so macOS, Windows and Linux cases all run
on every host. No system store, helper executable, live core or operator journal
is used.

## Format

Each wire case is one JSON object with recursively sorted keys, two-space
indentation and one trailing newline. `tag` is `ability-v1`; `method` is the
management operation; `request` is its whole request object, not just `params`.
`route` records `principal`, `flow_id`, `call_mode`, `codemode_head`,
`acts_as_agent` and `stamp` (null, or `kind`, `agent_id`, `run_id`, `flow_id`).
These are bind facts, not request members. `reply` is a successful response body;
`error` is an Error frame body containing only `code` and the fixed `message`.
`time_zone` records a pinned IANA zone for the event data cases. No success has a
top-level `outcome` or `image` member. There are no digest companions.

`catalog-token-mapping.json` predates this wire corpus. It remains unchanged and
is checked separately by the catalog mapping test; it is not a handler case.

## Fake sources and bindings

`VectorSource` implements the handler's status/setup/choices/read seam. Available
describe cases report all declared tokens available. Status cases model these
states:

* macOS: a missing or unverified helper, a revision mismatch, denied permission,
  missing Full Disk Access (FDA) stores, unrecognized FDA formats, and a failed
  personal information management (PIM) helper status request beside a
  responsive FDA unit. Helper identity failures apply to both units;
  store failures apply only to messages and mail. On a pre-14 system with the
  PIM file missing, calendar and reminders stay `os_unsupported` while contacts
  reports `helper_unverified`.
* Windows: every token in the single Outlook unit carries each of
  `classic_outlook_missing`, `outlook_not_running`, `outlook_guard_may_prompt`,
  `permission_missing` and, after a failed status request, `source_unresponsive`.
* Linux: EDS missing, an unrecognized interface format, or a failed status request
  affects every token. A separate case models an absent address-book service
  beside working calendar and task-list services.

The fake contains the calendars `also-bound` (Work calendar), `bound` (Family
calendar) and `outside` (Other calendar), deliberately returned out of order.
The choices page uses limit 1. Reads return two events in `bound`, `event-a`
at 10–15 ms and `event-b` at 20–25 ms, and `outside-event` in `outside` at
1–6 ms, all epoch milliseconds. Each title is `Fixture ` followed by its id;
other optional event fields use the item defaults. The source's time zone is
`America/New_York`. The list window is [0, 100) with limit 1: the earlier
out-of-scope event must not shape the page or cursor. The get case names
`event-a`. Setup fakes return each of the five states; the FDA action case names
`/fixture/ck-cerebellum-fda`. Linux's `not_required` is produced by the handler
without calling the source.

`VectorBinding` is the typed projection of a fake bound core record for
`flow-test`, install `vector-install`, version `1.0.0`. The `family_calendar`
entry binds calendar ids `bound` and `also-bound`. The carried description marks
calendar unavailable, deliberately: binding authority does not depend on that
description. Refusal cases additionally use a failed read or a record whose
entry has another key. These are injected binding records, not invented
`flow.install_status` wire samples. Every journal uses the isolated in-memory
fixture.

## Refusal cases

`refusal.one` through `refusal.fifteen` use the refusal table's numbered rows;
`refusal.sevena`, `refusal.sevenb`, and `refusal.sevenc` cover its inserted rows.
Row 10 has a separate `refusal.10.<reason>.json` for every reason it can carry.
The cases model, respectively: an unadmitted core call; a non-object scope;
unknown token; unknown op; empty scope id; a get id of 2049 bytes; an unbound
mailbox argument; failed binding read; absent binding key; pre-14 calendar on a
busy unit; queue expiry on an occupied unit; a failed journal reservation;
unavailable source; stale scope; unknown item; unsupported Linux recurrence;
a source read returning its deadline refusal; and a failed source read.
The last three source errors are injected at the adapter seam; native recurrence,
deadline and helper lifecycle behavior have their own tests.

There is a separate test per refusal row and per row-10 reason, as well as a
precedence test. They assert the fixed Error code independently of the golden
bytes, no journal entry for rows 1–8, and no source call for rows 1–7c (also
row 8 and a failed reservation). Rows 1–7 also make no binding read. Row 10
does preflight only, never a data read. `source_unresponsive` occurs only in
describe replies and is never an Error code.

## Checking and regenerating

Run `cargo test --locked -p cerebellum --lib ability::tests::vector_tests` for
the corpus and row tests. To regenerate, run just the corpus test with
`ABILITY_VECTOR_OUTPUT_DIR` set to a new scratch directory, inspect its output,
and copy the JSON files here. On the build server use an untracked directory at
the worktree root and return the generated files; do not overwrite tracked
fixtures remotely. Leave `catalog-token-mapping.json` untouched. Normal tests
never rewrite files and reject missing, extra or digest-companion files.
