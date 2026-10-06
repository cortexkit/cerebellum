# Person-input attribution and empty-filter investigation

On 2026-10-06 around 13:38 UTC, Magic Context Dashboard was relaunched. A `Config` text-filtered read showed only its window; a later role-filtered read showed `⚙️ Config`. Pressing that control was refused as `state_changed_by_person` / `input_seen`, although the Mac's owner, Ufuk, reported he had not touched the app or machine.

## Read and launch audit

`serve_read_state` captures `SeenMarks` before the full AX read, applies filters only while rendering, records the read's element/unreadable counts in the audit journal, and calls `remember_seen` regardless of match count. Marks contain focus, window and an `Instant`, **not a saved HID age**. The wire regression `every_filtered_read_even_without_matches_refreshes_person_marks` checks text and role filters, both matching and empty: old focus/window/input changes are cleared by that read, and later hardware input still refuses. It drives the real `ComputerPlane::serve` boundary with result-schema withholding and verifies actual press records.

Session keys include conversation, bundle, PID and process-generation evidence. `a_new_process_generation_starts_a_new_session` now explicitly checks that seen marks are absent for the new generation. `first_read_of_a_frontmost_process_does_not_count_input_predating_the_read` covers a fresh frontmost target whose last input predates the read. Being frontmost does not make old input newer than the first mark. No read-path or launch-mark bug was found.

## Proven attribution defect; incident limits

The old action guard used `seconds_since_last_deliberate_input(HidSystem)` (key-down, three mouse-button-down types and scroll), converted its minimum age into an instant, and excluded only events timestamped during this module's own posting calls or the short window-server lag after them. The HID table does not identify the sender. A synthetic event from another process outside those excluded intervals was therefore called `input_seen` and described as the person using the app. `another_process_s_synthetic_input_is_not_attributed_to_the_person` reproduces that exact defect over the wire using the desk's sender-blind HID double.

This proves a real false-attribution mechanism, **not which process sent the historical event**. There is no retained source-attributed event or raw AX tree from the reported incident. Passive ages cannot retrospectively identify its sender. The implementation must not make that accusation from those ages regardless of who was actually at the desk.

## Passive desk evidence

The coordinating agent posted a notice in `#fleet-notices` before sampling, asking other agents to leave the Mac untouched during a three-minute passive read-only sample. No activation, click, key, event posting, permission request or event tap was used. A Python ctypes probe read CoreGraphics HID-system per-type ages, the current cursor location, NSWorkspace's frontmost PID, and `ioreg` HIDIdleTime. It scheduled 720 samples at 250 ms; process overhead stretched the elapsed sample to 184.09 seconds.

| Signal | Age resets | Resets with identical consecutive cursor/frontmost readings |
| --- | ---: | ---: |
| Key-down | 58 | 56 |
| Mouse-button-down (minimum of left/right/other) | 21 | 1 |
| Scroll | 32 | 4 |
| HIDIdleTime | 203 | 64 |

The longest identical cursor/frontmost stretch was approximately 26 seconds. The sampled frontmost PID was always 90954 (LiteCode). **NSWorkspace may cache this value without a run loop**, so this is not verified continuous live frontmost evidence. Unchanged cursor and frontmost readings are also entirely consistent with a person typing: these numbers establish input activity, not hardware or synthetic origin. The fleet notice did not establish that Ufuk would keep his hands off the Mac. The coordinating agent declined a second sample because it could not settle origin either.

A non-prompting read-only query of the system TCC database found Accessibility grants. The user TCC database was inaccessible. A subsequent process snapshot matched these trusted clients to running executables:

- ck-subc, PID 1396
- Raycast, PID 1467 (and RaycastAppIntents, PID 2836, matched by enclosing app)
- Hammerspoon, PID 1470
- Parallels Toolbox Break Time, PID 1477
- Snapzy, PID 35538
- Sidebar, PID 57512
- Codex SkyComputerUseService, PID 67538
- Logitech logioptionsplus_agent, PID 69190

These are candidates capable of posting input, **not identified senders**. TCC is an unsupported implementation-detail inventory; matching a helper's enclosing bundle is not independent proof of its effective trust. The process snapshot was not taken on every sample, and no per-process activity trace was collected. No origin correlation is established. Raw readings remain at `/tmp/cerebellum-passive-sample.jsonl` on the Mac used to collect the sample.

## Hardware observer and unavailable disposition

The native source starts a single dedicated listen-only session observer lazily at its first state mark, only if Input Monitoring is already granted. It makes no permission request and stays on for the module process's lifetime. Its callback counts only deliberate key/button/scroll events with source PID zero and event-source state other than CoreGraphics private state (raw ID -1, which synthetic sources can use). Pointer movement and nonzero-PID synthetic input never enter this history. Existing seize dispatch taps retain their policy and do not feed this history.

The callback records only an event kind and timestamp; the history retains five latest timestamps, one per deliberate event kind. It never retains source/target PIDs, key codes, characters, flags or coordinates. It makes no window-list copy, frontmost query or other app-state read. `hardware_observation_shape_retains_only_kind_and_timestamp` pins the complete recorded struct's fields, not merely its size, so adding a content field cannot hide in padding.

`CGEventField::EventTargetUnixProcessID` was not used or measured. A proposed one-minute scratch listen-only check would compare its hardware-event target PIDs to live frontmost PIDs. Alfonso, the coordinating agent, explicitly canceled that measurement because a scratch binary launched from a terminal would use the terminal's permission attribution rather than the module's, and selected the timestamp-only design instead. No reliability claim about the target-PID field is made, and no new live tap was installed during this follow-up. The guard resolves frontmost PID when it checks the action, not inside the callback.

Coverage begins after the observer run loop is ready. A denied/not-created observer is unavailable. A timeout-disable or user-input-disable notification immediately invalidates coverage and clears the timestamps. The liveness worker re-enables the tap with `CGEventTapEnable`, resets `since` (the start of uninterrupted observation) to the successful recovery time, increments `disabled_reenabled_count`, and keeps running. Failed re-enabling keeps coverage unavailable and is retried. A successful re-enable is not coverage of the missing interval: an action using a pre-gap read must read again. Injected-disable tests exercise both notification kinds, the actual recovery helper's enable call, failed recovery, resumed recording, and stable coverage during ordinary polling.

The dedicated observer does not queue events, so it cannot stall a callback on an undrained channel. It uses a run-loop thread plus a liveness worker waking every 10 ms, five timestamp slots, and a small mutex critical section per deliberate event. There is no per-keystroke window-server query. Source snapshots copy only the coverage boundary and newest timestamp. Tests use explicit source-PID/state/kind fixtures for hardware classification and injected tap-disable/enable states for recovery, rather than relying on live desk activity.

The guard always compares focus and window first. When a successful live frontmost-PID read names a different process, the target is background and needs no input coverage. A frontmost target requires observation covering the interval since its last read; otherwise `observer_unavailable` says the module **could not tell whether** the person is using the app and says nothing was sent. After automatic disable recovery it asks for a fresh read, not a mandatory restart. Startup permission/creation failures still require restoring access and restarting the module. An unreadable frontmost reading cannot certify that the target is background. Missing coverage never falls back to HID ages. Before the first read there is still no seen-state comparison, as before.

Module `health.check` includes `hardwareInputObserver: {state, disabled_reenabled_count}`. States distinguish `not_started`, `running`, `unavailable_no_permission`, and other `unavailable` failures (`platform_unsupported` off macOS). The count records successful recoveries only. Health reads atomics and neither starts the observer nor requests permission; a separate wire test pins that property. No event timestamps or content are exposed through health.

Classifying source PID zero with non-private state as hardware is the repository's convention, not forensic proof that the desk user personally generated an event. Hardware remappers that re-post with their own PID are excluded from the input signal; their focus/window changes remain observable. Input is session-wide and considered only if the target is frontmost at check time. Consequently, hardware input in another app followed by a switch to the target can require another read; this is an intentional conservative refusal, not a claim of event-time target attribution. Background actions remain unaffected.

## Empty `text_filter` finding

The renderer lowercases labels/values and performs substring matching. ASCII `Config` remains a contiguous substring of `⚙️ Config`; the emoji and U+FE0F preceding it do not affect matching. The wire test `config_filter_matches_emoji_label_and_discloses_unpopulated_window_content` proves both `Config` and `config` match that exact populated label and produce the same control as the role filter.

The earlier read and later role-filter read were sequential, not observations of the same retained raw tree. WebKit can expose a window/layout shell or empty web area while its AX content is still populating; the native readiness helper checks for a web area with children and retries once after 100 ms within the original read deadline, but can still return an unpopulated shell as a complete read. The matching logic is not the cause for the reported label. The historical tree was not captured, so startup population is the supported explanation, not a conclusively replayed fact.

Before applying filters, the serving read now marks empty web areas and windows containing only layout shells as unknown content. It carries `unreadable_subtrees` and a plain completeness notice in `state_text`, rather than presenting header-only output as proof that Config does not exist. Legitimately empty windows may also receive this conservative marker: without populated content the reader cannot distinguish them from loading windows. Populated trees with no filter match remain ordinary complete no-match reads. Incomplete reads also cannot certify that previously observed elements were removed.

## Vocabulary

Revision 16 adds only `observer_unavailable` and its explanatory description to the three element-action result schemas; keystroke schemas already admitted it. The canonical UTF-8 JSON resource and its source/source-lock SHA mirrors were regenerated. Tests generate revision 16 from revision 15 and reverse exactly those additions, comparing the reconstructed JSON against the measured revision-15 digest `671ab7a2017cb556448c42661dd5e1b8fcb3f3aa360c54ee291518c59c5fe5c4`.
