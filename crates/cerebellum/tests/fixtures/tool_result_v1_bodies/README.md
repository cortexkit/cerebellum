# tool-result/v1 body bytes

These files are exact `tool-result/v1` response bodies for the three payloads in
`../content_v1_legacy/`, in the same order: `browser_snapshot.json`,
`browser_screenshot.json` and `computer_read_state.json`.

They were captured from Cerebellum at `60488c6744a3505efeed699d26235c835859bb1a`,
which linked `cortexkit-role-tool-provider` 0.9.3, when the format was still
named `content/v1`. A temporary library test bound a route that declared
`content/v1`, passed each legacy payload through the production
`send_tool_response` (the same `bound_planes` and `response` helpers as
`src/result_negotiation_tests.rs`), and printed the emitted body bytes. No
normalization followed.

`cortexkit-role-tool-provider` 0.13.0 renamed the format to `tool-result/v1`
and left the body shape unchanged. The test
`tool_result_v1_reader_gets_the_bytes_the_retired_name_got` checks that a route
declaring `tool-result/v1` now receives exactly these bytes.

Captured SHA-256 values:

- `browser_snapshot.json`: `d82fbb9a84799bbd4571e8add3d411b00dd4487927efa2dea94c8d8c0b056b10`
- `browser_screenshot.json`: `c611d44bacff09dbba7e8b5558c53853307ab3ea029edfd4c6d784283f8c7744`
- `computer_read_state.json`: `939a5e75535f3e4d4ce2fd2589b5d2a86cd877aaa0bc77dc9c4b44c7c1c751d4`

Do not regenerate these from the current projector: regenerating would save
whatever the current code emits as the expectation, so the comparison could no
longer catch a change to the body.
