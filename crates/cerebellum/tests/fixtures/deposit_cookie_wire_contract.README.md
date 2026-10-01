# deposit_cookie_wire_contract.json (copied from claustrum)

`deposit_cookie_wire_contract.json` is a byte-for-byte copy of claustrum's
producer-pinned wire contract for `credential.deposit_cookie`,
`crates/credentials-module/tests/fixtures/deposit_cookie_wire_contract.json`
at claustrum commit f3f968a (f3f968ad3be819fbc29058f001b3caeb1e6f286a). Its
SHA-256 is
`1eb8e1360d4a1267fa4f5a760634a2a16fbeedb58b0184f297b1cb20d3f64430`. The prose
contract is claustrum's `docs/wire-contract-v1.md`, section "Cookie deposit".
Do not edit or reformat it: it must stay identical to what claustrum
published. To update it, copy the file again from a newer claustrum commit and
change the commit and digest here.

Each key except `payload_hash` maps a reply case to the exact reply body the
vault sends (`created`, `replaced`, and one per refusal code).
`payload_hash` is the vault's audit commitment for the documented example
request (id `cookie:ollama.com:ufuk`, consent_ref `consent-123`, cookie
`session=abc`).

Cerebellum's tests use it in `crates/cerebellum/src/login_capture/`:

- `vault_wire.rs`: `the_fixture_is_the_one_claustrum_published` pins the
  digest above; `every_fixture_reply_parses_to_its_typed_result` runs
  `parse_deposit_reply` over every reply body;
  `the_example_request_is_built_byte_for_byte` checks the request built for the
  documented example against the doc's bytes and the fixture's `payload_hash`.
- `tests.rs`: `every_fixture_reply_gives_the_capture_reply_it_should` sends
  each reply body, byte for byte, through a whole capture.
