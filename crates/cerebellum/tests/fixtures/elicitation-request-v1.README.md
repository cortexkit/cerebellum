# elicitation-request-v1 (supervisor request vectors)

`elicitation-request-v1/` is a byte-for-byte copy of the supervising module's consent
request vectors, `test-vectors/elicitation-request-v1/` at upstream commit
d15391996594ce24ba53aa42fd1c31bb85922745. Its own `README.md` describes them.
Do not edit, reformat or add files inside that directory: it must stay
identical to what the supervising module published.

The supervising module decodes the `params` of every consent `elicitation/create`
cerebellum sends with `ConsentRequest::decode`. A body core refuses is never
shown to the person: core answers `not_put_to_anyone`. These vectors pin what
core accepts and refuses. Cerebellum's tests use them in two ways, both in
`crates/cerebellum/src/consent_card.rs`:

- `the_request_vectors_are_the_ones_prefrontal_published` recomputes the
  SHA-256 of every file against the copied `SHA256SUMS`, checks that the
  manifest covers every file in the directory, and pins the SHA-256 of
  `SHA256SUMS` itself, as the vectors' README asks.
- `the_contract_mirror_agrees_with_core_on_every_request_vector` runs
  `core_verdict`, the crate's mirror of core's decoder, over every body. Each
  valid card must be accepted. Each refused body must be refused with the
  `code` its `.expected.json` names, in a message that contains its
  `message_contains`. Every rendered cerebellum card is then held to the same
  `core_verdict`.

To take a new version, copy the new directory in beside this one under its
own versioned name, and move the pinned manifest hash and the paths in those
tests to it.
