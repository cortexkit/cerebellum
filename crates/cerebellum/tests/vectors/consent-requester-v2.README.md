# consent-requester-v2 (copied from Cingulate)

`consent-requester-v2/` is a byte-for-byte copy of Cingulate's
`test-vectors/consent-requester-v2/` at Cingulate main commit
2933c511f1de060449e4d04e7491b0734ba0a2ee ("Late answers on generic consent
cards: consent.detach and the consent_answered notice"), the commit that
settled the detach rules. That commit added the four `consent.detach` vectors
(`cerebellum-detach-pending-*`, `-settled-*`, `-repeat-*` and
`-wrong-owner-*`) to the directory published at tag `consent-requester-v2`
(commit a87da8c86f526f2d489adc433517246e1399e604) and tag
`consent-late-answer-v1` (commit 880a065865ae4aaecc0ccbef0e5fa73ae13d014a),
and Cingulate regenerated its `SHA256SUMS` to cover them. Its own `README.md`
describes the files. Do not edit, reformat or add files inside that
directory: it must stay identical to what Cingulate published.

The contract these vectors pin is Cingulate's
`docs/contracts/consent-requester-v2.md` (on top of `consent-requester-v1.md`),
including the section "Late answers on generic consent cards". Cerebellum is
the `reserved:cerebellum` requester: it raises `kind: "consent"` cards and
reads their settlements with `consent.await`, `consent.get`,
`consent.answers`, `consent.ack`, `consent.withdraw`,
`consent.report_execution` and `consent.detach`.

The checksum file is `consent-requester-v2/SHA256SUMS`, Cingulate's own,
never regenerated here. It covers every file except itself; its own SHA-256
is pinned in `the_requester_vectors_are_the_ones_cingulate_published`
(`crates/cerebellum/src/cingulate_client/vectors.rs`), which also checks that
the manifest lists exactly the files present. The scripted Cingulate double the
client's wire tests run against replays the reply files from this directory,
including the four detach replies.

To take a newer copy of this same version, replace the whole directory with
Cingulate's directory at the new commit (every file, `SHA256SUMS` included),
then move the pinned manifest hash and the commit lines above. A new contract
version goes in beside this one under its own versioned name. Never point a
test at the sibling Cingulate checkout.
