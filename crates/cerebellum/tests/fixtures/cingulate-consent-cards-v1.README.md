# cingulate-consent-cards-v1

The exact `consent.request` params cerebellum sends Cingulate for each of its
card kinds, one file per kind, built by the production card builders and
mapped by `crates/cerebellum/src/cingulate_client/card.rs`. `SHA256SUMS`
pins each file.

`every_card_kind_matches_its_golden` (in
`crates/cerebellum/src/cingulate_client/tests.rs`) re-renders every card and
compares it with its file and the sums. Beside it,
`every_card_kind_shows_the_phone_what_it_showed_before` proves each card's
phone-visible fields are byte-identical to the card the reverse elicitation
lane sent, and `no_card_carries_a_next_step` that the agent's next step stays
off the card.

After a deliberate change to a card, run the golden test with
`CEREBELLUM_WRITE_CINGULATE_CARD_GOLDENS=1` to rewrite the files and the sums,
and review the diff: every byte here is what the operator's phone renders.
