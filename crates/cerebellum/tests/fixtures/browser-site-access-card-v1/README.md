# Browser site-access card vectors

Each file holds the card body (the `params` object) that cerebellum's
builder renders for the browser site-access consent card, one file for each
set of options the card can present. The card is
raised with Cingulate, the consent module, as a `consent.request` built from
these params (`cingulate_client::card::consent_request`), which keeps every
field the phone shows; its exact bytes are pinned per card kind in
`../cingulate-consent-cards-v1/`.

| File | Options offered | Case |
|---|---|---|
| `all-options.json` | `allow_conversation`, `allow_origin_always`, `allow_all_sites_10m`, `allow_all_sites_always`, `deny` | primary session with an attested agent, public origin, ordinary browsing |
| `no-all-sites-level-4.json` | `allow_conversation`, `allow_origin_always`, `deny` | the request needs lasting changes (tier 4) |
| `no-all-sites-hazard.json` | `allow_conversation`, `allow_origin_always`, `deny` | the request discloses a hazard (here `credential_form_submit`) |
| `no-all-sites-private-origin.json` | `allow_conversation`, `allow_origin_always`, `deny` | the origin is not a public website (here `http://10.0.0.5`) |
| `conversation-only-worker.json` | `allow_conversation`, `deny` | a worker, ephemeral or unattested session |

Each option is `{id, label, effect, detail?}`; no option carries a level or a
duration. The card-wide `duration` is left unset. What each granting option
grants is recorded by cerebellum against its id when the card is sent, and an
answer is mapped back through that record, never through the id's spelling.

`SHA256SUMS` pins each file. The test
`consent_card::every_card_kind::browser_site_access_card_vectors_are_pinned`
rebuilds every card with the production builder, compares it with these
files, and checks the Cingulate request made from it offers the same options. After a deliberate change
to the card, rerun that test with `CEREBELLUM_WRITE_SITE_CARD_VECTORS=1` to
rewrite the files and the sums.
