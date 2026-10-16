# Agent permission request goldens

These files are exact `consent.request` params from Cerebellum's production
builders and mapper. `head-` and `worker-` pin the options for each admitted
holder; worker identity resolution is tested separately.

For each holder the files cover app control, takeover, website access in a call
and in advance, and the person's browser site access. The website and user-browser
`public` variants include all-sites danger options; the other site variants ask
for sign-in consent and do not offer all-sites. Login import, login capture,
profile reidentification and stuck-profile clearance are included as unchanged
single-use controls. `SHA256SUMS` lists all 24 filenames and their checksums.

Regenerate after an intentional card change:

```
CEREBELLUM_WRITE_AGENT_PERMISSION_CARDS=1 cargo test --locked -p cerebellum --lib exported_permission_cards_match_goldens_and_fail_closed
```

Without that variable the same test checks the committed bytes, checksum list,
decline default, expiry denial, and danger groups. The parent runs these exports
through Cingulate's production validator and relays the checksums to CKIOS.
