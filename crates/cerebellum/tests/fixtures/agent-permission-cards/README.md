# Agent permission request goldens

These files are exact `consent.request` params from Cerebellum's production
builders and mapper for a Cingulate advertising `consent-option-group/v1`.
`head-` identifies the main agent; `worker-` identifies a task worker whose
permissions are separate from its main agent. Both identities are verified by
the daemon before a granting choice can be offered.

| Head file | Worker file | Card |
|---|---|---|
| `head-app-control.json` | `worker-app-control.json` | App and whole-computer choices |
| `head-takeover.json` | `worker-takeover.json` | Takeover once and whole-computer choices |
| `head-website-access-in-call.json` | `worker-website-access-in-call.json` | Sign-in site, held call |
| `head-website-access-in-advance.json` | `worker-website-access-in-advance.json` | Sign-in site, asked ahead |
| `head-website-public-in-call.json` | `worker-website-public-in-call.json` | Public site and all-sites choices, held call |
| `head-website-public-in-advance.json` | `worker-website-public-in-advance.json` | Public site and all-sites choices, asked ahead |
| `head-user-browser-site.json` | `worker-user-browser-site.json` | Person's Chrome, sign-in site only |
| `head-user-browser-public.json` | `worker-user-browser-public.json` | Person's Chrome, public site only |
| `head-login-import.json` | `worker-login-import.json` | Unchanged single-use control |
| `head-login-capture.json` | `worker-login-capture.json` | Unchanged single-use control |
| `head-profile-reidentification.json` | `worker-profile-reidentification.json` | Unchanged single-use control |
| `head-stuck-profile-clearance.json` | `worker-stuck-profile-clearance.json` | Unchanged single-use control |

The person's Chrome never offers all-sites or danger options. Other danger
options are removed, along with their remembered granting answer ids, when
Cingulate's catalog declaration is missing or cannot be read. Takeover's
non-danger once option writes no reusable permission row.

`SHA256SUMS` lists the checksums of all 24 files for CKIOS. Existing changed
card goldens are `app-control.json`, `takeover.json`,
`website-access-in-call.json`, `website-access-in-advance.json` and
`user-browser-site.json` under `../cingulate-consent-cards-v1/`; its other four
cards are unchanged. The five site-option variants under
`../browser-site-access-card-v1/` were regenerated too, with the worker variant
renamed to `worker-options.json`. Both directories carry their own checksums.

Regenerate these JSON files and their checksum list after an intentional change
to the card builders:

```
CEREBELLUM_WRITE_AGENT_PERMISSION_CARDS=1 cargo test --locked -p cerebellum --lib exported_permission_cards_match_goldens_and_fail_closed
```

Without that variable, the test checks the committed bytes, checksum list,
decline default, expiry denial and danger groups. Cingulate's production
validator checks these exports separately; the local tests also check the
stripped requests sent to older Cingulate versions.
