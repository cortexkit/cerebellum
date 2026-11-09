# Login-origin bytes sent to the credential vault

## Pinned upstream source

- Repository: `cortexkit/claustrum`
- Tag: `secret-multi-host-vectors-v1`
- Commit: `cc7544d78c8c6a97b6be78f4b76cfed86651ddc7`
- Source: `crates/credentials-core/tests/vectors/multi-host/secret-scope-match-v1.json`
- Source SHA-256: `b3f1654c562518ab86a775a1a123049827cb6db7027114db47b5db7b65e06a21`
- Upstream `SHA256SUMS` SHA-256:
  `2b0ec7ffc87a62bd027939648320f94e54fcd6a2b8af8dbf7dbd4a6cd60f0207`

The source and manifest were read with `git show` at that tag, not from the
working tree. All five files in the tagged upstream manifest passed
`shasum -a 256 -c SHA256SUMS`. Our `SHA256SUMS` pins the two local JSON files.

`upstream-login-cases.json` contains ten selected upstream case objects without
changes to their fields, values or formatting. Only the containing file is a
subset, not a byte-identical copy of the complete upstream file. It retains:

- `login-target-is-not-api-key`, `four-origins`, `stored-origins-as-sent`;
- all four `legacy-login-…` cases;
- `login-origin-wildcard`, `login-origin-path`, `login-origin-port`.

The `expect`, `scope`, `form` and `kind` fields remain the **vault's verdict and
inputs**, not assertions that cerebellum implements scope matching. In
particular, an origin target is not an API-key target, wildcard/path/non-default
port login scopes are refused, and a `:444` target does not match a `:443` scope.
The scope-only refusal cases are retained as context; they have no login target
for the browser test to canonicalize.

The upstream target inputs are used verbatim. The test's expected outgoing
origins are the following literal strings, not values computed by the code
under test. The source publishes match/refusal verdicts rather than a separate
canonical-output column; the `:443` output follows its matching scope's literal
`https://x.test` and the contract below.

| Upstream case | Target input | Expected cerebellum origin |
| --- | --- | --- |
| `login-target-is-not-api-key` | `https://a.x.test` | `https://a.x.test` |
| `four-origins` | `https://login3.x.test` | `https://login3.x.test` |
| `stored-origins-as-sent` | `https://x.test` | `https://x.test` |
| `legacy-login-https://x.test:443` | `https://x.test:443` | `https://x.test` |
| `legacy-login-http://x.test` | `http://x.test` | No request: `origin_not_https` |
| `legacy-login-https://y.test` | `https://y.test` | `https://y.test` |
| `legacy-login-https://x.test:444` | `https://x.test:444` | `https://x.test:444` |

Keeping `:444` distinct prevents an accidental match after rewriting it to the
default port. The vault, not cerebellum, decides whether that origin matches.

## Derived browser examples, not published vault vectors

`derived-origin-cases.json` is **derived from docs/wire-contract-v1.md
'Multi-host secret scopes' at cc7544d7, not vault-published**. The exact tagged
section is "Multi-host secret scopes (normative extension)". It supplies these
sentences (line wrapping removed, text unchanged):

1. "An exact host is nonempty lowercase ASCII DNS text: nonempty dot-separated labels, each containing only `a`–`z`, digits and `-`, with no edge hyphen, trailing dot or IP literal."
2. "A login scope origin is exactly `https://<valid-host>` with optional `:443`; `canonical_origin` removes that suffix, with no URL normalization."
3. "A login target matches an origin with the same host, HTTPS and port 443; HTTP, another host or port 444 does not match."
4. "Targets remain one concrete URL or origin in the unchanged `secret.use` shape, never a wildcard or an array."

The source does not contain uppercase-host or www/apex examples. The following
rows are local, explicitly derived expectations for cerebellum's browser URL to
origin conversion, not a claim that the vault normalizes uppercase or accepts
URLs with paths as stored scope origins:

| Derived case | Browser URL input | Expected outgoing origin | Contract basis |
| --- | --- | --- | --- |
| `explicit-default-port` | `https://x.test:443` | `https://x.test` | Sentence 2 |
| `uppercase-host` | `https://X.TEST` | `https://x.test` | Sentences 1–2; browser lowercases before the vault sees it |
| `www-host` | `https://www.x.test` | `https://www.x.test` | Sentence 3: keep the same host |
| `apex-host` | `https://x.test` | `https://x.test` | Sentence 3: do not alias the apex and www hosts |
| `trailing-slash` | `https://x.test/` | `https://x.test` | Sentence 2: emit only an origin, not a document URL |
| `path-query-fragment` | `https://X.TEST:443/signin?next=%2F#password` | `https://x.test` | Sentences 1–2 and 4; reduce the browser document URL to its origin |
| `non-default-port` | `https://X.TEST:444/signin` | `https://x.test:444` | Sentence 3: keep the port distinct so the vault cannot match by accident |

## Production path covered

`BrowserPlane::plan_fill_login` calls `browser::fill::field_origin` for each
field. A field uses its own iframe URL/origin when present, otherwise the main
document's. All fields must agree. `field_origin` requires HTTPS, rejects opaque
or inconsistent browser-reported security origins, and calls
`classification::canonical_origin_from_url`. That helper removes path, query
and fragment; `canonical_origin` lowercases scheme and ASCII host, removes
`:443` for HTTPS, and retains a non-default port (normalized as a decimal u16).

`login_fill_consent::serve_inner` copies `FillPlan.origin` into
`SecretUseRequest.origin`. `VaultLoginSource::secret_use` sends
`login_capture::secret_use::encode_params`, which relays that string unchanged
in `target.origin` of `secret.use`. The tests exercise main-frame and cross-site
iframe origins with independent expected security origins, and compare the
actual vault encoder's target string byte-for-byte as well as the request's
`params()` representation. No wire, scope matching or credential checks change.
