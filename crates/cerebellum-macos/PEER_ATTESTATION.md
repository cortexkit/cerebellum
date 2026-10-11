# Local bridge peer attestation

The macOS seam exports `local_socket_peer_pid` for either side of a connected
local socket. `peer_satisfies_requirement` checks that kernel-reported pid's
running code with Security.framework, with readable, identical process start
times before and after the check. The caller supplies the host or server signing
requirement from trusted configuration, not from the peer or its frames. Socket
uid enforcement and the host's parent-check attestation remain bridge duties.

`parent_satisfies_chrome_requirement` checks the calling host's current parent
against Google Chrome's Developer ID requirement (team `EQHXZ8M8AV`, identifier
`com.google.Chrome`). It checks both the process generation and the parent
relationship again before returning. A host must pass this check before opening
the bridge socket. The shipped build has no ad-hoc parent override.

## Chrome for Testing gap and acceptance-only resolution

Stock Chrome for Testing is **unsupported in shipped builds**. The official
mac-arm64 Stable build inspected below is linker/ad-hoc signed, has no signing
team, and has the signing identifier `Google Chrome for Testing`, not a
Google-team Developer ID identity. Treating an arbitrary ad-hoc identifier as a
trusted parent would admit unsigned impostors.

The real-browser acceptance probe needs CfT because branded Chrome 137+ ignores
`--load-extension`. An operator-approved probe may opt into the Cargo feature
`cerebellum-macos/chrome-for-testing-parent-probe` and call
`parent_satisfies_chrome_for_testing_probe_requirement` instead of the production
parent check. The ordinary Chrome parent check remains unchanged even with the
feature enabled. The probe pins exactly:

- Version/platform: **155.0.8059.39 (mac-arm64)**.
- Official archive: <https://storage.googleapis.com/chrome-for-testing-public/155.0.8059.39/mac-arm64/chrome-mac-arm64.zip>.
- Main executable SHA-256: `316795971c05d253320fcc574168aa8ae7782eae9beb540e0595ebbd654ab965`.
- Code directory hash: `8f2a5ce4af6d1cd71fe66113dd809e4d106c3106`.

A different CfT build fails the pinned requirement, and the typed refusal names
the required version/platform. There is no fallback to an arbitrary installed
CfT binary or its self-reported identity. Updating the pin requires inspecting
the new official artifact and reviewing the new hash.

**Probe-only risk:** the hash pins the loader but does not seal its dynamically
loaded framework dependencies. This weaker boundary is acceptable only for a
scratch acceptance probe, never for production. No browser was launched to
inspect these signing facts; a real-browser probe still requires approval.

The feature defaults off. `scripts/release-build.sh` never enables it; a test
checks that script and the empty default-feature set. A compile-time exclusion
also rejects this feature when the release script's signing-topology attestation
is present, including when a caller forwards feature flags through `"$@"`.
Without the feature, the override function and pin are not compiled at all.

Future browser support should add each browser's own signing team and identifier
as data. Brave and Edge are not admitted by this slice.
