# ck-cerebellum — Charter

Computer use and browser use for the CortexKit fleet. The cerebellum executes
coordinated physical action on the machine: it drives browsers, clicks, types,
scrolls, reads screens, and hands the results back to whichever agent asked.

AFT remains the sensorimotor cortex for *code* (perceives code structure, acts
on it precisely, project-root-scoped). The cerebellum is the layer below: fine
motor control on the *machine* — GUI and web, machine-scoped, with its own
containment story. The two do not overlap: if the target is a file or a repo,
it is AFT's; if the target is a screen, a window, or a page, it is ours.

## Why a dedicated module

- **Scope model.** AFT's identity, config tiers, caches, and sandbox all key on
  a project root. Computer use is machine-scoped and browser sessions are
  conversation/task-scoped; neither fits a root-keyed bind model.
- **Blast radius.** On macOS this capability requires TCC Screen Recording and
  Accessibility grants, attributed to the responsible process. Fleet doctrine
  separates dangerous capabilities into dedicated organs (vault, quota,
  backups); the machine's two most powerful permissions get their own binary,
  their own policy surface, and a clean TCC attribution anchor.
- **Lifecycle.** Browser processes, profiles, CDP sessions, and screenshot
  streaming want their own supervision, health gauges, and restart semantics.
- **Plane discipline.** alfonso-core orchestrates; it is not an effector. The
  cerebellum is a provider module that alfonso (and any other consumer)
  reaches through subc routes, exactly like aft tools.

## Two planes, one module

They share the permission machinery, session model, and vision pipeline, so
they ship as one module with two capability families.

**Browser plane (the common case, ships first).**
- CDP-driven automation of managed browser instances: navigate, read
  (DOM/accessibility-tree extraction first, screenshot fallback), interact
  (click/fill/select by structured locator), wait conditions, downloads.
- Structured-action-first is a design principle, not an optimization: DOM-level
  actions are cheaper in tokens, more deterministic, and auditable. Pixel-level
  interaction is the escape hatch, never the default.
- Profile management: named browser profiles with isolated storage, so an
  agent's research session and a logged-in workflow session are different
  identities by construction.
- Needs no TCC ceremony — the walking skeleton lands here.

**Computer plane (the escalation).**
- Screen capture (full screen, window, region) and synthetic input (pointer,
  keyboard) via macOS Accessibility, extended by app-targeted primitives
  (window enumeration, frontmost app, AX-tree queries) where structure beats
  pixels — the same structured-first principle as the browser plane.
- TCC-gated: the module owns the grant ceremony UX (prompt attribution,
  detection of missing grants, honest typed errors instead of silent black
  screenshots).
- Machine-scoped and therefore the most dangerous surface in the fleet;
  everything here is permission-gated per the model below.

## Trust and permission model (design target)

- **Principal-aware by default.** Untrusted binds (`mcp:*` facade callers) get
  no cerebellum tools at all — default-deny in the gateway policy, not an
  in-module check alone. First-party consumers (alfonso workers, owned
  harnesses) get capability-scoped access.
- **Conversation-scoped grants.** Permission to drive the machine is granted
  per conversation via the elicitation relay (the bash-after-elicitation
  pattern), never ambiently. Grant state needs a durable session identity, so
  delivery is plugin/facade-path per the fleet's delivery-path doctrine.
- **Irreversibility honesty.** This module executes the least reversible
  action class in the fleet (send the email, submit the order). Actions carry
  the fleet's action-severity taxonomy from day one so reversibility ceilings
  and ask/quorum routing (Room-2 machinery) apply to it verbatim when team
  mode arrives — and inform per-action elicitation prompts before then.
- **Credential boundary.** The cerebellum never reads the vault. If a workflow
  needs a login, the human logs in once inside a named profile (browser plane)
  or the credential flows through existing custody paths; secrets never
  transit cerebellum tool arguments in plaintext as a design rule.

## Fleet integration

- Supervised subc module (`cerebellum` in subc.jsonc, binary `ck-cerebellum`),
  spawn-attested, wire v2, health v2 (insulated lane, mechanical gauges: CDP
  session liveness, browser process state, TCC grant status, oldest in-flight
  action age).
- Capability manifest declares the tool families; `execution_mode` honest per
  tool (reads `pure`, actions `unfenceable` — there is no undo for a click).
- Storage via cortexkit-store (profiles registry, grant ledger, action audit
  journal); config at `~/.config/cortexkit/cerebellum.jsonc`.
- Screenshot payloads ride the existing 64 MiB frame budget; live viewing /
  streaming surfaces (for the Cortex app's supervised-session view) are a
  later lane on the existing subscribe machinery.

## Open design questions (for the design rounds)

1. Permission model detail: grant granularity (per-action-class? per-app /
   per-origin allowlists?), grant lifetime, and what the elicitation prompt
   must disclose for informed consent.
2. Browser profile identity: naming, isolation guarantees, relationship to
   conversations and to human-owned logins; profile lifecycle and cleanup.
3. Engine choice and custody: CDP against which browser (bundled headless
   chromium vs driving the user's installed browser), and who owns updates.
4. Vision pipeline: screenshot formats, downscaling policy, coordinate-space
   contract between model-visible images and input synthesis (retina scaling
   is a classic corruption source), redaction hooks for sensitive regions.
5. Action audit: what the journal records per action (screenshot-before?
   DOM-hash? intent string from the caller?) and its retention/engram story.
6. Sequencing and liveness: action choreography (wait-for conditions,
   retries), deadlines, and what "the page never settled" looks like as a
   typed outcome.
7. Windows/Linux story: macOS ships first; where the platform seam sits so
   the planes port without a rewrite.

## Non-goals (v1)

- No autonomous unattended machine driving: v1 assumes an attended session or
  explicitly granted conversation scope.
- No credential entry automation (see credential boundary).
- No video capture; stills and action results only until the streaming lane.
- No Windows/Linux computer plane (browser plane is portable sooner).

## Sequencing

1. Design rounds on the open questions (Ufuk seeds with initial documents;
   adversarial gates per fleet practice).
2. Walking skeleton: browser plane, one managed profile, navigate/read/click
   against a real page over the subc wire.
3. Computer plane behind the grant ceremony, macOS only.
4. Streaming/live-view lane when the Cortex app needs it.
