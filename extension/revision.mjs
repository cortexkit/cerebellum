// The revision of the contract between this extension and cerebellum: the
// plans cerebellum sends and the replies and refusals this extension returns
// (see PROTOCOL.md). Cerebellum requires an exact match and refuses every
// action with extension_outdated or extension_newer otherwise, telling the
// agent to have the person reload the extension. Raise it by one, together
// with EXTENSION_REVISION in crates/cerebellum/src/user_browser.rs, whenever a
// plan, reply or refusal shape changes. The manifest `version` cannot serve
// here: Chrome keeps running whatever unpacked copy it loaded, and an old copy
// can carry the same `version` as a new one.
export const EXTENSION_REVISION = 2;
