// The revision of the contract between this extension and cerebellum: the
// plans cerebellum sends and the replies and refusals this extension returns
// (see PROTOCOL.md). Cerebellum accepts revision 4 for existing actions, but
// requires revision 5 for native option selection, telling the
// agent to have the person reload the extension. Raise it by one, together
// with EXTENSION_REVISION in crates/cerebellum/src/user_browser/revision.rs,
// whenever a plan, reply or refusal shape changes, or when an extension fix
// must reach the person's Chrome (revision 6: pop-up claims and held input).
// The manifest `version` cannot serve here: Chrome keeps running whatever unpacked copy it loaded, and an old copy
// can carry the same `version` as a new one.
export const EXTENSION_REVISION = 6;
