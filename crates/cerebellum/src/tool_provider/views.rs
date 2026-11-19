//! Display views for the apps' tool rows, served by `tool.views`.
//!
//! A view is keyed by a schema pin: `tp1:<tool>:<schema digest>:<semantics>`,
//! which names one version of one tool's definition. Old transcripts keep the
//! pin their call was made with, so once a pin's view is published it must keep
//! being served, with the same record schema, reads and tool definition, even
//! after the tool's definition changes. `published-v1.json` is that permanent
//! list, and it stores each pin's tool definition as data: the display server
//! recomputes the pin from it, so a pin that has left the current catalog still
//! renders.

use super::*;
use cortexkit_role_tool_provider::views::{ViewEntry, ViewManifest, ViewsReply, ViewsRequest};

const PUBLISHED: &str = include_str!("../../resources/tool-views/published-v1.json");
const POINTER_FRONTING_PUBLISHED: &str =
    include_str!("../../resources/tool-views/published-v2.json");
const POINTER_MOVE_SCROLL_PUBLISHED: &str =
    include_str!("../../resources/tool-views/published-v3.json");
const BROWSER_FILTERED_WAIT_PUBLISHED: &str =
    include_str!("../../resources/tool-views/published-v4.json");
const BROWSER_ROW: &str = include_str!("../../resources/tool-views/browser-row.ui");
const BROWSER_PAGE: &str = include_str!("../../resources/tool-views/browser-page.ui");
const COMPUTER_ROW: &str = include_str!("../../resources/tool-views/computer-row.ui");
const COMPUTER_PAGE: &str = include_str!("../../resources/tool-views/computer-page.ui");

/// The tool catalog the templates are written against, as `occipital-check
/// --catalog` prints it. Catalog 1.1 has had more than one digest while it grew
/// (only additions, so templates check and draw the same), and the display
/// server refuses a template naming a retired one.
const TOOL_CATALOG_DIGEST: &str =
    "sha256:af4559652b832b8908f4dc39364874eea6950ab708567e70f17d304e8c0f9a32";

/// Raised whenever a template changes. A pin's record schema and reads never
/// change; the display server replaces a kept view only at a higher revision.
pub(crate) const TEMPLATE_REVISION: u64 = 4;

fn template(profile: &str, source: &str) -> Value {
    json!({
        "schema": "occipital.template/1", "profile": profile, "executionDialect": "1.0",
        "catalog": {"version": "1.1", "digest": TOOL_CATALOG_DIGEST},
        "reads": [], "source": source,
    })
}

fn templates(tool: &str) -> (&'static str, &'static str) {
    match tool {
        flat_tools::BROWSER_USE => (BROWSER_ROW, BROWSER_PAGE),
        flat_tools::COMPUTER_USE => (COMPUTER_ROW, COMPUTER_PAGE),
        _ => panic!("published pin has no templates"),
    }
}

/// The view for one pin, read from the published table as data. Neither the
/// record schema, the reads nor the tool definition is rebuilt from current
/// code, so a later definition change cannot alter a pin already served.
fn view(pin: &str, entry: &Value) -> ViewManifest {
    let tool = SchemaPin::parse(pin).expect("published pin").tool;
    let (row, page) = templates(&tool);
    let schema = serde_json::from_value(entry["record_schema"].clone()).expect("kept schema");
    let reads = serde_json::from_value(entry["reads"].clone()).expect("kept reads");
    let tool = serde_json::from_value(entry["tool"].clone()).expect("kept tool definition");
    let template = json!({
        "row": template("tool_row", row),
        "page": template("tool_page", page),
    });
    ViewManifest::new(schema, reads, template)
        .with_template_revision(TEMPLATE_REVISION)
        .with_tool(tool)
}

fn published() -> BTreeMap<String, ViewManifest> {
    let mut entries: BTreeMap<String, Value> =
        serde_json::from_str(PUBLISHED).expect("published views");
    for table in [
        POINTER_FRONTING_PUBLISHED,
        POINTER_MOVE_SCROLL_PUBLISHED,
        BROWSER_FILTERED_WAIT_PUBLISHED,
    ] {
        let addition: BTreeMap<String, Value> =
            serde_json::from_str(table).expect("pointer-fronting published views");
        for (pin, entry) in addition {
            assert!(
                entries.insert(pin, entry).is_none(),
                "a published pin must never be replaced"
            );
        }
    }
    entries
        .into_iter()
        .map(|(pin, entry)| {
            let view = view(&pin, &entry);
            (pin, view)
        })
        .collect()
}

/// Keep the bucket payload on the same builder and JSON encoding as tool.views.
pub(super) fn published_replies() -> Vec<(String, Vec<u8>)> {
    published()
        .into_keys()
        .map(|pin| {
            let reply = answer(json!({"pins": [&pin]}).as_object().expect("request object"))
                .expect("published pin request");
            (pin, serde_json::to_vec(&reply).expect("views serialize"))
        })
        .collect()
}

pub(super) fn answer(arguments: &Map<String, Value>) -> Result<Value, ErrorBody> {
    if let Some(field) = arguments.keys().find(|field| field.as_str() != "pins") {
        return Err(errors::invalid_request(field, "unknown views member"));
    }
    let request: ViewsRequest = serde_json::from_value(Value::Object(arguments.clone()))
        .map_err(|_| errors::invalid_request("pins", "expected an array of pins"))?;
    request.validate()?;
    let kept = published();
    let reply = ViewsReply::new(
        request
            .pins
            .iter()
            .map(|pin| {
                let view = kept
                    .get(pin)
                    .cloned()
                    .map(ViewEntry::Manifest)
                    .unwrap_or(ViewEntry::Unknown);
                (pin.clone(), view)
            })
            .collect(),
    );
    Ok(serde_json::to_value(reply).expect("views serialize"))
}

#[cfg(test)]
mod tests;
