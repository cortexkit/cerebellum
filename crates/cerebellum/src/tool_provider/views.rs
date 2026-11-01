//! Display views for the apps' tool rows, served by `tool.views`.
//!
//! A view is keyed by a schema pin: `tp1:<tool>:<schema digest>:<semantics>`,
//! which names one version of one tool's definition. Old transcripts keep the
//! pin their call was made with, so once a pin's view is published it must keep
//! being served, with the same record schema and reads, even after the tool's
//! definition changes. `published-v1.json` is that permanent list.

use super::*;
use cortexkit_role_tool_provider::views::{ViewEntry, ViewManifest, ViewsReply, ViewsRequest};

const PUBLISHED: &str = include_str!("../../resources/tool-views/published-v1.json");
const BROWSER_ROW: &str = include_str!("../../resources/tool-views/browser-row.ui");
const BROWSER_PAGE: &str = include_str!("../../resources/tool-views/browser-page.ui");
const COMPUTER_ROW: &str = include_str!("../../resources/tool-views/computer-row.ui");
const COMPUTER_PAGE: &str = include_str!("../../resources/tool-views/computer-page.ui");

/// The tool catalog the templates are written against, as `occipital-check
/// --catalog` prints it. Catalog 1.1 changed digest before it shipped (Slots now
/// take their widths first in a row), and the display server refuses a template
/// naming the old one.
const TOOL_CATALOG_DIGEST: &str =
    "sha256:9a23139f4f1f48d6ed366a4a48b9221b1e5ac0ccd87473c0b241b8a37a876fbf";

/// Raised whenever a template changes. A pin's record schema and reads never
/// change; the display server replaces a kept view only at a higher revision.
pub(crate) const TEMPLATE_REVISION: u64 = 2;

fn template(profile: &str, source: &str) -> Value {
    json!({
        "schema": "occipital.template/1", "profile": profile, "executionDialect": "1.0",
        "catalog": {"version": "1.1", "digest": TOOL_CATALOG_DIGEST},
        "reads": [], "source": source,
    })
}

fn published() -> BTreeMap<String, ViewManifest> {
    let entries: BTreeMap<String, Value> =
        serde_json::from_str(PUBLISHED).expect("published views");
    entries
        .into_iter()
        .map(|(pin, entry)| {
            let tool = SchemaPin::parse(&pin).expect("published pin").tool;
            let (row, page) = match tool.as_str() {
                flat_tools::BROWSER_USE => (BROWSER_ROW, BROWSER_PAGE),
                flat_tools::COMPUTER_USE => (COMPUTER_ROW, COMPUTER_PAGE),
                _ => panic!("published pin has no templates"),
            };
            let schema =
                serde_json::from_value(entry["record_schema"].clone()).expect("kept schema");
            let reads = serde_json::from_value(entry["reads"].clone()).expect("kept reads");
            let template = json!({
                "row": template("tool_row", row),
                "page": template("tool_page", page),
            });
            (
                pin,
                ViewManifest::new(schema, reads, template)
                    .with_template_revision(TEMPLATE_REVISION),
            )
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
