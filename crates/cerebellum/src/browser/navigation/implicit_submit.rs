use super::*;
use crate::classification::{ClassificationError, FormMethod, ImplicitSubmit};

impl DomClassificationContext<'_> {
    pub(super) fn implicit_submit(
        &self,
        target: usize,
        epoch: u64,
    ) -> Option<Result<ImplicitSubmit, ClassificationError>> {
        let owner = self.form_owner(target)?;
        if !blocks_implicit_submission(&self.nodes[target]) {
            return None;
        }
        let controls = self.indexes.controls_by_form.get(&owner)?;
        let mut submitters = controls.iter().copied().filter(|&index| {
            let node = &self.nodes[index];
            let in_select = node
                .parent_id
                .and_then(|parent| self.by_node_id.get(&parent))
                .is_some_and(|&parent| self.nodes[parent].local_name == "select");
            is_submit_button(node, in_select)
        });
        let first = submitters.next();
        let mut submitter = first;
        for candidate in submitters {
            // Do not guess which action URL Chrome will use if the flattened
            // capture cannot establish the order of competing submitters.
            let a = self.indexes.document_order[submitter.expect("first submitter")];
            let b = self.indexes.document_order[candidate];
            let (Some(a), Some(b)) = (a, b) else {
                return Some(Err(ClassificationError::DerivedFieldMismatch));
            };
            if b < a {
                submitter = Some(candidate);
            }
        }
        let mut activation = if let Some(index) = submitter {
            // A disabled default submitter stops implicit submission; a later
            // enabled button does not take its place.
            let element = self.element(index, false);
            if !classification::activation_invokes_submit(&element) {
                return None;
            }
            element
        } else {
            if controls
                .iter()
                .filter(|&&index| blocks_implicit_submission(&self.nodes[index]))
                .count()
                != 1
            {
                return None;
            }
            // Without a submitter, the form itself is the activation target.
            // Reuse the click classifier's submit model with the form identity
            // and the focused input's associated controls, not its field data.
            let mut element = self.element(target, false);
            element.identity = self.identity(owner);
            element.target_kind = TargetKind::Button;
            element.effective_input_type = Some("submit".into());
            element.autocomplete_tokens.clear();
            element.password = false;
            element.activation_destination =
                self.resolve_activation_destination(self.nodes[owner].attributes.get("action"));
            element
        };
        let method = submitter
            .and_then(|index| self.nodes[index].attributes.get("formmethod"))
            .or_else(|| self.nodes[owner].attributes.get("method"));
        let method = match method.map(|method| method.to_ascii_lowercase()).as_deref() {
            Some("post") => FormMethod::Post,
            Some("dialog") => FormMethod::Dialog,
            _ => FormMethod::Get,
        };
        if method == FormMethod::Dialog {
            // A dialog-method submission closes the dialog, not a request to
            // the action URL. Still apply the click policy for a form submit.
            activation.activation_destination = None;
        }
        Some(
            classification::classify_click(&NonTypeClassificationInput::new(
                epoch,
                activation,
                self.current_origin,
            ))
            .map(|activation| ImplicitSubmit {
                activation: Box::new(activation),
                method,
            }),
        )
    }
}

fn is_submit_button(node: &RawDomNode, in_select: bool) -> bool {
    let kind = node
        .attributes
        .get("type")
        .map(|kind| kind.to_ascii_lowercase());
    match node.local_name.as_str() {
        "button" => match kind.as_deref() {
            Some("submit") => true,
            Some("button" | "reset") => false,
            _ => {
                !in_select
                    && !node.attributes.contains_key("command")
                    && !node.attributes.contains_key("commandfor")
            }
        },
        "input" => matches!(kind.as_deref(), Some("submit" | "image")),
        _ => false,
    }
}

fn blocks_implicit_submission(node: &RawDomNode) -> bool {
    if node.local_name != "input" {
        return false;
    }
    // Unknown and missing input types both default to text in HTML.
    !matches!(
        node.attributes
            .get("type")
            .map(|kind| kind.to_ascii_lowercase())
            .as_deref(),
        Some(
            "hidden"
                | "checkbox"
                | "radio"
                | "file"
                | "submit"
                | "image"
                | "reset"
                | "button"
                | "range"
                | "color"
        )
    )
}
