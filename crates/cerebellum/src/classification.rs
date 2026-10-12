//! Classification for the minted, non-`browser.type` actions.
//!
//! `browser.type` has a frozen serialized record in `browser_type.rs`. The
//! click actions deliberately use a different record so that adding activation
//! semantics cannot silently change the fingerprint or the evidence check used
//! for authorization.

use std::cmp::Ordering;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const NON_TYPE_CLASSIFICATION_SCHEMA: &str = "ck-browser-non-type-classification-record/v1";
pub const MAX_IDENTITY_COMPONENT_BYTES: usize = 4096;
pub const MAX_STRING_BYTES: usize = 4096;
pub const MAX_ASSOCIATED_CONTROLS: usize = 4096;
pub const MAX_TOKENS_PER_CONTROL: usize = 4096;
pub const MAX_AGGREGATE_TOKENS: usize = 4096;
pub const MAX_CANONICAL_RECORD_BYTES: usize = 1_048_576;
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

const CREDENTIAL_TOKENS: &[&str] = &["current-password", "new-password", "one-time-code"];
const FINANCIAL_TOKENS: &[&str] = &[
    "cc-name",
    "cc-given-name",
    "cc-additional-name",
    "cc-family-name",
    "cc-number",
    "cc-exp",
    "cc-exp-month",
    "cc-exp-year",
    "cc-csc",
    "cc-type",
];

/// The closed target-kind vocabulary in the non-type record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum TargetKind {
    Button,
    Input,
    Anchor,
    Area,
    #[default]
    Other,
}

impl TargetKind {
    pub fn is_form_submit_candidate(self) -> bool {
        matches!(self, Self::Button | Self::Input)
    }

    pub fn is_navigation_target(self) -> bool {
        matches!(self, Self::Anchor | Self::Area)
    }
}

/// The CDP identity tuple from which a stable, opaque node identity is made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeIdentityInput {
    pub target_id: String,
    pub frame_id: String,
    pub backend_node_id: u64,
}

impl NodeIdentityInput {
    pub fn new(
        target_id: impl Into<String>,
        frame_id: impl Into<String>,
        backend_node_id: u64,
    ) -> Self {
        Self {
            target_id: target_id.into(),
            frame_id: frame_id.into(),
            backend_node_id,
        }
    }

    pub fn validate(&self) -> Result<(), ClassificationError> {
        bounded_identity_component("target_id", &self.target_id)?;
        bounded_identity_component("frame_id", &self.frame_id)?;
        if !(1..=MAX_SAFE_INTEGER).contains(&self.backend_node_id) {
            return Err(ClassificationError::IdentityInputOutOfBounds {
                field: "backend_node_id",
            });
        }
        Ok(())
    }

    /// Construct the identity required by the record contract.  The digest
    /// covers canonical JSON rather than a debug representation or a map key.
    pub fn identity(&self) -> Result<String, ClassificationError> {
        self.validate()?;
        let value = serde_json::json!({
            "target_id": self.target_id,
            "frame_id": self.frame_id,
            "backend_node_id": self.backend_node_id,
        });
        Ok(sha256_hex(&canonical_json_bytes(&value)))
    }
}

/// A form-associated control examined for submit-target classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssociatedFormControlInput {
    pub identity: NodeIdentityInput,
    pub form_owner: Option<NodeIdentityInput>,
    pub autocomplete_tokens: Vec<String>,
    pub password: bool,
}

impl AssociatedFormControlInput {
    pub fn new(identity: NodeIdentityInput) -> Self {
        Self {
            identity,
            form_owner: None,
            autocomplete_tokens: Vec::new(),
            password: false,
        }
    }

    pub fn with_form_owner(mut self, owner: NodeIdentityInput) -> Self {
        self.form_owner = Some(owner);
        self
    }

    pub fn with_tokens(mut self, tokens: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.autocomplete_tokens = tokens.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_password(mut self, password: bool) -> Self {
        self.password = password;
        self
    }
}

impl Default for AssociatedFormControlInput {
    fn default() -> Self {
        Self::new(NodeIdentityInput::new("target", "frame", 1))
    }
}

/// A bounded element observation.  It contains only DOM facts needed by the
/// activation-target rules; text, accessible names, roles, and caller intent
/// are intentionally absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElementClassificationInput {
    pub identity: NodeIdentityInput,
    pub target_kind: TargetKind,
    pub effective_input_type: Option<String>,
    pub autocomplete_tokens: Vec<String>,
    pub password: bool,
    pub disabled: bool,
    pub form_owner: Option<NodeIdentityInput>,
    pub associated_form_controls: Vec<AssociatedFormControlInput>,
    /// A statically declared built-in href/form-action URL.  Author-script
    /// destinations are never supplied here.
    pub activation_destination: Option<String>,
    /// True for a built-in button/input/anchor/area activation behavior.  The
    /// explicit bit lets fixtures represent standard elements after retargeting
    /// without teaching this module about custom-element behavior.
    pub built_in_activation: bool,
    /// True when the node is a label participating in standardized label
    /// forwarding.  `label_control` is the forwarded control, if any.
    pub is_label: bool,
    pub label_control: Option<Box<ElementClassificationInput>>,
}

impl Default for ElementClassificationInput {
    fn default() -> Self {
        Self {
            identity: NodeIdentityInput::new("target", "frame", 1),
            target_kind: TargetKind::Other,
            effective_input_type: None,
            autocomplete_tokens: Vec::new(),
            password: false,
            disabled: false,
            form_owner: None,
            associated_form_controls: Vec::new(),
            activation_destination: None,
            built_in_activation: false,
            is_label: false,
            label_control: None,
        }
    }
}

impl ElementClassificationInput {
    pub fn new(identity: NodeIdentityInput, target_kind: TargetKind) -> Self {
        Self {
            identity,
            target_kind,
            built_in_activation: !matches!(target_kind, TargetKind::Other),
            ..Self::default()
        }
    }

    pub fn input_type(mut self, input_type: impl Into<String>) -> Self {
        self.effective_input_type = Some(input_type.into());
        self
    }

    pub fn autocomplete(mut self, tokens: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.autocomplete_tokens = tokens.into_iter().map(Into::into).collect();
        self
    }

    pub fn form_owner(mut self, owner: NodeIdentityInput) -> Self {
        self.form_owner = Some(owner);
        self
    }

    pub fn disabled(mut self, disabled: bool) -> Self {
        self.disabled = disabled;
        self
    }

    pub fn password(mut self, password: bool) -> Self {
        self.password = password;
        self
    }

    pub fn destination(mut self, destination: impl Into<String>) -> Self {
        self.activation_destination = Some(destination.into());
        self
    }

    pub fn associated_control(mut self, control: AssociatedFormControlInput) -> Self {
        self.associated_form_controls.push(control);
        self
    }

    pub fn label_for(mut self, control: ElementClassificationInput) -> Self {
        self.is_label = true;
        self.label_control = Some(Box::new(control));
        self
    }

    pub fn built_in_activation(mut self, value: bool) -> Self {
        self.built_in_activation = value;
        self
    }
}

/// One pre-commit classification observation.  `composed_ancestors` is in
/// nearest-first order, matching the deterministic composed-tree walk.  A
/// label's standardized forwarded control is represented by `label_control` on
/// the classified node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonTypeClassificationInput {
    pub document_epoch: u64,
    pub target: ElementClassificationInput,
    pub composed_ancestors: Vec<ElementClassificationInput>,
    pub current_top_level_origin: String,
}

impl NonTypeClassificationInput {
    pub fn new(
        document_epoch: u64,
        target: ElementClassificationInput,
        origin: impl Into<String>,
    ) -> Self {
        Self {
            document_epoch,
            target,
            composed_ancestors: Vec::new(),
            current_top_level_origin: origin.into(),
        }
    }

    pub fn with_composed_ancestor(mut self, ancestor: ElementClassificationInput) -> Self {
        self.composed_ancestors.push(ancestor);
        self
    }
}

/// The exact closed record used by `browser.click` and `browser.click_point`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonTypeClassificationRecord {
    pub schema: String,
    pub node_identity: String,
    pub activation_target_identity: String,
    pub document_epoch: u64,
    pub target_kind: TargetKind,
    pub effective_input_type: Option<String>,
    pub activation_invokes_form_submit: bool,
    pub form_owner: Option<String>,
    pub current_top_level_origin: String,
    pub activation_destination_origin: Option<String>,
    pub target_autocomplete_tokens: Vec<String>,
    pub target_password: bool,
    pub associated_form_controls: Vec<AssociatedFormControl>,
    pub required_tier: u8,
    pub credential: bool,
    pub financial: bool,
}

/// The associated-control projection retained in the closed record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssociatedFormControl {
    pub node_identity: String,
    pub autocomplete_tokens: Vec<String>,
    pub password: bool,
}

impl NonTypeClassificationRecord {
    /// Whether this record describes a field that may receive a credential.
    ///
    /// This is the same direct-field predicate used by the typing path: password
    /// inputs and the three credential autocomplete tokens. Associated controls
    /// do not make a non-field submit button into a credential field.
    pub fn is_credential_field(&self) -> bool {
        self.target_password
            || self.effective_input_type.as_deref() == Some("password")
            || self
                .target_autocomplete_tokens
                .iter()
                .any(|token| credential_token(token))
    }

    pub fn validate(&self) -> Result<(), ClassificationError> {
        if self.schema != NON_TYPE_CLASSIFICATION_SCHEMA {
            return Err(ClassificationError::WrongSchema);
        }
        validate_identity_string("node_identity", &self.node_identity)?;
        validate_identity_string(
            "activation_target_identity",
            &self.activation_target_identity,
        )?;
        if !(0..=MAX_SAFE_INTEGER).contains(&self.document_epoch) {
            return Err(ClassificationError::IdentityInputOutOfBounds {
                field: "document_epoch",
            });
        }
        if !(1..=5).contains(&self.required_tier) {
            return Err(ClassificationError::RequiredTierOutOfBounds);
        }
        if let Some(input_type) = &self.effective_input_type {
            bounded_lower_ascii("effective_input_type", input_type)?;
        }
        validate_origin("current_top_level_origin", &self.current_top_level_origin)?;
        if let Some(origin) = &self.activation_destination_origin {
            validate_origin("activation_destination_origin", origin)?;
        }
        validate_tokens(
            "target_autocomplete_tokens",
            &self.target_autocomplete_tokens,
        )?;
        if self.associated_form_controls.len() > MAX_ASSOCIATED_CONTROLS {
            return Err(ClassificationError::CollectionOutOfBounds {
                field: "associated_form_controls",
            });
        }
        let mut aggregate = self.target_autocomplete_tokens.len();
        if aggregate > MAX_AGGREGATE_TOKENS {
            return Err(ClassificationError::AggregateTokenLimit);
        }
        for control in &self.associated_form_controls {
            validate_identity_string(
                "associated_form_controls.node_identity",
                &control.node_identity,
            )?;
            validate_tokens(
                "associated_form_controls.autocomplete_tokens",
                &control.autocomplete_tokens,
            )?;
            aggregate = aggregate
                .checked_add(control.autocomplete_tokens.len())
                .ok_or(ClassificationError::AggregateTokenLimit)?;
            if aggregate > MAX_AGGREGATE_TOKENS {
                return Err(ClassificationError::AggregateTokenLimit);
            }
        }
        let computed = compute_flags(
            self.target_kind,
            self.activation_invokes_form_submit,
            &self.target_autocomplete_tokens,
            self.target_password,
            &self.associated_form_controls,
        );
        if computed.0 != self.credential || computed.1 != self.financial {
            return Err(ClassificationError::DerivedFieldMismatch);
        }
        let expected_tier = activation_tier(
            self.target_kind,
            self.activation_invokes_form_submit,
            self.credential,
            self.financial,
            &self.current_top_level_origin,
            self.activation_destination_origin.as_deref(),
        );
        if self.required_tier != expected_tier {
            return Err(ClassificationError::DerivedFieldMismatch);
        }
        Ok(())
    }

    /// Serialize the entire record as RFC 8785-style canonical JSON.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ClassificationError> {
        self.validate()?;
        let value = serde_json::to_value(self).map_err(|_| ClassificationError::Serialization)?;
        let bytes = canonical_json_bytes(&value);
        if bytes.len() > MAX_CANONICAL_RECORD_BYTES {
            return Err(ClassificationError::CanonicalRecordOutOfBounds);
        }
        Ok(bytes)
    }

    pub fn fingerprint(&self) -> NonTypeClassificationFingerprint {
        // A record obtained from `classify` is validated. Keeping this method
        // infallible makes equality-only verification small at the authorization
        // boundary; callers that receive external data must call `try_fingerprint`.
        NonTypeClassificationFingerprint(
            Sha256::digest(
                self.canonical_bytes()
                    .expect("non-type classification fingerprint requires a valid record"),
            )
            .into(),
        )
    }

    pub fn try_fingerprint(&self) -> Result<NonTypeClassificationFingerprint, ClassificationError> {
        Ok(NonTypeClassificationFingerprint(
            Sha256::digest(self.canonical_bytes()?).into(),
        ))
    }

    pub fn required_severity_tier(&self) -> u8 {
        self.required_tier
    }
}

/// Opaque equality-only fingerprint for the non-type record.  This type is
/// intentionally distinct from `browser_type::ClassificationFingerprint`.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NonTypeClassificationFingerprint([u8; 32]);

impl NonTypeClassificationFingerprint {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn as_hex(&self) -> String {
        hex_digest(&self.0)
    }
}

impl fmt::Debug for NonTypeClassificationFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("NonTypeClassificationFingerprint")
            .field(&self.as_hex())
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassificationError {
    WrongSchema,
    MissingIdentity { field: &'static str },
    IdentityInputOutOfBounds { field: &'static str },
    IdentityStringMalformed { field: &'static str },
    StringOutOfBounds { field: &'static str },
    CollectionOutOfBounds { field: &'static str },
    AggregateTokenLimit,
    InvalidToken { field: &'static str },
    RequiredTierOutOfBounds,
    InvalidOrigin { field: &'static str },
    InvalidDestination,
    CanonicalRecordOutOfBounds,
    DerivedFieldMismatch,
    Serialization,
}

impl ClassificationError {
    /// Stable snake_case name for this rejection, safe to show a caller.
    pub fn code(&self) -> &'static str {
        match self {
            Self::WrongSchema => "wrong_schema",
            Self::MissingIdentity { .. } => "missing_identity",
            Self::IdentityInputOutOfBounds { .. } => "identity_input_out_of_bounds",
            Self::IdentityStringMalformed { .. } => "identity_string_malformed",
            Self::StringOutOfBounds { .. } => "string_out_of_bounds",
            Self::CollectionOutOfBounds { .. } => "collection_out_of_bounds",
            Self::AggregateTokenLimit => "aggregate_token_limit",
            Self::InvalidToken { .. } => "invalid_token",
            Self::RequiredTierOutOfBounds => "required_tier_out_of_bounds",
            Self::InvalidOrigin { .. } => "invalid_origin",
            Self::InvalidDestination => "invalid_destination",
            Self::CanonicalRecordOutOfBounds => "canonical_record_out_of_bounds",
            Self::DerivedFieldMismatch => "derived_field_mismatch",
            Self::Serialization => "serialization",
        }
    }

    /// The record or input field the rejection names, when it names one.
    pub fn field(&self) -> Option<&'static str> {
        match self {
            Self::MissingIdentity { field }
            | Self::IdentityInputOutOfBounds { field }
            | Self::IdentityStringMalformed { field }
            | Self::StringOutOfBounds { field }
            | Self::CollectionOutOfBounds { field }
            | Self::InvalidToken { field }
            | Self::InvalidOrigin { field } => Some(field),
            Self::WrongSchema
            | Self::AggregateTokenLimit
            | Self::RequiredTierOutOfBounds
            | Self::InvalidDestination
            | Self::CanonicalRecordOutOfBounds
            | Self::DerivedFieldMismatch
            | Self::Serialization => None,
        }
    }
}

impl fmt::Display for ClassificationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ClassificationError {}

/// Why a click target has no classification record.
///
/// Authorization treats every one of these the same way: the target might
/// submit a form nobody inspected, so it requires the strongest disclosure.
/// The distinction exists for the caller and for diagnosis. Without it, "the
/// DOM projection could not be read" and "the classifier refused this page's
/// origin" produce the same refusal, and nobody can tell which one happened.
///
/// Each variant names exactly one cause and carries only structural facts
/// (positions, CDP node ids, field names), never page text or URLs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClassificationUnavailable {
    /// The observation was captured without asking for form facts.
    NotCaptured,
    /// The document URL yields no origin the classifier accepts, for example
    /// `about:blank`, a non-HTTP scheme, or a URL carrying credentials.
    DocumentOriginUnavailable,
    /// `DOM.enable` answered with an error or with no result.
    DomEnableRefused,
    /// `DOM.getFlattenedDocument` answered with an error.
    FlattenedDocumentRefused,
    /// Reading the DOM failed at the transport level (for example, no answer
    /// before the deadline).
    DomReadFailed,
    /// The flattened document has no `nodes` array.
    FlattenedNodesMissing,
    /// The entry at `index` in `nodes` is not an object.
    NodeNotObject { index: usize },
    /// The entry at `index` lacks, or has an unusable, `field`.
    NodeFieldInvalid { index: usize, field: &'static str },
    /// Element `node_id` has no `attributes` array.
    AttributesMissing { node_id: u64 },
    /// Element `node_id` has an attribute array that is not name/value pairs.
    AttributesOddLength { node_id: u64, length: usize },
    /// Element `node_id` has a non-string entry at `position` in its
    /// attribute array.
    AttributeNotString { node_id: u64, position: usize },
    /// Element `node_id` names the same attribute twice, so which value the
    /// browser uses is unknown.
    DuplicateAttribute { node_id: u64 },
    /// Two elements share `node_id`.
    DuplicateNodeId { node_id: u64 },
    /// Two elements share `backend_node_id`.
    DuplicateBackendNodeId { backend_node_id: u64 },
    /// The clicked element is not among the document's elements.
    TargetNotInDocument { backend_node_id: u64 },
    /// Walking up from the target revisits element `node_id`.
    ComposedParentCycle { node_id: u64 },
    /// The DOM projection was complete and the classifier refused it.
    ClassifierRejected(ClassificationError),
}

impl ClassificationUnavailable {
    /// Stable snake_case name for this cause, carried to the caller.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::NotCaptured => "not_captured",
            Self::DocumentOriginUnavailable => "document_origin_unavailable",
            Self::DomEnableRefused => "dom_enable_refused",
            Self::FlattenedDocumentRefused => "flattened_document_refused",
            Self::DomReadFailed => "dom_read_failed",
            Self::FlattenedNodesMissing => "flattened_nodes_missing",
            Self::NodeNotObject { .. } => "node_not_object",
            Self::NodeFieldInvalid { .. } => "node_field_invalid",
            Self::AttributesMissing { .. } => "attributes_missing",
            Self::AttributesOddLength { .. } => "attributes_odd_length",
            Self::AttributeNotString { .. } => "attribute_not_string",
            Self::DuplicateAttribute { .. } => "duplicate_attribute",
            Self::DuplicateNodeId { .. } => "duplicate_node_id",
            Self::DuplicateBackendNodeId { .. } => "duplicate_backend_node_id",
            Self::TargetNotInDocument { .. } => "target_not_in_document",
            Self::ComposedParentCycle { .. } => "composed_parent_cycle",
            Self::ClassifierRejected(_) => "classifier_rejected",
        }
    }

    /// The identifying facts of this cause as a JSON object. Keys are drawn
    /// from a fixed set so a reply schema can declare every one of them.
    pub fn facts(&self) -> serde_json::Map<String, Value> {
        let mut facts = serde_json::Map::new();
        match self {
            Self::NotCaptured
            | Self::DocumentOriginUnavailable
            | Self::DomEnableRefused
            | Self::FlattenedDocumentRefused
            | Self::DomReadFailed
            | Self::FlattenedNodesMissing => {}
            Self::NodeNotObject { index } => {
                facts.insert("index".into(), Value::from(*index));
            }
            Self::NodeFieldInvalid { index, field } => {
                facts.insert("index".into(), Value::from(*index));
                facts.insert("field".into(), Value::from(*field));
            }
            Self::AttributesMissing { node_id } | Self::DuplicateAttribute { node_id } => {
                facts.insert("node_id".into(), Value::from(*node_id));
            }
            Self::AttributesOddLength { node_id, length } => {
                facts.insert("node_id".into(), Value::from(*node_id));
                facts.insert("length".into(), Value::from(*length));
            }
            Self::AttributeNotString { node_id, position } => {
                facts.insert("node_id".into(), Value::from(*node_id));
                facts.insert("position".into(), Value::from(*position));
            }
            Self::DuplicateNodeId { node_id } | Self::ComposedParentCycle { node_id } => {
                facts.insert("node_id".into(), Value::from(*node_id));
            }
            Self::DuplicateBackendNodeId { backend_node_id }
            | Self::TargetNotInDocument { backend_node_id } => {
                facts.insert("backend_node_id".into(), Value::from(*backend_node_id));
            }
            Self::ClassifierRejected(error) => {
                facts.insert("classifier_error".into(), Value::from(error.code()));
                if let Some(field) = error.field() {
                    facts.insert("field".into(), Value::from(field));
                }
            }
        }
        facts
    }
}

impl fmt::Display for ClassificationUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason_code())?;
        let facts = self.facts();
        if !facts.is_empty() {
            write!(f, " {}", Value::Object(facts))?;
        }
        Ok(())
    }
}

impl std::error::Error for ClassificationUnavailable {}

/// Classify a non-type action target.  Point-click uses the same function after
/// its topmost hit-test has selected the `target` node.
pub fn classify_non_type(
    input: &NonTypeClassificationInput,
) -> Result<NonTypeClassificationRecord, ClassificationError> {
    if input.document_epoch > MAX_SAFE_INTEGER {
        return Err(ClassificationError::IdentityInputOutOfBounds {
            field: "document_epoch",
        });
    }
    let current_origin = canonical_origin(&input.current_top_level_origin).ok_or(
        ClassificationError::InvalidOrigin {
            field: "current_top_level_origin",
        },
    )?;
    let activation_target = derive_activation_target(&input.target, &input.composed_ancestors)?;
    let node_identity =
        input
            .target
            .identity
            .identity()
            .map_err(|_| ClassificationError::MissingIdentity {
                field: "node_identity",
            })?;
    let activation_target_identity = activation_target.identity.identity().map_err(|_| {
        ClassificationError::MissingIdentity {
            field: "activation_target_identity",
        }
    })?;
    let form_owner = activation_target
        .form_owner
        .as_ref()
        .map(NodeIdentityInput::identity)
        .transpose()
        .map_err(|_| ClassificationError::MissingIdentity {
            field: "form_owner",
        })?;

    validate_element(activation_target)?;
    let associated_form_controls = activation_target
        .associated_form_controls
        .iter()
        .filter(|control| {
            control.form_owner.is_none()
                || control.form_owner.as_ref() == activation_target.form_owner.as_ref()
        })
        .map(|control| {
            Ok(AssociatedFormControl {
                node_identity: control.identity.identity().map_err(|_| {
                    ClassificationError::MissingIdentity {
                        field: "associated_form_controls.node_identity",
                    }
                })?,
                autocomplete_tokens: control.autocomplete_tokens.clone(),
                password: control.password,
            })
        })
        .collect::<Result<Vec<_>, ClassificationError>>()?;

    let activation_invokes_form_submit = activation_invokes_submit(activation_target);
    let activation_destination_origin = if !activation_target.disabled
        && (activation_target.target_kind.is_navigation_target() || activation_invokes_form_submit)
    {
        if let Some(destination) = activation_target.activation_destination.as_deref() {
            Some(
                canonical_origin_from_url(destination)
                    .ok_or(ClassificationError::InvalidDestination)?,
            )
        } else {
            None
        }
    } else {
        None
    };
    let (credential, financial) = compute_flags(
        activation_target.target_kind,
        activation_invokes_form_submit,
        &activation_target.autocomplete_tokens,
        activation_target.password,
        &associated_form_controls,
    );
    let required_tier = activation_tier(
        activation_target.target_kind,
        activation_invokes_form_submit,
        credential,
        financial,
        &current_origin,
        activation_destination_origin.as_deref(),
    );

    let record = NonTypeClassificationRecord {
        schema: NON_TYPE_CLASSIFICATION_SCHEMA.to_string(),
        node_identity,
        activation_target_identity,
        document_epoch: input.document_epoch,
        target_kind: activation_target.target_kind,
        effective_input_type: effective_input_type(activation_target)?,
        activation_invokes_form_submit,
        form_owner,
        current_top_level_origin: current_origin,
        activation_destination_origin,
        target_autocomplete_tokens: activation_target.autocomplete_tokens.clone(),
        target_password: activation_target.password,
        associated_form_controls,
        required_tier,
        credential,
        financial,
    };
    record.validate().map_err(|error| match error {
        ClassificationError::CanonicalRecordOutOfBounds => error,
        other => other,
    })?;
    // Check the bound as part of initial collection, before the caller can use
    // this record for a grant decision.
    record.canonical_bytes()?;
    Ok(record)
}

pub fn classify_click(
    input: &NonTypeClassificationInput,
) -> Result<NonTypeClassificationRecord, ClassificationError> {
    classify_non_type(input)
}

pub fn classify_click_point(
    input: &NonTypeClassificationInput,
) -> Result<NonTypeClassificationRecord, ClassificationError> {
    classify_non_type(input)
}

/// Final verification is equality-only.  The candidate is never returned as a
/// replacement and must not be passed to authorization by callers.
pub fn verify_classification_equality(
    initial: &NonTypeClassificationRecord,
    candidate: &NonTypeClassificationRecord,
) -> Result<(), ClassificationError> {
    initial.validate()?;
    candidate.validate()?;
    if initial.document_epoch != candidate.document_epoch {
        return Err(ClassificationError::IdentityStringMalformed {
            field: "document_epoch_changed",
        });
    }
    if initial.try_fingerprint()? != candidate.try_fingerprint()? {
        return Err(ClassificationError::IdentityStringMalformed {
            field: "resolved_node_changed",
        });
    }
    Ok(())
}

pub fn credential_token(token: &str) -> bool {
    CREDENTIAL_TOKENS.contains(&token)
}

pub fn financial_token(token: &str) -> bool {
    FINANCIAL_TOKENS.contains(&token)
}

fn derive_activation_target<'a>(
    target: &'a ElementClassificationInput,
    ancestors: &'a [ElementClassificationInput],
) -> Result<&'a ElementClassificationInput, ClassificationError> {
    // The nearest activation boundary wins: a nested button must not inherit
    // the behavior of a more distant link or label.
    for element in std::iter::once(target).chain(ancestors.iter()) {
        if element.is_label {
            if let Some(control) = element.label_control.as_deref() {
                return Ok(control);
            }
        }
        if element.built_in_activation {
            return Ok(element);
        }
    }
    Ok(target)
}

fn validate_element(element: &ElementClassificationInput) -> Result<(), ClassificationError> {
    element.identity.validate()?;
    if let Some(owner) = &element.form_owner {
        owner.validate()?;
    }
    if element.associated_form_controls.len() > MAX_ASSOCIATED_CONTROLS {
        return Err(ClassificationError::CollectionOutOfBounds {
            field: "associated_form_controls",
        });
    }
    validate_tokens("target_autocomplete_tokens", &element.autocomplete_tokens)?;
    let mut aggregate = element.autocomplete_tokens.len();
    for control in &element.associated_form_controls {
        control.identity.validate()?;
        if let Some(owner) = &control.form_owner {
            owner.validate()?;
        }
        validate_tokens(
            "associated_form_controls.autocomplete_tokens",
            &control.autocomplete_tokens,
        )?;
        aggregate = aggregate
            .checked_add(control.autocomplete_tokens.len())
            .ok_or(ClassificationError::AggregateTokenLimit)?;
        if aggregate > MAX_AGGREGATE_TOKENS {
            return Err(ClassificationError::AggregateTokenLimit);
        }
    }
    if element.effective_input_type.is_some()
        && !matches!(element.target_kind, TargetKind::Input | TargetKind::Button)
    {
        // Buttons retain their effective HTML type for submit detection, even
        // though the closed record emits null for non-input activation targets.
        return Err(ClassificationError::DerivedFieldMismatch);
    }
    if let Some(input_type) = &element.effective_input_type {
        bounded_lower_ascii("effective_input_type", input_type)?;
    }
    Ok(())
}

fn effective_input_type(
    element: &ElementClassificationInput,
) -> Result<Option<String>, ClassificationError> {
    if matches!(element.target_kind, TargetKind::Input) {
        let input_type = element.effective_input_type.as_deref().unwrap_or("text");
        bounded_lower_ascii("effective_input_type", input_type)?;
        Ok(Some(input_type.to_string()))
    } else {
        Ok(None)
    }
}

fn activation_invokes_submit(element: &ElementClassificationInput) -> bool {
    // Submission needs a form owner: an ancestor <form>, or a `form` attribute
    // naming a form in the same document. A submit-type control without one
    // submits nothing, so it must not be rated as a form submit (which would
    // ask for the highest grantable tier).
    if element.disabled || element.form_owner.is_none() {
        return false;
    }
    match element.target_kind {
        TargetKind::Button => {
            // HTML button's effective default type is submit.
            !matches!(
                element.effective_input_type.as_deref(),
                Some("button" | "reset")
            )
        }
        TargetKind::Input => matches!(
            element.effective_input_type.as_deref(),
            Some("submit" | "image")
        ),
        _ => false,
    }
}

fn compute_flags(
    target_kind: TargetKind,
    activation_invokes_submit: bool,
    target_tokens: &[String],
    target_password: bool,
    associated: &[AssociatedFormControl],
) -> (bool, bool) {
    let direct_credential =
        target_password || target_tokens.iter().any(|token| credential_token(token));
    let direct_financial = target_tokens.iter().any(|token| financial_token(token));
    let associated_credential = activation_invokes_submit
        && associated.iter().any(|control| {
            control.password
                || control
                    .autocomplete_tokens
                    .iter()
                    .any(|token| credential_token(token))
        });
    let associated_financial = activation_invokes_submit
        && associated.iter().any(|control| {
            control
                .autocomplete_tokens
                .iter()
                .any(|token| financial_token(token))
        });
    let associated_applies = target_kind.is_form_submit_candidate() && activation_invokes_submit;
    (
        direct_credential || (associated_applies && associated_credential),
        direct_financial || (associated_applies && associated_financial),
    )
}

fn bounded_identity_component(field: &'static str, value: &str) -> Result<(), ClassificationError> {
    if value.is_empty() || value.len() > MAX_IDENTITY_COMPONENT_BYTES {
        return Err(ClassificationError::IdentityInputOutOfBounds { field });
    }
    Ok(())
}

fn bounded_lower_ascii(field: &'static str, value: &str) -> Result<(), ClassificationError> {
    if value.is_empty()
        || value.len() > MAX_STRING_BYTES
        || !value.is_ascii()
        || value != value.to_ascii_lowercase()
    {
        return Err(ClassificationError::StringOutOfBounds { field });
    }
    Ok(())
}

fn validate_tokens(field: &'static str, tokens: &[String]) -> Result<(), ClassificationError> {
    if tokens.len() > MAX_TOKENS_PER_CONTROL {
        return Err(ClassificationError::CollectionOutOfBounds { field });
    }
    for token in tokens {
        bounded_lower_ascii(field, token)?;
    }
    Ok(())
}

fn validate_identity_string(field: &'static str, value: &str) -> Result<(), ClassificationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ClassificationError::IdentityStringMalformed { field });
    }
    Ok(())
}

fn validate_origin(field: &'static str, origin: &str) -> Result<(), ClassificationError> {
    if canonical_origin(origin).as_deref() != Some(origin) || origin.len() > MAX_STRING_BYTES {
        return Err(ClassificationError::InvalidOrigin { field });
    }
    Ok(())
}

/// Canonicalize an RFC 6454 origin.  This intentionally accepts only the
/// origins that can be used by the HTTP(S) browser plane plus the opaque
/// sentinel, and never retains URL paths, queries, fragments, or credentials.
pub fn canonical_origin(value: &str) -> Option<String> {
    if value == "null" {
        return Some("null".to_string());
    }
    let (scheme, authority) = value.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    if authority.is_empty() || authority.contains(['/', '?', '#', '@']) {
        return None;
    }
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let close = rest.find(']')?;
        let host = &rest[..close];
        let remaining = &rest[close + 1..];
        let port = if remaining.is_empty() {
            None
        } else {
            Some(remaining.strip_prefix(':')?)
        };
        (format!("[{host}]"), port)
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        if host.contains(':') {
            return None;
        }
        (host.to_string(), Some(port))
    } else {
        (authority.to_string(), None)
    };
    if host.is_empty() || !host.is_ascii() {
        return None;
    }
    let host = host.to_ascii_lowercase();
    let port = match port {
        Some(port) if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) => {
            let parsed = port.parse::<u16>().ok()?;
            if parsed == 0 {
                return None;
            }
            if (scheme == "http" && parsed == 80) || (scheme == "https" && parsed == 443) {
                None
            } else {
                Some(parsed.to_string())
            }
        }
        Some(_) => return None,
        None => None,
    };
    Some(match port {
        Some(port) => format!("{scheme}://{host}:{port}"),
        None => format!("{scheme}://{host}"),
    })
}

/// The canonical form of an origin a grant may name: an http or https scheme,
/// host and port, and nothing else.
///
/// `canonical_origin` also accepts the opaque origin `null`, because a live
/// page on about:blank, a data: URL or a sandboxed document really has that
/// origin and classification has to describe it. A grant must never name it:
/// `null` identifies no site, so the person asked to approve it cannot tell
/// what they are allowing, and every opaque document shares that one value, so
/// a grant for it would authorize reading all of them at once.
pub fn canonical_grant_origin(value: &str) -> Option<String> {
    canonical_origin(value).filter(|origin| origin != "null")
}

/// The canonical origin of an absolute http(s) URL, dropping its path, query
/// and fragment. Returns `None` for anything `canonical_origin` would refuse.
pub fn canonical_origin_from_url(value: &str) -> Option<String> {
    let (scheme, rest) = value.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    canonical_origin(&format!("{scheme}://{authority}"))
}

pub(crate) fn canonical_json_bytes(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_canonical_json(value, &mut out);
    out
}

fn write_canonical_json(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(value) => out.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(value) => out.extend_from_slice(value.to_string().as_bytes()),
        Value::String(value) => out.extend_from_slice(
            serde_json::to_string(value)
                .expect("string serialization")
                .as_bytes(),
        ),
        Value::Array(values) => {
            out.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    out.push(b',');
                }
                write_canonical_json(value, out);
            }
            out.push(b']');
        }
        Value::Object(values) => {
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_by(|(left, _), (right, _)| compare_utf16(left, right));
            out.push(b'{');
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    out.push(b',');
                }
                out.extend_from_slice(
                    serde_json::to_string(key)
                        .expect("key serialization")
                        .as_bytes(),
                );
                out.push(b':');
                write_canonical_json(value, out);
            }
            out.push(b'}');
        }
    }
}

// RFC 8785 orders object member names by their UTF-16 code units.
fn compare_utf16(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_digest(&Sha256::digest(bytes))
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

// Moving to a public page is reading, not a lasting change. Both the source and
// destination still pass authorization, so local destinations retain site consent.
fn activation_tier(
    kind: TargetKind,
    submits: bool,
    credential: bool,
    financial: bool,
    current: &str,
    destination: Option<&str>,
) -> u8 {
    let public_link = kind.is_navigation_target()
        && destination.is_some_and(crate::browser_standing_grants::origin_is_public);
    if submits
        || credential
        || financial
        || destination.is_some_and(|origin| origin != current && !public_link)
    {
        4
    } else if kind.is_navigation_target() && (destination == Some(current) || public_link) {
        1
    } else {
        2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(number: u64) -> NodeIdentityInput {
        NodeIdentityInput::new("target-1", "frame-1", number)
    }

    fn button() -> ElementClassificationInput {
        ElementClassificationInput::new(identity(1), TargetKind::Button)
            .form_owner(identity(2))
            .associated_control(
                AssociatedFormControlInput::new(identity(3)).with_tokens(["cc-number"]),
            )
    }

    #[test]
    fn non_type_record_is_distinct_and_uses_canonical_fingerprint() {
        let input = NonTypeClassificationInput::new(7, button(), "HTTPS://Example.test:443");
        let record = classify_click(&input).unwrap();
        assert_eq!(record.schema, NON_TYPE_CLASSIFICATION_SCHEMA);
        assert!(record.activation_invokes_form_submit);
        assert!(record.financial);
        assert_eq!(record.required_tier, 4);
        assert_eq!(record.current_top_level_origin, "https://example.test");
        assert_eq!(record.try_fingerprint().unwrap(), record.fingerprint());
        assert_eq!(record.canonical_bytes().unwrap(), {
            let value = serde_json::to_value(&record).unwrap();
            canonical_json_bytes(&value)
        });
    }

    #[test]
    fn unknown_cc_prefix_does_not_set_financial_flag() {
        let input = NonTypeClassificationInput::new(
            1,
            ElementClassificationInput::new(identity(1), TargetKind::Input)
                .input_type("text")
                .autocomplete(["cc-future-token"]),
            "https://example.test",
        );
        let record = classify_click(&input).unwrap();
        assert!(!record.financial);
    }

    #[test]
    fn label_and_composed_descendant_use_activation_target() {
        let control = ElementClassificationInput::new(identity(8), TargetKind::Input)
            .input_type("submit")
            .form_owner(identity(9));
        let label_descendant =
            ElementClassificationInput::new(identity(7), TargetKind::Other).label_for(control);
        let record = classify_click(&NonTypeClassificationInput::new(
            1,
            label_descendant,
            "https://example.test",
        ))
        .unwrap();
        assert_ne!(record.node_identity, record.activation_target_identity);
        assert!(record.activation_invokes_form_submit);
        assert_eq!(record.required_tier, 4);
    }

    #[test]
    fn final_verification_does_not_adopt_candidate() {
        let initial = classify_click(&NonTypeClassificationInput::new(
            1,
            ElementClassificationInput::new(identity(1), TargetKind::Button),
            "https://example.test",
        ))
        .unwrap();
        let candidate = classify_click(&NonTypeClassificationInput::new(
            1,
            ElementClassificationInput::new(identity(2), TargetKind::Button),
            "https://example.test",
        ))
        .unwrap();
        assert!(verify_classification_equality(&initial, &candidate).is_err());
        assert_eq!(initial.node_identity, identity(1).identity().unwrap());
    }
}
