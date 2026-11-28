use crate::app_state::source::AppStateSource;
use crate::dispatch::post_condition::{evaluate, ConditionOutcome, ObservedElement};
use crate::dispatch::ExpectedPostCondition;
use crate::platform::*;

use super::*;

struct Search {
    matches: Vec<Object>,
    unreadable: u64,
}

async fn search(
    open: &Open,
    name: &AccessibilityElementName,
    stop_on_presence: bool,
) -> Result<Search, Error> {
    let bus = &open.live.bus;
    let bounds = ReadBounds::default();
    let mut seen = HashSet::new();
    let mut pending = vec![(Some(open.root.clone()), 0)];
    let mut result = Search {
        matches: Vec::new(),
        unreadable: 0,
    };
    while let Some((object, depth)) = pending.pop() {
        if seen.len() >= bounds.max_elements {
            result.unreadable += 1;
            break;
        }
        let Some(object) = object.filter(|object| {
            depth <= bounds.max_depth
                && object.peer == open.root.peer
                && seen.insert(object.clone())
        }) else {
            result.unreadable += 1;
            continue;
        };
        let found = match name {
            AccessibilityElementName::Identifier(identifier) => Ok(object.path == *identifier),
            AccessibilityElementName::RoleAndTitle { role, title } => match bus.role(&object).await
            {
                Ok(raw) if tree::role(&raw) != role => Ok(false),
                Ok(_) => bus.name(&object).await.map(|name| name == *title),
                Err(error) => Err(error),
            },
        };
        match found {
            Ok(true) => {
                result.matches.push(object.clone());
                if stop_on_presence || result.matches.len() == 2 {
                    break;
                }
            }
            Ok(false) => {}
            Err(_) => result.unreadable += 1,
        }
        match bus.children(&object).await {
            Ok(children) => {
                pending.extend(children.into_iter().rev().map(|child| (child, depth + 1)))
            }
            Err(_) => result.unreadable += 1,
        }
    }
    Ok(result)
}

fn scoped_error(error: Error) -> DriverError {
    match error {
        Error::Timeout => DriverError::AccessibilityUnreadable(
            AccessibilityReadFailure::RetryableDeadlineExceeded,
        ),
        _ => Source::driver_error(reason(error)),
    }
}

impl Source {
    pub fn accessibility_tree(
        &self,
        request: AccessibilityTreeRequest,
    ) -> Result<AccessibilityTreeResult, DriverError> {
        let target = request.target;
        let state = self
            .read_tree(&target, None, ReadBounds::default())
            .map_err(Self::driver_error)?;
        Ok(AccessibilityTreeResult {
            root_identifier: serde_json::to_string(&target).ok(),
            child_count: u32::try_from(state.roots.len()).unwrap_or(u32::MAX),
            handshake_attempted: false,
            degenerate_reason: state.roots.is_empty().then(|| UNREADABLE.to_owned()),
            unreadable_subtrees: (state.unreadable_subtrees + usize::from(state.read_bound_reached))
                as u64,
        })
    }

    pub fn scoped_read(
        &self,
        request: AccessibilityElementReadRequest,
    ) -> Result<AccessibilityElementReadResult, DriverError> {
        use AccessibilityReadbackAttribute::*;
        let deadline = Instant::now() + Duration::from_millis(request.deadline_ms.into());
        let open = self
            .open(&request.target, deadline)
            .map_err(Self::driver_error)?;
        let (readback, ambiguous) = atspi::bounded(deadline, async {
            let Search {
                matches,
                unreadable,
            } = search(&open, &request.element_name, request.attribute == Presence).await?;
            let (mut focused, mut enabled, mut value) = (None, None, None);
            if let [object] = matches.as_slice() {
                let bus = &open.live.bus;
                match request.attribute {
                    Presence => {}
                    Focused => focused = tree::state(&bus.state(object).await?, tree::FOCUSED),
                    Enabled => enabled = tree::enabled(&bus.state(object).await?),
                    Value if tree::floor(&open, object, false).await.is_ok() => {
                        value = bus.text(object).await.ok()
                    }
                    Value => {}
                }
            }
            Ok((
                AccessibilityElementReadResult {
                    element_name: request.element_name,
                    present: !matches.is_empty(),
                    focused,
                    enabled,
                    value,
                    unreadable_subtrees: unreadable,
                },
                matches.len() > 1,
            ))
        })
        .map_err(scoped_error)?;
        self.verify(&request.target).map_err(Self::driver_error)?;
        if ambiguous {
            return Err(DriverError::Semantic(
                SemanticDriverError::ElementNameAmbiguous {
                    key_form: readback.element_name.key_form(),
                    match_count: 2,
                },
            ));
        }
        Ok(readback)
    }

    pub fn resolve(
        &self,
        request: ElementResolutionRequest,
    ) -> Result<(ElementResolutionResult, ElementHandle), DriverError> {
        let target: ProcessGrant = serde_json::from_str(&request.root_identifier)
            .map_err(|_| Self::driver_error(STALE))?;
        let deadline = Instant::now() + ReadBounds::default().timeout;
        let open = self.open(&target, deadline).map_err(Self::driver_error)?;
        let result = atspi::bounded(deadline, search(&open, &request.element_name, false))
            .map_err(scoped_error)?;
        let object = match result.matches.as_slice() {
            [object] if result.unreadable == 0 => object.clone(),
            [_, _, ..] => {
                return Err(DriverError::Semantic(
                    SemanticDriverError::ElementNameAmbiguous {
                        key_form: request.element_name.key_form(),
                        match_count: 2,
                    },
                ))
            }
            _ if result.unreadable != 0 => return Err(Self::driver_error(UNREADABLE)),
            _ => return Err(DriverError::ElementNotFound),
        };
        let (raw_role, attributes) = atspi::bounded(deadline, async {
            Ok((
                open.live.bus.role(&object).await.ok(),
                open.live.bus.attributes(&object).await.ok(),
            ))
        })
        .map_err(scoped_error)?;
        let token: ElementHandle = Arc::new(Token {
            object,
            grant: target.clone(),
            raw_role,
            attributes,
        });
        self.action_floor(&token, false)
            .map_err(Self::driver_error)?;
        let facts = self
            .element_facts(&token)
            .map_err(|_| Self::driver_error(UNREADABLE))?;
        Ok((
            ElementResolutionResult {
                element_name: request.element_name,
                alternate_name: None,
                owning_process: target,
                semantic_actions: if facts.actions.iter().any(|a| a == "AXPress") {
                    vec![SEMANTIC_PRESS_ACTION.into()]
                } else {
                    Vec::new()
                },
                unreadable_subtrees: 0,
            },
            token,
        ))
    }

    pub fn effect(&self, request: EffectObservationRequest) -> EffectObservationResult {
        let Ok(expected) = serde_json::from_str::<ExpectedPostCondition>(&request.predicate) else {
            return EffectObservationResult {
                status: EffectStatus::EffectIndeterminate,
                failure_reason: Some("post_condition_undeclarable".into()),
            };
        };
        let read = self.scoped_read(AccessibilityElementReadRequest {
            target: request.target,
            element_name: expected.condition.element().clone(),
            attribute: expected.condition.readback_attribute(),
            deadline_ms: request.deadline_ms,
        });
        let (status, failure_reason) = match read {
            Ok(read) if read.unreadable_subtrees == 0 => {
                let result = evaluate(
                    &expected.condition,
                    &ObservedElement {
                        present: read.present,
                        focused: read.focused,
                        enabled: read.enabled,
                        value: read.value,
                        unreadable_subtrees: 0,
                    },
                );
                match result {
                    ConditionOutcome::Satisfied => (EffectStatus::EffectObserved, None),
                    ConditionOutcome::Unsatisfied => (EffectStatus::NoEffectObserved, None),
                    ConditionOutcome::Indeterminate => (
                        EffectStatus::EffectIndeterminate,
                        Some("predicate_attribute_unavailable"),
                    ),
                }
            }
            Err(DriverError::StartupRefused(reason)) => {
                (EffectStatus::EffectIndeterminate, Some(reason))
            }
            _ => (
                EffectStatus::EffectIndeterminate,
                Some("observation_primitive_unavailable"),
            ),
        };
        EffectObservationResult {
            status,
            failure_reason: failure_reason.map(str::to_owned),
        }
    }
}
