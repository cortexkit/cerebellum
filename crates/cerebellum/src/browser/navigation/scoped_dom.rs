use super::*;

// Exact login-field ordinals and a form's complete associated-control set are
// global facts in the existing classifier. Bound their discovery per requested
// ref, and refuse that ref when completeness cannot be established. Ordinary
// non-form controls need only their two ancestor chains (DOM and composed).
const CONTEXT_NODES: usize = 256;
const CONTEXT_FUNCTION: &str = include_str!("scoped_dom.js");
const OBJECT_GROUP: &str = "ck-snapshot-classification";

fn needs_complete_context(node: &RawDomNode) -> bool {
    matches!(node.local_name.as_str(), "input" | "form" | "label")
        || node.attributes.contains_key("form")
        || ["href", "formaction"].iter().any(|attribute| {
            node.attributes.get(*attribute).is_some_and(|value| {
                let value = value.trim();
                let absolute = value.split_once(':').is_some_and(|(scheme, _)| {
                    scheme
                        .as_bytes()
                        .first()
                        .is_some_and(u8::is_ascii_alphabetic)
                        && scheme.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')
                        })
                });
                !absolute && !value.starts_with("//")
            })
        })
}

impl<IO: CdpPipeIo> CdpNavigationDriver<IO> {
    pub(super) fn scoped_snapshot_dom<C: NavigationClock>(
        &mut self,
        observation: &mut BrowserSnapshotObservation,
        attachment: &AttachedTarget,
        classification: Option<(u64, &str)>,
        timings: &mut SnapshotTimings,
        deadline: Instant,
        clock: &mut C,
    ) -> Vec<RawDomNode> {
        let mut facts = HashMap::new();
        let mut classification_time = Duration::ZERO;
        let frame = observation
            .refs
            .iter()
            .find_map(|r| r.backend_identity.as_ref());
        let enabled = self
            .command_response(
                "DOM.enable",
                None,
                Some(attachment.session_id.clone()),
                snapshot_step_deadline(deadline, true, clock.now()),
                None,
                None,
                clock,
            )
            .map_err(|_| ClassificationUnavailable::DomReadFailed)
            .and_then(|response| {
                if response.error.is_some() || response.result.is_none() {
                    Err(ClassificationUnavailable::DomEnableRefused)
                } else {
                    Ok(())
                }
            });
        let world = enabled.and_then(|()| frame.ok_or(ClassificationUnavailable::DomReadFailed)).and_then(|frame| {
            self.command(
                "Page.createIsolatedWorld",
                Some(serde_json::json!({"frameId":frame.frame_id,"worldName":"ck-snapshot-classification"}).as_object().unwrap().clone()),
                Some(attachment.session_id.clone()), snapshot_step_deadline(deadline, true, clock.now()), None, clock,
            ).map_err(|_| ClassificationUnavailable::DomReadFailed)?.get("executionContextId").and_then(Value::as_u64).ok_or(ClassificationUnavailable::DomReadFailed)
        });
        let count = observation.refs.len();
        for (index, reference) in observation.refs.iter_mut().enumerate() {
            let Some(identity) = &reference.backend_identity else {
                continue;
            };
            let read = world.as_ref().map_err(Clone::clone).and_then(|world| {
                let share = (deadline.saturating_duration_since(clock.now())
                    / (count - index) as u32)
                    .min(Duration::from_millis(crate::budgets::CDP_STEP_MS));
                self.scoped_dom_context(
                    attachment,
                    identity,
                    *world,
                    false,
                    clock.now() + share,
                    clock,
                )
                .and_then(|dom| parse_flattened_dom_nodes(&dom))
            });
            let started = Instant::now();
            reference.classification = read.as_ref().map_err(Clone::clone).and_then(|nodes| {
                let (epoch, url) = classification.ok_or(ClassificationUnavailable::NotCaptured)?;
                let origin = document_origin(url)?;
                build_non_type_classification(nodes, identity, epoch, &origin).map(Box::new)
            });
            classification_time += started.elapsed();
            if let Ok(nodes) = read {
                for node in nodes {
                    facts.entry(node.backend_node_id).or_insert(node);
                }
            }
        }
        // Remote objects must not keep detached page subtrees alive across reads.
        if world.is_ok() && clock.now() < deadline {
            let _ = self.command(
                "Runtime.releaseObjectGroup",
                Some(
                    serde_json::json!({"objectGroup":OBJECT_GROUP})
                        .as_object()
                        .unwrap()
                        .clone(),
                ),
                Some(attachment.session_id.clone()),
                deadline,
                None,
                clock,
            );
        }
        timings.classification_ms += classification_time.as_millis();
        facts.into_values().collect()
    }

    pub(super) fn scoped_dom_context<C: NavigationClock>(
        &mut self,
        attachment: &AttachedTarget,
        identity: &BackendNodeIdentity,
        world: u64,
        ancestors_only: bool,
        deadline: Instant,
        clock: &mut C,
    ) -> Result<Map<String, Value>, ClassificationUnavailable> {
        let mut read = |method: &str, params: Value| {
            let step = snapshot_step_deadline(deadline, true, clock.now());
            self.command(
                method,
                Some(params.as_object().unwrap().clone()),
                Some(attachment.session_id.clone()),
                step,
                None,
                clock,
            )
            .map_err(|_| ClassificationUnavailable::DomReadFailed)
        };
        let resolved = read(
            "DOM.resolveNode",
            serde_json::json!({"backendNodeId":identity.backend_node_id,"executionContextId":world,"objectGroup":OBJECT_GROUP}),
        )?;
        let object = resolved
            .get("object")
            .and_then(|v| v.get("objectId"))
            .and_then(Value::as_str)
            .ok_or(ClassificationUnavailable::DomReadFailed)?;
        let context = read(
            "Runtime.callFunctionOn",
            serde_json::json!({"objectId":object,"functionDeclaration":CONTEXT_FUNCTION,"arguments":[{"value":CONTEXT_NODES},{"value":ancestors_only}],"returnByValue":false,"silent":true,"objectGroup":OBJECT_GROUP}),
        )?;
        if context.contains_key("exceptionDetails") {
            return Err(ClassificationUnavailable::DomReadFailed);
        }
        let array = context
            .get("result")
            .and_then(|v| v.get("objectId"))
            .and_then(Value::as_str)
            .ok_or(ClassificationUnavailable::DomReadFailed)?;
        let properties = read(
            "Runtime.getProperties",
            serde_json::json!({"objectId":array,"ownProperties":true,"generatePreview":false}),
        )?;
        let properties = properties
            .get("result")
            .and_then(Value::as_array)
            .ok_or(ClassificationUnavailable::DomReadFailed)?;
        let mut indexed = properties
            .iter()
            .filter_map(|p| {
                Some((
                    p.get("name")?.as_str()?.parse::<usize>().ok()?,
                    p.get("value")?,
                ))
            })
            .collect::<Vec<_>>();
        indexed.sort_by_key(|(index, _)| *index);
        if indexed.is_empty()
            || indexed.len() > CONTEXT_NODES + 1
            || indexed
                .iter()
                .enumerate()
                .any(|(i, (index, _))| i != *index)
        {
            return Err(ClassificationUnavailable::DomReadFailed);
        }
        let metadata: Value = indexed[0]
            .1
            .get("value")
            .and_then(Value::as_str)
            .and_then(|text| serde_json::from_str(text).ok())
            .ok_or(ClassificationUnavailable::DomReadFailed)?;
        let parents: Vec<Option<usize>> = serde_json::from_value(metadata["parents"].clone())
            .map_err(|_| ClassificationUnavailable::DomReadFailed)?;
        let complete = metadata["complete"]
            .as_bool()
            .ok_or(ClassificationUnavailable::DomReadFailed)?;
        if parents.len() + 1 != indexed.len() {
            return Err(ClassificationUnavailable::DomReadFailed);
        }
        let mut values = Vec::new();
        for (_, value) in &indexed[1..] {
            let object = value
                .get("objectId")
                .and_then(Value::as_str)
                .ok_or(ClassificationUnavailable::DomReadFailed)?;
            let described = read(
                "DOM.describeNode",
                serde_json::json!({"objectId":object,"depth":0,"pierce":true}),
            )?;
            values.push(
                described
                    .get("node")
                    .filter(|v| v.is_object())
                    .cloned()
                    .ok_or(ClassificationUnavailable::DomReadFailed)?,
            );
        }
        let backends = values
            .iter()
            .map(|node| {
                node.get("backendNodeId")
                    .and_then(Value::as_u64)
                    .filter(|id| *id > 0)
                    .ok_or(ClassificationUnavailable::DomReadFailed)
            })
            .collect::<Result<Vec<_>, _>>()?;
        for (node, backend) in values.iter().zip(&backends) {
            if node["localName"] == "iframe" || node["localName"] == "frame" {
                if let Some(frame) = node.get("frameId").and_then(Value::as_str) {
                    self.snapshot_frame_owners
                        .insert(frame.to_owned(), *backend);
                }
            }
        }
        if !backends.contains(&identity.backend_node_id) {
            return Err(ClassificationUnavailable::TargetNotInDocument {
                backend_node_id: identity.backend_node_id,
            });
        }
        for (index, value) in values.iter_mut().enumerate() {
            if complete
                && value
                    .get("childNodeCount")
                    .and_then(Value::as_u64)
                    .is_some_and(|count| metadata["childCounts"][index].as_u64() != Some(count))
            {
                return Err(ClassificationUnavailable::DomReadFailed);
            }
            // A closed shadow root, assigned slot, or pseudo-element that the
            // isolated-world walk could not see must not silently disappear.
            for key in ["shadowRoots", "pseudoElements"] {
                if complete
                    && value
                        .get(key)
                        .and_then(Value::as_array)
                        .is_some_and(|nodes| {
                            nodes.iter().any(|n| {
                                !n.get("backendNodeId")
                                    .and_then(Value::as_u64)
                                    .is_some_and(|id| backends.contains(&id))
                            })
                        })
                {
                    return Err(ClassificationUnavailable::DomReadFailed);
                }
                value.as_object_mut().unwrap().remove(key);
            }
            if complete && value.get("templateContent").is_some() {
                return Err(ClassificationUnavailable::DomReadFailed);
            }
            if value
                .get("assignedSlot")
                .and_then(|s| s.get("backendNodeId"))
                .and_then(Value::as_u64)
                .is_some_and(|id| !backends.contains(&id))
            {
                return Err(ClassificationUnavailable::DomReadFailed);
            }
            value["nodeId"] = Value::from(backends[index]);
            value.as_object_mut().unwrap().remove("parentId");
            if let Some(parent) = parents[index] {
                let backend = backends
                    .get(parent)
                    .ok_or(ClassificationUnavailable::DomReadFailed)?;
                value["parentId"] = Value::from(*backend);
            }
        }
        let dom = serde_json::json!({"nodes":values})
            .as_object()
            .unwrap()
            .clone();
        let nodes = parse_flattened_dom_nodes(&dom)?;
        // Discovery and attribute reads are separate CDP observations. A node
        // that gains form/label/base-dependent semantics between them needs a
        // new complete context, not an inferred form-less classification.
        if !ancestors_only && !complete && nodes.iter().any(needs_complete_context) {
            return Err(ClassificationUnavailable::DomReadFailed);
        }
        Ok(dom)
    }
}
