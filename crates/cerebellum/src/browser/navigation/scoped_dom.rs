use super::*;

// Exact login-field ordinals and a form's complete associated-control set are
// global facts in the classifier. Complete graphs scale with their control
// count up to 16,384 nodes; refuse refs when completeness cannot be established.
// Ordinary
// non-form controls need only their two ancestor chains (DOM and composed).
pub(super) const CONTEXT_NODES: usize = 256;
const CONTEXT_FUNCTION: &str = include_str!("scoped_dom.js");
pub(super) const OBJECT_GROUP: &str = "ck-snapshot-classification";

pub(super) struct SnapshotDomCache {
    enabled: bool,
    scope: Option<(String, String)>,
    state_object: Option<String>,
    backends_by_key: HashMap<u64, u64>,
    // Backend IDs are scoped to the target/frame held in `scope`, and this
    // cache is created only after the accessibility-tree walk finishes. There
    // are two phases:
    // ancestor descriptions are reused only after fresh native facts match;
    // they never satisfy a complete-context read. One fresh complete read may
    // describe those nodes again to observe closed shadow roots, then its
    // frozen graph serves all remaining refs just like the whole-DOM index.
    partial_by_backend: HashMap<u64, Value>,
    failed_keys: HashSet<u64>,
    complete_requested: bool,
    complete_error: Option<ClassificationUnavailable>,
    #[cfg(test)]
    complete_batch: Option<DomClassificationBatch>,
}

impl Default for SnapshotDomCache {
    fn default() -> Self {
        Self {
            enabled: true,
            scope: None,
            state_object: None,
            backends_by_key: HashMap::new(),
            partial_by_backend: HashMap::new(),
            failed_keys: HashSet::new(),
            complete_requested: false,
            complete_error: None,
            #[cfg(test)]
            complete_batch: None,
        }
    }
}

pub(super) fn same_native_facts(described: &Value, native: &Value) -> bool {
    let normalized = |value: &Value| {
        let mut value = value.clone();
        let object = value.as_object_mut()?;
        object.insert("nodeId".into(), Value::from(1));
        object.insert("backendNodeId".into(), Value::from(1));
        for key in ["parentId", "assignedSlot", "shadowRoots", "pseudoElements"] {
            object.remove(key);
        }
        parse_flattened_dom_nodes(serde_json::json!({"nodes":[value]}).as_object()?)
            .ok()?
            .pop()
    };
    described["nodeType"] == native["nodeType"]
        && described
            .get("nodeValue")
            .and_then(Value::as_str)
            .unwrap_or_default()
            == native
                .get("nodeValue")
                .and_then(Value::as_str)
                .unwrap_or_default()
        && normalized(described).is_some_and(|node| normalized(native).as_ref() == Some(&node))
}

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
    /// Manual live-browser parity oracle. Reads native DOM facts in each
    /// captured frame and compares every retained classification record without
    /// performing input or changing the production capture strategy.
    #[doc(hidden)]
    pub fn check_snapshot_classification_parity(
        &mut self,
        observation: &BrowserSnapshotObservation,
        epoch: u64,
        url: &str,
        deadline_ms: u64,
    ) -> Result<usize, String> {
        let mut clock = SystemNavigationClock;
        let deadline = clock.now() + Duration::from_millis(deadline_ms);
        let mut batches = HashMap::new();
        let mut count = 0;
        for reference in &observation.refs {
            let Some(identity) = &reference.backend_identity else {
                continue;
            };
            if !batches.contains_key(&identity.frame_id) {
                let mut attachment = self
                    .frame_attachment(identity)
                    .map_err(|e| format!("{e:?}"))?;
                if let Some(frame) = &reference.frame_document {
                    attachment.session_id = frame.session_id.clone();
                }
                let nodes = self
                    .flattened_dom_nodes_before(&attachment, deadline, &mut clock)
                    .map_err(|e| format!("{e:?}"))?
                    .map_err(|e| format!("{e:?}"))?;
                batches.insert(
                    identity.frame_id.clone(),
                    DomClassificationBatch::new(&nodes),
                );
            }
            let origin = document_origin(
                reference
                    .frame_document
                    .as_ref()
                    .map_or(url, |f| f.url.as_str()),
            )
            .map_err(|e| format!("{e:?}"))?;
            let expected = batches[&identity.frame_id]
                .classify(identity, epoch, &origin)
                .map(Box::new);
            if reference.classification != expected
                || reference
                    .classification
                    .as_ref()
                    .ok()
                    .map(|c| &c.login_field)
                    != expected.as_ref().ok().map(|c| &c.login_field)
            {
                let actual_json = reference
                    .classification
                    .as_ref()
                    .ok()
                    .map(|c| serde_json::to_value(c).unwrap());
                let expected_json = expected
                    .as_ref()
                    .ok()
                    .map(|c| serde_json::to_value(c).unwrap());
                let differences = expected_json
                    .as_ref()
                    .and_then(Value::as_object)
                    .into_iter()
                    .flat_map(|object| object.keys())
                    .filter(|key| {
                        actual_json.as_ref().map(|v| &v[*key])
                            != expected_json.as_ref().map(|v| &v[*key])
                    })
                    .map(|key| {
                        format!(
                            "{key}: actual={} old={}",
                            actual_json.as_ref().unwrap_or(&Value::Null)[key]
                                .to_string()
                                .chars()
                                .take(250)
                                .collect::<String>(),
                            expected_json.as_ref().unwrap_or(&Value::Null)[key]
                                .to_string()
                                .chars()
                                .take(250)
                                .collect::<String>()
                        )
                    })
                    .collect::<Vec<_>>();
                return Err(format!("{} {} backend={}: differences={differences:?}; actual_error={:?}; old_error={:?}; login={:?}/{:?}", reference.captured.role, reference.captured.name, identity.backend_node_id, reference.classification.as_ref().err(), expected.as_ref().err(), reference.classification.as_ref().ok().map(|c| &c.login_field), expected.as_ref().ok().map(|c| &c.login_field)));
            }
            count += 1;
        }
        Ok(count)
    }

    pub(super) fn snapshot_dom<C: NavigationClock>(
        &mut self,
        observation: &mut BrowserSnapshotObservation,
        attachment: &AttachedTarget,
        classification: Option<(u64, &str)>,
        timings: &mut SnapshotTimings,
        deadline: Instant,
        clock: &mut C,
    ) -> Vec<RawDomNode> {
        // Content has already been captured. A single native document read is
        // much cheaper than remote-object round trips on ordinary pages. Limit
        // its attempt so a busy renderer still leaves time for scoped reads.
        let deadline =
            deadline.min(clock.now() + Duration::from_millis(crate::budgets::CDP_STEP_MS));
        let remaining = deadline.saturating_duration_since(clock.now());
        if !observation.ax_truncated
            && observation.records.len() < MAX_AX_NODES
            && remaining >= POLL_INTERVAL * 3
        {
            let share = (remaining / 3).min(Duration::from_millis(500));
            match self.flattened_dom_nodes_before(attachment, clock.now() + share, clock) {
                Ok(Ok(nodes)) => {
                    let started = Instant::now();
                    if let Some((epoch, url)) = classification {
                        match document_origin(url) {
                            Ok(origin) => {
                                classify_refs(&mut observation.refs, &nodes, epoch, &origin)
                            }
                            Err(reason) => {
                                for reference in &mut observation.refs {
                                    reference.classification = Err(reason.clone());
                                }
                            }
                        }
                    }
                    timings.classification_ms += started.elapsed().as_millis();
                    return nodes;
                }
                Ok(Err(ClassificationUnavailable::DomEnableRefused)) => {
                    for reference in &mut observation.refs {
                        reference.classification = Err(ClassificationUnavailable::DomEnableRefused);
                    }
                    return Vec::new();
                }
                _ => {}
            }
        }
        self.scoped_snapshot_dom(
            observation,
            attachment,
            classification,
            timings,
            deadline,
            clock,
        )
    }

    pub(super) fn scoped_snapshot_dom<C: NavigationClock>(
        &mut self,
        observation: &mut BrowserSnapshotObservation,
        attachment: &AttachedTarget,
        classification: Option<(u64, &str)>,
        timings: &mut SnapshotTimings,
        deadline: Instant,
        clock: &mut C,
    ) -> Vec<RawDomNode> {
        #[cfg(test)]
        if !self.cache_snapshot_contexts {
            return self.uncached_snapshot_dom(
                observation,
                attachment,
                classification,
                timings,
                deadline,
                clock,
            );
        }
        let mut world_created = false;
        let read = (|| {
            if deadline.saturating_duration_since(clock.now()) < POLL_INTERVAL {
                return Err(ClassificationUnavailable::DomReadFailed);
            }
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
                .map_err(|_| ClassificationUnavailable::DomReadFailed)?;
            if enabled.error.is_some() || enabled.result.is_none() {
                return Err(ClassificationUnavailable::DomEnableRefused);
            }
            let frame = observation
                .refs
                .iter()
                .find_map(|r| r.backend_identity.as_ref())
                .ok_or(ClassificationUnavailable::DomReadFailed)?;
            let world = self.command("Page.createIsolatedWorld", Some(serde_json::json!({"frameId":frame.frame_id,"worldName":"ck-snapshot-classification"}).as_object().unwrap().clone()), Some(attachment.session_id.clone()), snapshot_step_deadline(deadline, true, clock.now()), None, clock).map_err(|_| ClassificationUnavailable::DomReadFailed)?;
            let world = world
                .get("executionContextId")
                .and_then(Value::as_u64)
                .ok_or(ClassificationUnavailable::DomReadFailed)?;
            world_created = true;
            self.snapshot_contexts(observation, attachment, world, deadline, clock)
        })();
        let started = Instant::now();
        let mut facts = HashMap::new();
        match read {
            Ok((assignments, contexts)) => {
                let batches = contexts
                    .into_iter()
                    .map(|context| {
                        context.map(|nodes| {
                            let batch = DomClassificationBatch::new(&nodes);
                            for node in nodes {
                                facts.entry(node.backend_node_id).or_insert(node);
                            }
                            batch
                        })
                    })
                    .collect::<Vec<_>>();
                for reference in &mut observation.refs {
                    if let Some(identity) = &reference.backend_identity {
                        reference.classification = (|| {
                            let index = assignments
                                .get(&identity.backend_node_id)
                                .ok_or(ClassificationUnavailable::DomReadFailed)?;
                            let batch = batches[*index].as_ref().map_err(Clone::clone)?;
                            let (epoch, url) =
                                classification.ok_or(ClassificationUnavailable::NotCaptured)?;
                            batch
                                .classify(identity, epoch, &document_origin(url)?)
                                .map(Box::new)
                        })();
                    }
                }
            }
            Err(reason) => {
                for reference in &mut observation.refs {
                    reference.classification = Err(reason.clone());
                }
            }
        }
        timings.classification_ms += started.elapsed().as_millis();
        if world_created && deadline.saturating_duration_since(clock.now()) >= POLL_INTERVAL {
            let _ = self.command(
                "Runtime.releaseObjectGroup",
                Some(
                    serde_json::json!({"objectGroup":OBJECT_GROUP})
                        .as_object()
                        .unwrap()
                        .clone(),
                ),
                Some(attachment.session_id.clone()),
                snapshot_step_deadline(deadline, true, clock.now()),
                None,
                clock,
            );
        }
        facts.into_values().collect()
    }

    #[cfg(test)]
    // Unbatched reference reader for measuring protocol costs in tests only.
    fn uncached_snapshot_dom<C: NavigationClock>(
        &mut self,
        observation: &mut BrowserSnapshotObservation,
        attachment: &AttachedTarget,
        classification: Option<(u64, &str)>,
        timings: &mut SnapshotTimings,
        deadline: Instant,
        clock: &mut C,
    ) -> Vec<RawDomNode> {
        let mut facts = HashMap::new();
        let mut cache = SnapshotDomCache::default();
        #[cfg(test)]
        {
            cache.enabled = self.cache_snapshot_contexts;
        }
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
            if let Some(batch) = &cache.complete_batch {
                let started = Instant::now();
                reference.classification = classification
                    .ok_or(ClassificationUnavailable::NotCaptured)
                    .and_then(|(epoch, url)| {
                        document_origin(url)
                            .and_then(|origin| batch.classify(identity, epoch, &origin))
                    })
                    .map(Box::new);
                classification_time += started.elapsed();
                continue;
            }
            let read = world.as_ref().map_err(Clone::clone).and_then(|world| {
                let share = (deadline.saturating_duration_since(clock.now())
                    / (count - index) as u32)
                    .min(Duration::from_millis(crate::budgets::CDP_STEP_MS));
                self.scoped_dom_context(
                    attachment,
                    identity,
                    *world,
                    false,
                    &mut cache,
                    clock.now() + share,
                    clock,
                )
                .and_then(|dom| {
                    parse_flattened_dom_nodes(&dom)
                        .map(|nodes| (dom["contextComplete"] == true, nodes))
                })
            });
            let started = Instant::now();
            reference.classification =
                read.as_ref().map_err(Clone::clone).and_then(|(_, nodes)| {
                    let (epoch, url) =
                        classification.ok_or(ClassificationUnavailable::NotCaptured)?;
                    let origin = document_origin(url)?;
                    build_non_type_classification(nodes, identity, epoch, &origin).map(Box::new)
                });
            classification_time += started.elapsed();
            if let Ok((complete, nodes)) = read {
                if complete && cache.enabled {
                    cache.complete_batch = Some(DomClassificationBatch::new(&nodes));
                }
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

    #[allow(clippy::too_many_arguments)]
    pub(super) fn scoped_dom_context<C: NavigationClock>(
        &mut self,
        attachment: &AttachedTarget,
        identity: &BackendNodeIdentity,
        world: u64,
        ancestors_only: bool,
        cache: &mut SnapshotDomCache,
        deadline: Instant,
        clock: &mut C,
    ) -> Result<Map<String, Value>, ClassificationUnavailable> {
        let scope = (identity.target_id.clone(), identity.frame_id.clone());
        if cache
            .scope
            .as_ref()
            .is_some_and(|existing| *existing != scope)
        {
            return Err(ClassificationUnavailable::DomReadFailed);
        }
        cache.scope = Some(scope);
        cache.complete_requested = false;
        let result = self.scoped_dom_context_read(
            attachment,
            identity,
            world,
            ancestors_only,
            cache,
            deadline,
            clock,
        );
        if cache.enabled && cache.complete_requested {
            if let Err(reason) = &result {
                cache.complete_error = Some(reason.clone());
            }
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn scoped_dom_context_read<C: NavigationClock>(
        &mut self,
        attachment: &AttachedTarget,
        identity: &BackendNodeIdentity,
        world: u64,
        ancestors_only: bool,
        cache: &mut SnapshotDomCache,
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
            serde_json::json!({"objectId":object,"functionDeclaration":CONTEXT_FUNCTION,"arguments":[{"value":CONTEXT_NODES},{"value":ancestors_only},cache.state_object.as_ref().map(|id| serde_json::json!({"objectId":id})).unwrap_or(serde_json::json!({"value":null}))],"returnByValue":false,"silent":true,"objectGroup":OBJECT_GROUP}),
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
        cache.state_object = properties
            .iter()
            .find(|property| property["name"] == "state")
            .and_then(|property| property["value"]["objectId"].as_str())
            .map(str::to_owned);
        if cache.state_object.is_none() {
            return Err(ClassificationUnavailable::DomReadFailed);
        }
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
            || indexed.len() > 16384 + 1
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
        cache.complete_requested = complete;
        if complete && cache.enabled {
            if let Some(reason) = &cache.complete_error {
                return Err(reason.clone());
            }
        }
        let keys: Vec<u64> = serde_json::from_value(metadata["keys"].clone())
            .map_err(|_| ClassificationUnavailable::DomReadFailed)?;
        let native = metadata["facts"]
            .as_array()
            .ok_or(ClassificationUnavailable::DomReadFailed)?;
        let slots: Vec<Option<u64>> = serde_json::from_value(metadata["slots"].clone())
            .map_err(|_| ClassificationUnavailable::DomReadFailed)?;
        if parents.len() + 1 != indexed.len() {
            return Err(ClassificationUnavailable::DomReadFailed);
        }
        if keys.len() != parents.len()
            || native.len() != parents.len()
            || slots.len() != parents.len()
            || keys.contains(&0)
            || keys.iter().copied().collect::<HashSet<_>>().len() != keys.len()
        {
            return Err(ClassificationUnavailable::DomReadFailed);
        }
        let mut values = Vec::new();
        for (index, (_, value)) in indexed[1..].iter().enumerate() {
            let key = keys[index];
            if cache.enabled && !complete && cache.failed_keys.contains(&key) {
                return Err(ClassificationUnavailable::DomReadFailed);
            }
            let cached = if cache.enabled && !complete {
                cache
                    .backends_by_key
                    .get(&key)
                    .and_then(|backend| cache.partial_by_backend.get(backend))
                    .cloned()
            } else {
                None
            };
            let object = value
                .get("objectId")
                .and_then(Value::as_str)
                .ok_or(ClassificationUnavailable::DomReadFailed)?;
            let described = if let Some(node) = cached {
                node
            } else {
                let result = read(
                    "DOM.describeNode",
                    serde_json::json!({"objectId":object,"depth":0,"pierce":true}),
                );
                let node = match result {
                    Ok(described) => described
                        .get("node")
                        .filter(|v| v.is_object())
                        .cloned()
                        .ok_or(ClassificationUnavailable::DomReadFailed),
                    Err(reason) => Err(reason),
                };
                if node.is_err() && cache.enabled && !complete {
                    cache.failed_keys.insert(key);
                }
                let node = node?;
                if cache.enabled && !complete {
                    let backend = node["backendNodeId"]
                        .as_u64()
                        .filter(|id| *id > 0)
                        .ok_or(ClassificationUnavailable::DomReadFailed)?;
                    cache.backends_by_key.insert(key, backend);
                    cache.partial_by_backend.insert(backend, node.clone());
                }
                node
            };
            // Cached attributes are not evidence of current semantics. The
            // isolated-world call reads them atomically with scope discovery;
            // any mismatch refuses this ref without a second description.
            if !same_native_facts(&described, &native[index]) {
                return Err(ClassificationUnavailable::DomReadFailed);
            }
            values.push(described);
        }
        if !values
            .iter()
            .any(|node| node["backendNodeId"].as_u64() == Some(identity.backend_node_id))
        {
            return Err(ClassificationUnavailable::TargetNotInDocument {
                backend_node_id: identity.backend_node_id,
            });
        }
        self.remember_frame_owners(&values);
        materialize_context(&metadata, values, ancestors_only)
    }
    pub(super) fn remember_frame_owners(&mut self, values: &[Value]) {
        for node in values {
            if matches!(node["localName"].as_str(), Some("iframe" | "frame")) {
                if let (Some(frame), Some(backend)) =
                    (node["frameId"].as_str(), node["backendNodeId"].as_u64())
                {
                    self.snapshot_frame_owners.insert(frame.into(), backend);
                }
            }
        }
    }
}

pub(super) fn materialize_context(
    metadata: &Value,
    mut values: Vec<Value>,
    ancestors_only: bool,
) -> Result<Map<String, Value>, ClassificationUnavailable> {
    let complete = metadata["complete"]
        .as_bool()
        .ok_or(ClassificationUnavailable::DomReadFailed)?;
    let parents: Vec<Option<usize>> = serde_json::from_value(metadata["parents"].clone())
        .map_err(|_| ClassificationUnavailable::DomReadFailed)?;
    let keys: Vec<u64> = serde_json::from_value(metadata["keys"].clone())
        .map_err(|_| ClassificationUnavailable::DomReadFailed)?;
    let slots: Vec<Option<u64>> = serde_json::from_value(metadata["slots"].clone())
        .map_err(|_| ClassificationUnavailable::DomReadFailed)?;
    let bound = metadata
        .get("bound")
        .and_then(Value::as_u64)
        .unwrap_or(CONTEXT_NODES as u64);
    if bound > 16384
        || values.len() as u64 > bound
        || (!complete && bound != CONTEXT_NODES as u64)
        || parents.len() != values.len()
        || keys.len() != values.len()
        || slots.len() != values.len()
        || keys.contains(&0)
        || keys.iter().collect::<HashSet<_>>().len() != keys.len()
    {
        return Err(ClassificationUnavailable::DomReadFailed);
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
        let slot = slots[index]
            .map(|key| {
                keys.iter()
                    .position(|candidate| *candidate == key)
                    .map(|index| backends[index])
                    .ok_or(ClassificationUnavailable::DomReadFailed)
            })
            .transpose()?;
        if value
            .get("assignedSlot")
            .and_then(|s| s.get("backendNodeId"))
            .and_then(Value::as_u64)
            .is_some_and(|id| Some(id) != slot)
        {
            return Err(ClassificationUnavailable::DomReadFailed);
        }
        value.as_object_mut().unwrap().remove("assignedSlot");
        if let Some(slot) = slot {
            value["assignedSlot"] = serde_json::json!({"backendNodeId":slot});
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
    let dom = serde_json::json!({"nodes":values,"contextComplete":complete})
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
