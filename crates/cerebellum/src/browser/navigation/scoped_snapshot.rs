use super::*;

pub(super) type SnapshotContexts = (
    HashMap<u64, usize>,
    Vec<Result<Vec<RawDomNode>, ClassificationUnavailable>>,
);

impl<IO: CdpPipeIo> CdpNavigationDriver<IO> {
    pub(super) fn snapshot_contexts<C: NavigationClock>(
        &mut self,
        observation: &BrowserSnapshotObservation,
        attachment: &AttachedTarget,
        world: u64,
        deadline: Instant,
        clock: &mut C,
    ) -> Result<SnapshotContexts, ClassificationUnavailable> {
        let mut backends = Vec::new();
        let mut seen = HashSet::new();
        for identity in observation
            .refs
            .iter()
            .filter_map(|r| r.backend_identity.as_ref())
        {
            if seen.insert(identity.backend_node_id) {
                backends.push(identity.backend_node_id);
            }
        }
        let resolved = self.scoped_reads("DOM.resolveNode", backends.iter().map(|backend| serde_json::json!({"backendNodeId":backend,"executionContextId":world,"objectGroup":super::scoped_dom::OBJECT_GROUP})).collect(), &attachment.session_id, deadline, clock).map_err(|_| ClassificationUnavailable::DomReadFailed)?;
        let mut arguments = vec![serde_json::json!({"value":super::scoped_dom::CONTEXT_NODES})];
        let mut targets = Vec::new();
        for (backend, result) in backends.into_iter().zip(resolved) {
            if let Some(object) = result.ok().and_then(|r| {
                r.get("object")?
                    .get("objectId")?
                    .as_str()
                    .map(str::to_owned)
            }) {
                targets.push(backend);
                arguments.push(serde_json::json!({"objectId":object}));
            }
        }
        if targets.is_empty() {
            return Err(ClassificationUnavailable::DomReadFailed);
        }
        let function = include_str!("scoped_snapshot.js")
            .replace("__COLLECTOR__", include_str!("scoped_dom.js"));
        let mut read = |method: &str, params: Value| {
            if deadline.saturating_duration_since(clock.now()) < POLL_INTERVAL {
                return Err(ClassificationUnavailable::DomReadFailed);
            }
            self.command(
                method,
                params.as_object().cloned(),
                Some(attachment.session_id.clone()),
                snapshot_step_deadline(deadline, true, clock.now()),
                None,
                clock,
            )
            .map_err(|_| ClassificationUnavailable::DomReadFailed)
        };
        let result = read(
            "Runtime.callFunctionOn",
            serde_json::json!({"executionContextId":world,"functionDeclaration":function,"arguments":arguments,"returnByValue":false,"silent":true,"objectGroup":super::scoped_dom::OBJECT_GROUP}),
        )?;
        if result.contains_key("exceptionDetails") {
            return Err(ClassificationUnavailable::DomReadFailed);
        }
        let object = result
            .get("result")
            .and_then(|result| result.get("objectId"))
            .and_then(Value::as_str)
            .ok_or(ClassificationUnavailable::DomReadFailed)?;
        let properties = read(
            "Runtime.getProperties",
            serde_json::json!({"objectId":object,"ownProperties":true,"generatePreview":false}),
        )?;
        let mut indexed = properties
            .get("result")
            .and_then(Value::as_array)
            .ok_or(ClassificationUnavailable::DomReadFailed)?
            .iter()
            .filter_map(|p| Some((p["name"].as_str()?.parse::<usize>().ok()?, &p["value"])))
            .collect::<Vec<_>>();
        indexed.sort_by_key(|(i, _)| *i);
        if indexed.is_empty()
            || indexed.len() > MAX_AX_NODES * 16
            || indexed
                .iter()
                .enumerate()
                .any(|(i, (index, _))| i != *index)
        {
            return Err(ClassificationUnavailable::DomReadFailed);
        }
        let metadata: Value = serde_json::from_str(
            indexed[0].1["value"]
                .as_str()
                .ok_or(ClassificationUnavailable::DomReadFailed)?,
        )
        .map_err(|_| ClassificationUnavailable::DomReadFailed)?;
        let assignments = metadata["assignments"]
            .as_array()
            .filter(|a| a.len() == targets.len())
            .ok_or(ClassificationUnavailable::DomReadFailed)?;
        let contexts = metadata["contexts"]
            .as_array()
            .ok_or(ClassificationUnavailable::DomReadFailed)?;
        let params = indexed[1..]
            .iter()
            .map(|(_, value)| {
                value["objectId"]
                    .as_str()
                    .map(|object| serde_json::json!({"objectId":object,"depth":0,"pierce":true}))
                    .ok_or(ClassificationUnavailable::DomReadFailed)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let descriptions = self
            .scoped_reads(
                "DOM.describeNode",
                params,
                &attachment.session_id,
                deadline,
                clock,
            )
            .map_err(|_| ClassificationUnavailable::DomReadFailed)?;
        let descriptions = descriptions
            .into_iter()
            .map(|r| {
                r.and_then(|r| {
                    r.get("node")
                        .filter(|n| n.is_object())
                        .cloned()
                        .ok_or(ClassificationUnavailable::DomReadFailed)
                })
            })
            .collect::<Vec<_>>();
        let ua_roots =
            self.snapshot_ua_roots(&descriptions, &attachment.session_id, deadline, clock)?;
        self.remember_frame_owners(
            &descriptions
                .iter()
                .filter_map(|r| r.as_ref().ok().cloned())
                .collect::<Vec<_>>(),
        );
        let mut out = Vec::new();
        for context in contexts {
            let validated = (|| {
                if context["invalid"] == true {
                    return Err(ClassificationUnavailable::DomReadFailed);
                }
                let members: Vec<usize> = serde_json::from_value(context["members"].clone())
                    .map_err(|_| ClassificationUnavailable::DomReadFailed)?;
                let mut values = members
                    .iter()
                    .map(|index| {
                        let value = descriptions
                            .get(*index)
                            .ok_or(ClassificationUnavailable::DomReadFailed)?
                            .as_ref()
                            .map_err(Clone::clone)?;
                        if !super::scoped_dom::same_native_facts(value, &metadata["facts"][*index])
                        {
                            return Err(ClassificationUnavailable::DomReadFailed);
                        }
                        Ok(value.clone())
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let positions = members
                    .iter()
                    .enumerate()
                    .map(|(position, index)| (*index, position))
                    .collect::<HashMap<_, _>>();
                let parents = members
                    .iter()
                    .map(|index| {
                        metadata["parents"][*index]
                            .as_u64()
                            .and_then(|parent| positions.get(&(parent as usize)).copied())
                    })
                    .collect::<Vec<_>>();
                let keys = members.iter().map(|index| index + 1).collect::<Vec<_>>();
                let slots = members
                    .iter()
                    .map(|index| metadata["slots"][*index].as_u64().map(|slot| slot + 1))
                    .collect::<Vec<_>>();
                let child_counts = members
                    .iter()
                    .map(|index| metadata["childCounts"][*index].clone())
                    .collect::<Vec<_>>();
                let mut meta = serde_json::json!({"parents":parents,"keys":keys,"slots":slots,"childCounts":child_counts,"complete":context["complete"],"bound":context["bound"]});
                super::scoped_ua::supplement_ua_context(&mut meta, &mut values, &ua_roots)?;
                super::scoped_dom::materialize_context(&meta, values, false).and_then(|mut dom| {
                    // Chrome's flattened reply exposes UA roots as host stubs,
                    // not top-level records. Validate their complete native
                    // subtrees first, then omit the root records so parent
                    // links match DOM.getFlattenedDocument exactly.
                    dom.get_mut("nodes")
                        .and_then(Value::as_array_mut)
                        .ok_or(ClassificationUnavailable::DomReadFailed)?
                        .retain(|node| node["shadowRootType"] != "user-agent");
                    parse_flattened_dom_nodes(&dom)
                })
            })();
            out.push(validated);
        }
        let mut by_backend = HashMap::new();
        for (backend, assignment) in targets.into_iter().zip(assignments) {
            if let Some(index) = assignment
                .as_u64()
                .and_then(|n| usize::try_from(n).ok())
                .filter(|i| *i < out.len())
            {
                by_backend.insert(backend, index);
            }
        }
        Ok((by_backend, out))
    }
}
