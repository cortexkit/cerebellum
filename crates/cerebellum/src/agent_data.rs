//! The move driver's private-content participant. Import adds provenance before
//! replying; activation is bookkeeping, and release never removes provenance.

mod checkpoint;
pub(crate) mod door;
mod transfer;

use crate::{
    private_content::{PrivateContent, Source},
    AcceptedBindFacts, Frame, ModuleError, Planes,
};
use cerebellum_core::format_floor::DurableFormat;
use cortexkit_role_agent_data::{
    errors::{ErrorBody, RefusalCode},
    request::Request,
    step::{self, Step},
    Op,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

pub const CHECKPOINT_FORMAT: DurableFormat = DurableFormat::new("agent-data-cuts", 1);
const FORMAT: &str = "cerebellum-marks/v1";
const STREAM: &str = "reserved:cerebellum";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    v: u64,
    agent_id: String,
    sources: BTreeSet<Source>,
}

pub(crate) struct Participant {
    state: Arc<tokio::sync::Mutex<checkpoint::Document>>,
    path: Option<PathBuf>,
    requires_persistence: bool,
    door: Mutex<Option<Arc<dyn door::Door>>>,
}

pub(crate) fn error(code: RefusalCode, message: impl Into<String>) -> ErrorBody {
    ErrorBody::new(code, message)
}

fn unavailable(why: impl std::fmt::Debug) -> ErrorBody {
    error(
        RefusalCode::Unavailable,
        format!("agent-data storage or door unavailable: {why:?}"),
    )
}

fn detailed(code: RefusalCode, message: &str, detail: Value) -> ErrorBody {
    let mut e = error(code, message);
    e.detail = Some(detail);
    e
}

pub(crate) fn bind_admitted(
    principal: &Option<subc_protocol::Principal>,
    target: &subc_protocol::RouteTarget,
) -> bool {
    is_driver(principal)
        && matches!(target, subc_protocol::RouteTarget::InternalService {module_id,service_id} if module_id == "cerebellum" && service_id == cortexkit_role_agent_data::SERVICE_ID)
}

fn is_driver(principal: &Option<subc_protocol::Principal>) -> bool {
    matches!(principal, Some(subc_protocol::Principal::Reserved {module_id}) if cortexkit_role_agent_data::caller_admitted(&format!("reserved:{module_id}")))
}

impl Participant {
    pub(crate) fn in_memory() -> Self {
        Self {
            state: Arc::new(tokio::sync::Mutex::new(checkpoint::Document::default())),
            path: None,
            requires_persistence: false,
            door: Mutex::new(None),
        }
    }

    pub(crate) fn production() -> Self {
        Self::with_data_home(cerebellum_core::platform_dirs::data_home().as_deref())
    }

    fn with_data_home(home: Option<&Path>) -> Self {
        let path = home.map(|home| {
            let directory =
                cerebellum_core::format_floor::module_directory(home).join("agent-data");
            // Backups look for this directory even before an agent move writes a checkpoint.
            // Leave existing permissions alone; checkpoint writes still report storage errors.
            if !directory.is_dir() {
                let _ = cerebellum_core::private_fs::create_dir_all(&directory);
            }
            directory.join("cuts.json")
        });
        Self {
            path,
            requires_persistence: true,
            ..Self::in_memory()
        }
    }

    pub(crate) fn set_door(&self, door: Arc<dyn door::Door>) {
        *self.door.lock().unwrap() = Some(door);
    }

    fn door(&self) -> Result<Arc<dyn door::Door>, ErrorBody> {
        self.door
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| unavailable("no session door configured"))
    }

    async fn execute(
        &self,
        marks: &Arc<PrivateContent>,
        request: Request,
    ) -> Result<Value, ErrorBody> {
        let op = request.op();
        if self.requires_persistence && self.path.is_none() {
            return Err(unavailable("no durable data home"));
        }
        let mut memory = self.state.clone().lock_owned().await;
        let mut document = self.load(&memory).await?;
        if op == Op::Describe {
            return Ok(
                json!({"ref_kinds":["agent"],"stores":[{"name":FORMAT,"sync_class":"agent"}],"external":false}),
            );
        }
        let refs = request.refs().expect("non-describe has refs");
        for r in refs.as_slice() {
            if r.ref_kind != "agent" {
                return Err(
                    if matches!(op, Op::Busy | Op::Prepare | Op::Export | Op::Release) {
                        detailed(
                            RefusalCode::UnknownRef,
                            "only agent refs are held here",
                            serde_json::to_value(r).unwrap(),
                        )
                    } else {
                        error(RefusalCode::InvalidRequest, "only agent refs are supported")
                    },
                );
            }
        }
        if op == Op::Busy {
            return Ok(
                json!({"refs":refs.as_slice().iter().map(|_| json!({"state":"idle"})).collect::<Vec<_>>()}),
            );
        }
        let id = request.cut_id().expect("cut operation").as_str();
        let current = document.cuts.get(id);
        if op == Op::Status {
            return Ok(json!({"step":current.map_or(Step::None, |c| c.step)}));
        }
        if op == Op::Diverged {
            let mut answers = Vec::new();
            for r in refs.as_slice() {
                let local = marks.export_agent(&r.r#ref);
                if local.is_empty() {
                    answers.push(json!({"state":"at_cut"}));
                } else {
                    let (_, incoming) = self.download(op, &r.r#ref, id).await?;
                    answers.push(json!({"state":if local.is_subset(&incoming.sources) {"at_cut"} else {"advanced"}}));
                }
            }
            return Ok(json!({"refs":answers}));
        }
        // Compare every decoded parameter, including the optional holderBox on release.
        let canonical = request.with_sorted_refs().params();
        if let Some(saved) = current.and_then(|c| c.replies.get(op.method())) {
            return if saved.request == canonical {
                Ok(saved.reply.clone())
            } else {
                Err(error(
                    RefusalCode::IdReused,
                    "cut operation request changed",
                ))
            };
        }
        let step = current.map_or(Step::None, |c| c.step);
        let next = step::advance(op, step).map_err(|e| match e {
            step::StepRefusal::CutUnknown => {
                error(RefusalCode::CutUnknown, "cut has no earlier step")
            }
            step::StepRefusal::InvalidState { step } => detailed(
                RefusalCode::InvalidState,
                "operation out of order",
                json!({"step":step}),
            ),
        })?;
        step::check_ref_set(op, step, current.and_then(|c| c.refs.as_ref()), refs).map_err(
            |d| {
                detailed(
                    RefusalCode::InvalidState,
                    "cut ref set changed",
                    serde_json::to_value(d).unwrap(),
                )
            },
        )?;
        let mut cut = current.cloned().unwrap_or_default();
        let reply = match op {
            Op::Prepare => {
                // Persist the snapshot before uploading it to the backup module's session
                // stream. A failed upload must retry the same bytes even if more
                // marks arrive meanwhile.
                if cut.payloads.is_empty() {
                    cut.refs = Some(refs.clone());
                    for r in refs.as_slice() {
                        cut.payloads.insert(
                            r.r#ref.clone(),
                            Payload {
                                v: 1,
                                agent_id: r.r#ref.clone(),
                                sources: marks.export_agent(&r.r#ref),
                            },
                        );
                    }
                    document.cuts.insert(id.to_owned(), cut.clone());
                    (memory, document) = self.save(document, memory).await?;
                } else if cut.refs.as_ref().is_some_and(|saved| !saved.same_set(refs)) {
                    return Err(detailed(
                        RefusalCode::InvalidState,
                        "prepared snapshot ref set changed",
                        json!({"step":step,"refs":cut.refs}),
                    ));
                }
                // An agent with no marks gets no item: an empty cut entry
                // lets the driver skip a receiver that runs no cerebellum,
                // while any marked agent still needs a participant there.
                let mut items = Vec::new();
                for r in refs.as_slice() {
                    let payload = cut.payloads.get(&r.r#ref).expect("snapshot for ref");
                    if payload.sources.is_empty() {
                        continue;
                    }
                    let item = self.upload(payload, id, step).await?;
                    let mut value = serde_json::to_value(item).unwrap();
                    let fields = value.as_object_mut().unwrap();
                    fields.insert("ref_kind".into(), json!("agent"));
                    fields.insert("ref".into(), json!(r.r#ref));
                    fields.insert("format".into(), json!(FORMAT));
                    fields.insert("frozen".into(), json!(false));
                    items.push(value);
                }
                json!({"items":items,"external":[]})
            }
            Op::Export => {
                let mut items = Vec::new();
                for payload in cut.payloads.values().filter(|p| !p.sources.is_empty()) {
                    let item = self.upload(payload, id, step).await?;
                    items.push(json!({"sessionRef":item.session_ref,"endOffset":item.end_offset}));
                }
                json!({"items":items})
            }
            Op::Import => {
                let mut items = Vec::new();
                let mut payloads = BTreeMap::new();
                for r in refs.as_slice() {
                    let (item, payload) = self.download(op, &r.r#ref, id).await?;
                    payloads.insert(r.r#ref.clone(), payload);
                    if let Some(item) = item {
                        items.push(json!({"sessionRef":item.session_ref,"endOffset":item.end_offset,"digest":item.digest}));
                    }
                }
                // No replacement or staging: importing only adds marks, so it
                // cannot discard anything recorded here, even reads made after
                // this computer answered the driver's divergence check.
                for payload in payloads.values().filter(|p| !p.sources.is_empty()) {
                    if !marks
                        .import_agent(&payload.agent_id, &payload.sources)
                        .await
                    {
                        return Err(unavailable("private-content marks did not persist"));
                    }
                }
                cut.refs = Some(refs.clone());
                cut.payloads = payloads;
                json!({"items":items})
            }
            Op::Activate | Op::Abort => json!({}),
            Op::Release => json!({"enforced":false}),
            _ => unreachable!("reads returned above"),
        };
        cut.step = next;
        // No op after a finished step reads the snapshot or the ref set: the
        // saved replies below answer every repeat. Dropping them keeps a
        // finished cut small; see the checkpoint module for retiring it.
        if matches!(next, Step::Activated | Step::Released | Step::Aborted) {
            cut.payloads.clear();
            cut.refs = None;
        }
        cut.replies.insert(
            op.method().into(),
            checkpoint::Reply {
                request: canonical,
                reply: reply.clone(),
            },
        );
        document.cuts.insert(id.to_owned(), cut);
        self.save(document, memory).await?;
        Ok(reply)
    }
}

pub(crate) async fn handle(
    frame: &Frame,
    writer: &tokio::sync::mpsc::Sender<Frame>,
    facts: &AcceptedBindFacts,
    planes: &Planes,
) -> Result<(), ModuleError> {
    let outcome = if !is_driver(&facts.principal) {
        Err(error(
            RefusalCode::CallerForbidden,
            "agent-data admits only reserved:entorhinal",
        ))
    } else {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Envelope {
            method: String,
            params: Value,
        }
        match serde_json::from_slice::<Envelope>(&frame.body) {
            Err(_) => Err(error(
                RefusalCode::InvalidRequest,
                "invalid agent-data envelope",
            )),
            Ok(body) => match Request::decode(&body.method, &body.params) {
                Err(e) => Err(e),
                Ok(request) => {
                    let op = request.op();
                    planes
                        .agent_data
                        .execute(&planes.private_content, request)
                        .await
                        .map_err(|e| {
                            if cortexkit_role_agent_data::errors::allowed_refusals(op)
                                .contains(&e.code)
                            {
                                e
                            } else {
                                unavailable(e)
                            }
                        })
                }
            },
        }
    };
    let (ty, body) = match outcome {
        Ok(reply) => (subc_protocol::FrameType::Response, json!({"result":reply})),
        Err(e) => (
            subc_protocol::FrameType::Error,
            serde_json::to_value(e).map_err(ModuleError::Json)?,
        ),
    };
    let response = Frame::build_with_version(
        frame.header.ver,
        ty,
        subc_protocol::Flags::new(false, subc_protocol::Priority::Background, false),
        frame.header.channel,
        frame.header.epoch,
        frame.header.corr,
        serde_json::to_vec(&body).map_err(ModuleError::Json)?,
    )
    .map_err(|e| ModuleError::Message(e.to_string()))?;
    crate::send(writer, response).await
}

#[cfg(test)]
pub(crate) mod tests;
