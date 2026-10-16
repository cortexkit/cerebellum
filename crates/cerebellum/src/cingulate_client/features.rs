//! Unknown peer capabilities must never make an older Cingulate reject a card.

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CingulateFeatures {
    pub option_group: bool,
    /// Cingulate 0.7.1 understands this marker; older versions reject it.
    pub single_use: bool,
}

pub(crate) fn negotiated(reported: Option<CingulateFeatures>) -> CingulateFeatures {
    reported.unwrap_or_default()
}

pub(crate) fn from_catalog(body: &[u8]) -> Option<CingulateFeatures> {
    let subc_control::ClientControlResponse::CatalogList { modules, .. } =
        serde_json::from_slice(body).ok()?
    else {
        return None;
    };
    Some(CingulateFeatures {
        option_group: modules.iter().any(|module| {
            module.module_id == "cingulate"
                && module.capabilities.as_ref().is_some_and(|capabilities| {
                    capabilities
                        .provides
                        .iter()
                        .any(|capability| capability == "consent-option-group/v1")
                })
        }),
        single_use: modules.iter().any(|module| {
            module.module_id == "cingulate"
                && module.capabilities.as_ref().is_some_and(|capabilities| {
                    capabilities
                        .provides
                        .iter()
                        .any(|capability| capability == "consent-single-use/v1")
                })
        }),
    })
}

pub(crate) async fn discover(stream: &mut tokio::net::TcpStream) -> Option<CingulateFeatures> {
    use subc_protocol::{Frame, FrameType};
    use subc_transport::{read_frame, write_frame};
    // Each route opening reads Cingulate's catalog on its connection.
    // A missing declaration or an error is not cached across routes.
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let request = subc_control::ClientControlRequest::CatalogList {
            module_id: Some("cingulate".into()),
        };
        let frame = Frame::build(
            FrameType::Request,
            crate::control_flags(),
            0,
            0,
            2,
            serde_json::to_vec(&request).ok()?,
        )
        .ok()?;
        write_frame(stream, &frame).await.ok()?;
        loop {
            let reply = read_frame(stream).await.ok()??;
            if reply.header.channel == 0 && reply.header.corr == 2 {
                return (reply.header.ty == FrameType::Response)
                    .then(|| from_catalog(&reply.body))
                    .flatten();
            }
        }
    })
    .await
    .ok()
    .flatten()
}

impl super::card::CardRequest {
    pub(crate) fn for_features(mut self, features: CingulateFeatures) -> Self {
        let single_use = features.single_use
            && matches!(
                self.kind,
                super::card::CardKind::LoginCapture | super::card::CardKind::LoginImport
            );
        let params = self.params.as_object_mut().expect("mapped card params");
        if single_use {
            params.insert("single_use".into(), serde_json::Value::Bool(true));
        } else {
            // Cingulate rejects this field on older versions and on other card kinds.
            params.remove("single_use");
        }
        if !features.option_group {
            let options = params
                .get_mut("options")
                .expect("mapped card options")
                .as_array_mut()
                .expect("mapped card options");
            options.retain(|option| option["group"] != "danger");
            self.grant_ids
                .retain(|id| options.iter().any(|option| option["id"] == *id));
            self.next_steps
                .retain(|id, _| options.iter().any(|option| option["id"] == *id));
        }
        self
    }
}
