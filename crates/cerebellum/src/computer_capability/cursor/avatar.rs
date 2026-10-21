//! Read-only, memory-only avatar recipes. The helper receives pixels, not recipes.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cerebellum_computer::cursor::{
    area_average, avatar_tint, AvatarTint, AVATAR_SIZE, TINT_RENDER_SIDE, TINT_SAMPLE_SIDE,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::login_capture::vault::{ClaustrumVault, CookieVault};

const FETCH_BUDGET: Duration = Duration::from_secs(1);
const CACHE_CAPACITY: usize = 32;
/// Agents whose avatar colour is remembered: one per badge the helper can
/// draw at once, which is far more agents than one person runs together.
const TINT_CAPACITY: usize = 64;
static MALFORMED_ROWS: AtomicU64 = AtomicU64::new(0);
static READ_REFUSALS: AtomicU64 = AtomicU64::new(0);

pub(crate) fn malformed_rows() -> u64 {
    MALFORMED_ROWS.load(Ordering::Relaxed)
}
pub(crate) fn read_refusals() -> u64 {
    READ_REFUSALS.load(Ordering::Relaxed)
}

fn avatar_read_request(agent_ids: &[&str]) -> Vec<u8> {
    serde_json::to_vec(
        &serde_json::json!({"method":"agent.avatar_read", "params":{"agentIds":agent_ids}}),
    )
    .unwrap_or_default()
}

#[derive(Clone, Deserialize)]
struct AvatarRow {
    #[serde(rename = "agentId")]
    agent_id: String,
    genome: String,
    #[serde(rename = "type")]
    avatar_type: String,
    version: Option<u32>,
}

#[derive(Deserialize)]
struct Reply {
    result: AvatarRead,
}

#[derive(Deserialize)]
struct AvatarRead {
    avatars: Vec<AvatarRow>,
    generation: u64,
    incarnation: String,
}

fn decode_reply(bytes: &[u8], agent: &str) -> Option<AvatarRow> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    if value
        .get("code")
        .and_then(serde_json::Value::as_str)
        .is_some()
    {
        READ_REFUSALS.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    let reply: Reply = serde_json::from_value(value).ok()?;
    let _ = (reply.result.generation, reply.result.incarnation);
    reply
        .result
        .avatars
        .into_iter()
        .find(|row| row.agent_id == agent)
}

#[derive(PartialEq, Eq)]
struct Key {
    genome_hash: [u8; 32],
    avatar_type: String,
    version: u32,
    mood: &'static str,
    size: u32,
}

#[derive(Default)]
struct Cache {
    entries: VecDeque<(Key, Rendered)>,
    renders: usize,
    malformed: u64,
}

/// One genome's renders: the badge's avatar pixels, and the agent colour
/// read from the creature (`None` when it has no colourful pixels, which
/// draws the neutral colour).
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Rendered {
    pub(crate) pixels: Vec<u8>,
    pub(crate) tint: Option<AvatarTint>,
}

/// The creature drawn `side` pixels square, premultiplied RGBA, with its
/// ground shadow or without it. The badge and the colour reading both come
/// through here, so they always show the same creature.
fn rasterize(
    bytes: &[u8],
    avatar_type: &str,
    version: u32,
    side: u32,
    ground_shadow: bool,
) -> Option<Vec<u8>> {
    let mut tree =
        avatar_svg::render_tree_for_bytes(bytes, avatar_type, version, avatar_svg::Mood::Neutral)
            .ok()?;
    if !ground_shadow {
        tree.primitives
            .retain(|primitive| primitive.role != Some(avatar_svg::Role::GroundShadow));
    }
    let svg = avatar_svg::serialize_tree(&tree);
    let svg_tree = resvg::usvg::Tree::from_data(&svg, &resvg::usvg::Options::default()).ok()?;
    let mut pixmap = resvg::tiny_skia::Pixmap::new(side, side)?;
    let scale = side as f32 / svg_tree.size().width();
    resvg::render(
        &svg_tree,
        resvg::tiny_skia::Transform::from_scale(scale, scale),
        &mut pixmap.as_mut(),
    );
    Some(pixmap.take())
}

/// The agent's colour the way the Alfonso phone app reads it, so a badge
/// here matches the agent's page there: the creature in its neutral mood,
/// with its ground shadow as the phone draws it, at the phone's size, then
/// averaged down to the phone's 24 x 24 sample. Memory only.
fn read_tint(bytes: &[u8], avatar_type: &str, version: u32) -> Option<AvatarTint> {
    let side = TINT_RENDER_SIDE;
    let pixels = rasterize(bytes, avatar_type, version, side, true)?;
    avatar_tint(&area_average(&pixels, side as usize, TINT_SAMPLE_SIDE))
}

impl Cache {
    fn render(&mut self, row: &AvatarRow) -> Option<Rendered> {
        let (length, default_version) = match row.avatar_type.as_str() {
            "creature.wild" => (16_384, 1),
            "creature.classic" => (1_024, 2),
            _ => return None,
        };
        let version = row.version.unwrap_or(default_version);
        if version != default_version {
            return None;
        }
        let hex = row.genome.as_bytes();
        if hex.len() != length * 2
            || !hex
                .iter()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
        {
            self.malformed += 1;
            MALFORMED_ROWS.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let bytes: Vec<u8> = hex
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
            .collect::<Option<_>>()?;
        let key = Key {
            genome_hash: Sha256::digest(&bytes).into(),
            avatar_type: row.avatar_type.clone(),
            version,
            mood: "neutral",
            size: AVATAR_SIZE,
        };
        if let Some(index) = self.entries.iter().position(|(cached, _)| *cached == key) {
            let hit = self.entries.remove(index)?;
            let rendered = hit.1.clone();
            self.entries.push_back(hit);
            return Some(rendered);
        }
        self.renders += 1;
        // Ground shadows belong on a scene's floor, not inside a floating badge.
        let pixels = rasterize(&bytes, &row.avatar_type, version, AVATAR_SIZE, false)?;
        let rendered = Rendered {
            pixels,
            tint: read_tint(&bytes, &row.avatar_type, version),
        };
        if self.entries.len() == CACHE_CAPACITY {
            self.entries.pop_front();
        }
        self.entries.push_back((key, rendered.clone()));
        Some(rendered)
    }
}

pub(crate) struct Avatars {
    route: Arc<dyn CookieVault>,
    cache: Mutex<Cache>,
    /// Each agent's latest avatar colour, so its next badge, even after a
    /// hide, is drawn in that colour from the start instead of waiting for
    /// the avatar to be fetched again.
    tints: Mutex<VecDeque<(String, Option<AvatarTint>)>>,
    slots: Arc<tokio::sync::Semaphore>,
}

impl Avatars {
    pub(crate) fn supervised(connection_file: PathBuf, module_id: String) -> Self {
        Self::new(Arc::new(ClaustrumVault::management(
            connection_file,
            module_id,
            "entorhinal",
        )))
    }

    fn new(route: Arc<dyn CookieVault>) -> Self {
        Self {
            route,
            cache: Mutex::new(Cache::default()),
            tints: Mutex::new(VecDeque::new()),
            slots: Arc::new(tokio::sync::Semaphore::new(4)),
        }
    }

    /// The colour `agent`'s avatar was last read as: `None` until it has
    /// been, and `Some(None)` for an avatar with no colourful pixels.
    pub(super) fn known_tint(&self, agent: &str) -> Option<Option<AvatarTint>> {
        self.tints
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .find(|(known, _)| known == agent)
            .map(|(_, tint)| *tint)
    }

    fn remember_tint(&self, agent: &str, tint: Option<AvatarTint>) {
        let mut tints = self
            .tints
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tints.retain(|(known, _)| known != agent);
        if tints.len() == TINT_CAPACITY {
            tints.pop_front();
        }
        tints.push_back((agent.to_owned(), tint));
    }

    pub(super) async fn fetch_and_render(self: &Arc<Self>, agent: &str) -> Option<Rendered> {
        // Saturation drops cosmetics rather than queuing unbounded recipe reads.
        let permit = self.slots.clone().try_acquire_owned().ok()?;
        let row = tokio::time::timeout(FETCH_BUDGET, async {
            let mut route = self.route.open().await.ok()?;
            let reply = route.call(&avatar_read_request(&[agent])).await.ok()?;
            decode_reply(&reply, agent)
        })
        .await
        .ok()
        .flatten()?;
        let avatars = self.clone();
        let rendered = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            avatars
                .cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .render(&row)
        })
        .await
        .ok()
        .flatten()?;
        self.remember_tint(agent, rendered.tint);
        Some(rendered)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::login_capture::vault::{BoxFuture, VaultReachError, VaultRoute};
    use crate::test_support::HANG_GUARD;

    const VECTORS: &[u8] =
        include_bytes!("../../../tests/vectors/agent-identity-reads-v1/avatar-read.json");
    const REAL_GENOME: &str =
        include_str!("../../../tests/vectors/agent-identity-reads-v1/wild-port-0005.hex");

    fn fixture(agent: &str) -> AvatarRow {
        AvatarRow {
            agent_id: agent.into(),
            genome: REAL_GENOME.trim().into(),
            avatar_type: "creature.wild".into(),
            version: Some(1),
        }
    }

    #[test]
    fn pinned_entorhinal_vectors_decode_and_pin_the_request_envelope() {
        assert_eq!(
            format!("{:x}", Sha256::digest(VECTORS)),
            "40b1d942b8b69117121441574cc550826d6f1243a4a8a0768a15ce80efcb125a"
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(REAL_GENOME.as_bytes())),
            "29092c973687a3a99ef294aa1fb2fbf68cafe37e7cc61dce1cca5f1ae1ea78b5"
        );
        let vectors: Vec<serde_json::Value> = serde_json::from_slice(VECTORS).unwrap();
        for vector in &vectors {
            let ids: Vec<_> = vector["request"]["agentIds"]
                .as_array()
                .unwrap()
                .iter()
                .map(|id| id.as_str().unwrap())
                .collect();
            let encoded: serde_json::Value =
                serde_json::from_slice(&avatar_read_request(&ids)).unwrap();
            assert_eq!(
                encoded,
                serde_json::json!({"method":vector["op"], "params":vector["request"]})
            );
            let reply = serde_json::to_vec(&vector["reply"]).unwrap();
            if let Some(avatars) = vector["reply"]["result"]["avatars"].as_array() {
                for expected in avatars {
                    let row = decode_reply(&reply, expected["agentId"].as_str().unwrap()).unwrap();
                    assert_eq!(row.genome, expected["genome"]);
                    assert_eq!(row.avatar_type, expected["type"]);
                }
                assert!(decode_reply(&reply, "unknown-agent").is_none());
            } else {
                let before = read_refusals();
                assert!(decode_reply(&reply, "agent").is_none());
                assert!(read_refusals() > before);
                let subc_protocol::session::ModuleControlResponse::HealthCheck {
                    metrics: Some(metrics),
                    ..
                } = crate::with_process_gauges(crate::HealthState::new().report())
                else {
                    panic!("missing health metrics");
                };
                assert!(metrics["cursorAvatarReadRefusals"].as_u64().unwrap() > before);
            }
        }
    }

    #[test]
    fn real_fixture_raster_has_badge_dimensions_and_visible_pixels() {
        let mut cache = Cache::default();
        let pixels = cache.render(&fixture("agent-a")).unwrap().pixels;
        assert_eq!(pixels.len(), (AVATAR_SIZE * AVATAR_SIZE * 4) as usize);
        assert!(pixels.as_chunks::<4>().0.iter().any(|pixel| pixel[3] != 0));
        assert_eq!(cache.renders, 1);
        // Removing a role is independent of whichever label AVA gives it.
        let bytes = vec![0xaa; 16_384];
        let tree = avatar_svg::render_tree_for_bytes(
            &bytes,
            "creature.wild",
            1,
            avatar_svg::Mood::Neutral,
        )
        .unwrap();
        assert!(tree
            .primitives
            .iter()
            .any(|primitive| primitive.role == Some(avatar_svg::Role::GroundShadow)));
    }

    /// Agent colours the Alfonso phone app computed for three creatures; see
    /// the README beside the file.
    const COLOUR_VECTORS: &str = include_str!("../../../tests/fixtures/avatar-colour/vectors.json");

    #[derive(Deserialize)]
    struct ColourVector {
        fingerprint: String,
        avatar_type: String,
        avatar_version: u32,
        genome_hex: String,
        dock_hue: f64,
        dock_sat: f64,
    }

    /// How close our reading must come to the phone's. The phone rasterizes
    /// with CoreGraphics and we with resvg, so a pixel here and there
    /// differs; CKIOS, who produced the vectors, gave these margins for that.
    const HUE_TOLERANCE: f64 = 0.003;
    const SATURATION_TOLERANCE: f64 = 0.015;

    #[test]
    fn avatar_colour_matches_the_phone_for_its_reference_creatures() {
        let vectors: Vec<ColourVector> = serde_json::from_str(COLOUR_VECTORS).unwrap();
        assert_eq!(vectors.len(), 3);
        let mut cache = Cache::default();
        let mut misses = Vec::new();
        for vector in &vectors {
            // Through the same decoding the live badge uses for a genome
            // from Entorhinal: its length and type are checked there.
            let row = AvatarRow {
                agent_id: vector.fingerprint.clone(),
                genome: vector.genome_hex.clone(),
                avatar_type: vector.avatar_type.clone(),
                version: Some(vector.avatar_version),
            };
            let tint = cache
                .render(&row)
                .unwrap_or_else(|| panic!("{} did not decode", vector.fingerprint))
                .tint
                .unwrap_or_else(|| panic!("{} has no colour", vector.fingerprint));
            let hue_gap = {
                let gap = (tint.hue - vector.dock_hue).rem_euclid(1.0);
                gap.min(1.0 - gap)
            };
            let saturation_gap = (tint.saturation - vector.dock_sat).abs();
            eprintln!(
                "{}: hue {:.6} (phone {:.6}, gap {hue_gap:.6}), saturation {:.6} \
                 (phone {:.6}, gap {saturation_gap:.6})",
                vector.fingerprint, tint.hue, vector.dock_hue, tint.saturation, vector.dock_sat
            );
            if hue_gap > HUE_TOLERANCE || saturation_gap > SATURATION_TOLERANCE {
                misses.push(vector.fingerprint.clone());
            }
        }
        assert!(misses.is_empty(), "off the phone's colour: {misses:?}");
    }

    #[test]
    fn malformed_genomes_are_plain_and_counted_before_rendering() {
        let before = malformed_rows();
        let mut cache = Cache::default();
        for (kind, length) in [("creature.wild", 32768), ("creature.classic", 2048)] {
            for genome in [
                "z".repeat(length),
                "a".repeat(length - 2),
                "A".repeat(length),
            ] {
                let mut row = fixture("agent-a");
                row.avatar_type = kind.into();
                row.version = None;
                row.genome = genome;
                assert!(cache.render(&row).is_none());
            }
        }
        assert_eq!(cache.malformed, 6);
        assert_eq!(cache.renders, 0);
        assert!(cache.entries.is_empty());
        let subc_protocol::session::ModuleControlResponse::HealthCheck {
            metrics: Some(metrics),
            ..
        } = crate::with_process_gauges(crate::HealthState::new().report())
        else {
            panic!("missing health metrics");
        };
        assert!(metrics["cursorAvatarMalformedRows"].as_u64().unwrap() >= before + 6);
    }

    #[test]
    fn unsupported_type_or_version_is_quietly_plain() {
        let mut cache = Cache::default();
        let mut row = fixture("agent-a");
        row.version = Some(999);
        assert!(cache.render(&row).is_none());
        row.avatar_type = "unknown".into();
        row.version = None;
        assert!(cache.render(&row).is_none());
        assert_eq!(cache.malformed, 0);
        assert_eq!(cache.renders, 0);
    }

    #[test]
    fn cache_reuses_genomes_across_agents_and_rerenders_rolls() {
        let mut cache = Cache::default();
        let first = fixture("agent-a");
        let second = fixture("agent-b");
        assert_eq!(cache.render(&first), cache.render(&second));
        assert_eq!(
            cache.renders, 1,
            "same genome under different ids must render once"
        );
        let mut rerolled = first.clone();
        rerolled.genome = "ab".repeat(16_384);
        assert!(cache.render(&rerolled).is_some());
        assert_eq!(
            cache.renders, 2,
            "a re-roll for the same id must render again"
        );
        assert_eq!(cache.entries.len(), 2);
    }

    #[test]
    fn cache_is_bounded_and_hits_refresh_recency() {
        let mut cache = Cache::default();
        let row = fixture("agent-a");
        let pixels = cache.render(&row).unwrap();
        for n in 1..CACHE_CAPACITY {
            let key = Key {
                genome_hash: [n as u8; 32],
                avatar_type: row.avatar_type.clone(),
                version: 1,
                mood: "neutral",
                size: AVATAR_SIZE,
            };
            cache.entries.push_back((key, pixels.clone()));
        }
        cache.render(&row).unwrap();
        assert_eq!(cache.renders, 1);
        let mut reroll = row.clone();
        reroll.agent_id = "agent-b".into();
        reroll.genome = "ac".repeat(16_384);
        cache.render(&reroll).unwrap();
        assert_eq!(cache.entries.len(), CACHE_CAPACITY);
        assert_ne!(cache.entries.front().unwrap().0.genome_hash, [1; 32]);
        cache.render(&row).unwrap();
        assert_eq!(cache.renders, 2, "the refreshed entry must not be evicted");
    }

    struct ScriptedEntorhinal {
        reply: Option<Vec<u8>>,
        fail: bool,
    }

    impl CookieVault for ScriptedEntorhinal {
        fn open(&self) -> BoxFuture<'_, Result<Box<dyn VaultRoute>, VaultReachError>> {
            Box::pin(async {
                Ok(Box::new(Self {
                    reply: self.reply.clone(),
                    fail: self.fail,
                }) as Box<dyn VaultRoute>)
            })
        }
    }

    impl VaultRoute for ScriptedEntorhinal {
        fn call<'a>(
            &'a mut self,
            request: &'a [u8],
        ) -> BoxFuture<'a, Result<Vec<u8>, VaultReachError>> {
            Box::pin(async move {
                let request: serde_json::Value = serde_json::from_slice(request).unwrap();
                assert_eq!(request["method"], "agent.avatar_read");
                assert_eq!(
                    request["params"]["agentIds"],
                    serde_json::json!(["agent-a"])
                );
                if self.fail {
                    return Err(VaultReachError::Unreachable);
                }
                match &self.reply {
                    Some(bytes) => Ok(bytes.clone()),
                    None => std::future::pending().await,
                }
            })
        }
    }

    fn source(reply: Option<serde_json::Value>, fail: bool) -> Arc<Avatars> {
        Arc::new(Avatars::new(Arc::new(ScriptedEntorhinal {
            reply: reply.map(|value| serde_json::to_vec(&value).unwrap()),
            fail,
        })))
    }

    struct VisibleGeometry;
    impl cerebellum_computer::app_state::source::AppStateSource for VisibleGeometry {
        fn read_app_state(
            &self,
            _: &cerebellum_computer::platform::ProcessGrant,
            _: cerebellum_computer::app_state::source::ReadBounds,
        ) -> Result<
            cerebellum_computer::app_state::source::RawAppState,
            cerebellum_computer::app_state::source::AppStateReadError,
        > {
            Err(cerebellum_computer::app_state::source::AppStateReadError::Unreadable)
        }
        fn visible_cursor_point(
            &self,
            _: &cerebellum_computer::platform::ProcessGrant,
            _: Option<[f64; 2]>,
            _: Option<[f64; 4]>,
        ) -> Option<[f64; 2]> {
            Some([10.0, 20.0])
        }
    }

    async fn scheduled(
        avatars: Arc<Avatars>,
    ) -> tokio::sync::mpsc::Receiver<cerebellum_computer::cursor::CursorEvent> {
        let (cursor, mut lines) = super::super::Coordinator::channel();
        cursor.set_avatars(avatars);
        cursor.schedule(
            super::super::Identity {
                badge: "agent-a".into(),
                avatar_agent: Some("agent-a".into()),
                call: None,
                session: None,
            },
            cerebellum_computer::cursor::CursorKind::Reading,
            cerebellum_computer::platform::ProcessGrant {
                bundle_identity: "fixture".into(),
                pid: 7,
                process_generation_evidence: "fixture".into(),
            },
            Arc::new(VisibleGeometry),
            None,
            None,
        );
        // Nothing here ends a badge, so every line is a picture; forwarding
        // only pictures keeps these tests about the pictures themselves.
        let (pictures, receiver) = tokio::sync::mpsc::channel(8);
        tokio::spawn(async move {
            while let Some(line) = lines.recv().await {
                let picture = line.picture().expect("no badge was ended");
                if pictures.send(picture).await.is_err() {
                    break;
                }
            }
        });
        receiver
    }

    #[tokio::test]
    async fn missing_avatar_sends_only_the_plain_badge() {
        let avatars = source(
            Some(
                serde_json::json!({"result":{"avatars":[],"generation":1,"incarnation":"0123456789abcdef"}}),
            ),
            false,
        );
        let mut events = scheduled(avatars.clone()).await;
        assert!(events.recv().await.unwrap().avatar_rgba.is_none());
        assert!(events.recv().await.is_none());
        assert_eq!(avatars.cache.lock().unwrap().renders, 0);
    }

    #[tokio::test]
    async fn ready_avatar_decorates_the_same_event_after_the_plain_badge() {
        let row = fixture("agent-a");
        let avatars = source(
            Some(
                serde_json::json!({"result":{"avatars":[{"agentId":row.agent_id,"genome":row.genome,"type":row.avatar_type,"version":1}],"generation":1,"incarnation":"0123456789abcdef"}}),
            ),
            false,
        );
        let mut events = scheduled(avatars).await;
        let plain = events.recv().await.unwrap();
        let update = events.recv().await.unwrap();
        assert!(plain.avatar_rgba.is_none());
        assert!(!plain.avatar_update);
        assert!(update.avatar_update);
        assert_eq!(update.serial, plain.serial);
        assert_eq!(update.to, plain.to);
        assert!(update
            .avatar_rgba
            .unwrap()
            .as_chunks::<4>()
            .0
            .iter()
            .any(|pixel| pixel[3] != 0));
    }

    #[tokio::test]
    async fn the_avatar_colour_rides_with_the_avatar_and_starts_the_next_badge() {
        let row = fixture("agent-a");
        let avatars = source(
            Some(
                serde_json::json!({"result":{"avatars":[{"agentId":row.agent_id,"genome":row.genome,"type":row.avatar_type,"version":1}],"generation":1,"incarnation":"0123456789abcdef"}}),
            ),
            false,
        );
        let mut events = scheduled(avatars.clone()).await;
        let plain = events.recv().await.unwrap();
        let update = events.recv().await.unwrap();
        // Unknown at first: the helper draws the neutral colour.
        assert_eq!(plain.avatar_tint, None);
        let tint = update
            .avatar_tint
            .expect("the colour comes with the avatar");
        assert!(tint.valid());
        // A later badge, even a fresh one after a hide, starts in that colour.
        let mut events = scheduled(avatars).await;
        let next = events.recv().await.unwrap();
        assert!(!next.avatar_update);
        assert_eq!(next.avatar_tint, Some(tint));
    }

    #[tokio::test]
    async fn hanging_or_failed_avatar_fetch_never_delays_the_action_or_plain_badge() {
        // Prove ordering while the optional fetch is unresolved instead of
        // asserting a wall-clock latency that can vary with host load.
        for fail in [false, true] {
            let avatars = source(None, fail);
            let mut events = scheduled(avatars.clone()).await;
            let plain = tokio::time::timeout(HANG_GUARD, events.recv())
                .await
                .expect("badge waited for entorhinal")
                .unwrap();
            assert!(plain.avatar_rgba.is_none());
            // The single-thread Tokio test runtime must still dispatch other
            // work while the optional entorhinal request is waiting for a reply.
            assert_eq!(
                tokio::time::timeout(HANG_GUARD, tokio::spawn(async { "completed" }))
                    .await
                    .unwrap()
                    .unwrap(),
                "completed"
            );
            assert!(
                tokio::time::timeout(FETCH_BUDGET + Duration::from_millis(500), events.recv())
                    .await
                    .unwrap()
                    .is_none()
            );
            assert_eq!(avatars.slots.available_permits(), 4);
            assert_eq!(avatars.cache.lock().unwrap().renders, 0);
        }
    }
}
