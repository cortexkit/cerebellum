//! Element ids that stay attached to the same element across reads, and the
//! diff between one read and the next.
//!
//! A session is one conversation reading one process generation of one
//! application. Its map pairs each retained element with a small number;
//! a later read finds the same element again by token equality, never by
//! position or title, so the id keeps naming it while it lives.
//!
//! An id is the bare number, such as `389`, because a caller reads and types
//! hundreds of them. Every session draws from one counter, so a number names
//! one element of one application of one conversation, and an action given
//! only the number knows which application it is about. A number is issued
//! once and never again: a new process generation is a new session whose
//! numbers continue the count, so nothing it numbers can answer to an old
//! id, and two conversations never hold the same number.
//!
//! The count restarts with the module. A caller that kept an id from before
//! a restart finds it stale until it reads again, because nothing resolves
//! before a read; once it has read, the ids it holds are the new ones.
//!
//! The map belongs to a conversation. Two conversations reading the same
//! application get separate sessions with disjoint ids, so neither can act on
//! or move the diff baseline of the other, and a conversation's sessions end
//! when it does.

use std::collections::hash_map::RandomState;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::hash::{BuildHasher, Hasher};
use std::sync::Mutex;

use super::image::ImageMapping;
use super::render::{self, describe, is_session_ending_item, ObservedNode};
use super::source::{ElementHandle, RawAppState, RawElement};
use crate::platform::ProcessGrant;

/// The most elements one session numbers. Past it, new elements go
/// unnumbered and the reply says so; a live element is never evicted to make
/// room, so nothing the agent can see turns stale because the map filled.
///
/// Twice the read bound, so one complete read always fits and a view change
/// still finds room while the previous view's ids wait out their eviction.
/// Discord's tree measured about 2,260 elements, and at a cap below that its
/// last-read elements (the direct-message list among them) had no ids and
/// could not be pressed.
pub const MAX_SESSION_ELEMENTS: usize = 2 * super::source::READ_BOUND_ELEMENTS;

/// How many consecutive complete reads an element may be missing from before
/// its id is retired. More than one, so an element that flickers out for a
/// single read (a menu rebuilding, a list re-rendering) keeps its id.
pub const EVICT_AFTER_ABSENT_READS: u8 = 3;

/// The most images remembered per conversation for point mapping. An image
/// is only useful until the agent reads again, so a handful is plenty.
const MAX_IMAGES_PER_CONVERSATION: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct SessionKey {
    conversation_key: String,
    bundle_identity: String,
    pid: u32,
    process_generation: String,
}

impl SessionKey {
    fn new(conversation_key: &str, target: &ProcessGrant) -> Self {
        Self {
            conversation_key: conversation_key.to_string(),
            bundle_identity: target.bundle_identity.clone(),
            pid: target.pid,
            process_generation: target.process_generation_evidence.clone(),
        }
    }

    fn same_application(&self, other: &Self) -> bool {
        self.conversation_key == other.conversation_key
            && self.bundle_identity == other.bundle_identity
    }
}

#[derive(Debug)]
struct Entry {
    number: u64,
    handle: ElementHandle,
    signature: String,
    /// Whether the element was seen by the last read that could tell,
    /// which is what a diff compares against and what `resolve` requires.
    in_baseline: bool,
    absent_reads: u8,
    /// A session-ending menu item, or something beneath one: numbered so a
    /// press on it can be recognised and refused, never shown.
    refusing: bool,
}

#[derive(Debug)]
struct Session {
    entries: BTreeMap<u64, Entry>,
    by_hash: HashMap<u64, Vec<u64>>,
    /// Whether any read has set a baseline yet. A diff with none reports
    /// nothing rather than reporting everything as added.
    has_baseline: bool,
}

impl Session {
    fn element_id(&self, number: u64) -> String {
        session_element_id(number)
    }

    fn find(&self, handle: &ElementHandle) -> Option<u64> {
        self.by_hash
            .get(&handle.identity_hash())?
            .iter()
            .copied()
            .find(|number| {
                self.entries
                    .get(number)
                    .is_some_and(|entry| entry.handle.same_element(handle.as_ref()))
            })
    }

    /// Number a new element with the conversation's next number, or `None`
    /// when the session is at its cap.
    fn insert(
        &mut self,
        next_number: &mut u64,
        handle: ElementHandle,
        signature: String,
        refusing: bool,
    ) -> Option<u64> {
        if self.entries.len() >= MAX_SESSION_ELEMENTS {
            return None;
        }
        *next_number += 1;
        let number = *next_number;
        self.by_hash
            .entry(handle.identity_hash())
            .or_default()
            .push(number);
        self.entries.insert(
            number,
            Entry {
                number,
                handle,
                signature,
                in_baseline: false,
                absent_reads: 0,
                refusing,
            },
        );
        Some(number)
    }

    fn evict(&mut self, number: u64) {
        if let Some(entry) = self.entries.remove(&number) {
            let hash = entry.handle.identity_hash();
            if let Some(numbers) = self.by_hash.get_mut(&hash) {
                numbers.retain(|candidate| *candidate != entry.number);
                if numbers.is_empty() {
                    self.by_hash.remove(&hash);
                }
            }
        }
    }
}

/// What changed between the session's baseline and a new read. Only elements
/// a reply may show appear here: session-ending menu items never do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StateDiff {
    pub changed: Vec<String>,
    pub added: Vec<String>,
    pub removed: Vec<String>,
}

/// One read, numbered by its session.
#[derive(Debug, Clone)]
pub struct SessionRead {
    pub roots: Vec<ObservedNode>,
    pub focused_element_id: Option<String>,
    pub unreadable_subtrees: usize,
    pub diff: StateDiff,
}

/// Where an element id leads.
#[derive(Debug, Clone)]
pub enum ElementResolution {
    /// A live element of this conversation's session, with the application
    /// whose grant an action on it must hold.
    Live {
        handle: ElementHandle,
        bundle_identity: String,
        pid: u32,
        process_generation: String,
    },
    /// A session-ending menu item: never pressable.
    Refusing,
    /// Unknown, evicted, gone from the last complete read, from a process
    /// generation that has ended, or issued to another conversation. The
    /// remedy for all of them is the same: read the state again.
    Stale,
}

/// The possible results of giving a session id to an element found by a hit
/// test rather than by a read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Adoption {
    /// The element's id in the session.
    Numbered(String),
    /// A session-ending menu item the session already knows: never pressable.
    Refusing,
    /// The session is at its element cap; the element goes unnumbered.
    Full,
    /// The conversation has not read this process generation.
    NoSession,
}

/// An image the conversation was given, and how its pixels map to the screen.
#[derive(Debug, Clone, PartialEq)]
pub struct RegisteredImage {
    pub bundle_identity: String,
    pub pid: u32,
    pub process_generation: String,
    pub width_px: u32,
    pub height_px: u32,
    pub mapping: ImageMapping,
}

#[derive(Debug, Default)]
struct StoreState {
    next_image: u64,
    sessions: BTreeMap<SessionKey, Session>,
    /// The last element number issued, by any session.
    last_number: u64,
    /// Which session issued each live number.
    owners: HashMap<u64, SessionKey>,
    images: HashMap<String, (String, RegisteredImage)>,
}

impl StoreState {
    /// Drop a session and forget which numbers it issued.
    fn remove_session(&mut self, key: &SessionKey) {
        if let Some(session) = self.sessions.remove(key) {
            for number in session.entries.keys() {
                self.owners.remove(number);
            }
        }
    }
}

/// Every conversation's element sessions, for the life of the module.
#[derive(Debug)]
pub struct AppStateSessions {
    /// Distinguishes this module process's image ids from a previous one's.
    /// Image numbers restart with the process, and without this an image id
    /// handed out before a restart would name whatever image a new read
    /// numbered the same.
    salt: String,
    state: Mutex<StoreState>,
}

impl Default for AppStateSessions {
    fn default() -> Self {
        Self::new()
    }
}

fn process_salt() -> String {
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or_default(),
    );
    hasher.write_u32(std::process::id());
    let mut value = hasher.finish();
    let alphabet = b"abcdefghijklmnopqrstuvwxyz";
    let mut salt = String::new();
    for _ in 0..4 {
        salt.push(alphabet[(value % 26) as usize] as char);
        value /= 26;
    }
    salt
}

impl AppStateSessions {
    pub fn new() -> Self {
        Self {
            salt: process_salt(),
            state: Mutex::new(StoreState::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, StoreState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Number a read, compare it with the session's baseline, and make it the
    /// new baseline.
    ///
    /// A process generation other than the one the conversation last read is
    /// a new session: its elements are new objects, and carrying ids across
    /// would point them at whatever the new process put in the same place.
    pub fn observe(
        &self,
        conversation_key: &str,
        target: &ProcessGrant,
        read: &RawAppState,
    ) -> SessionRead {
        let key = SessionKey::new(conversation_key, target);
        let mut guard = self.lock();
        let state = &mut *guard;
        let replaced: Vec<SessionKey> = state
            .sessions
            .keys()
            .filter(|existing| existing.same_application(&key) && **existing != key)
            .cloned()
            .collect();
        for old in replaced {
            state.remove_session(&old);
        }
        state.sessions.entry(key.clone()).or_insert_with(|| Session {
            entries: BTreeMap::new(),
            by_hash: HashMap::new(),
            has_baseline: false,
        });
        let session = state
            .sessions
            .get_mut(&key)
            .expect("the session was just ensured");
        let next_number = &mut state.last_number;
        let first_new = *next_number + 1;

        let mut walk = Walk {
            session,
            next_number,
            seen: HashSet::new(),
            diff: StateDiff::default(),
        };
        let roots: Vec<ObservedNode> = read
            .roots
            .iter()
            .enumerate()
            .map(|(index, root)| walk.node(root, None, index, false, false))
            .collect();
        let Walk {
            session,
            next_number,
            seen,
            mut diff,
        } = walk;
        let last_new = *next_number;

        let complete = read.is_complete();
        let had_baseline = session.has_baseline;
        let mut evicted = Vec::new();
        for entry in session.entries.values_mut() {
            if seen.contains(&entry.number) {
                entry.in_baseline = true;
                entry.absent_reads = 0;
            } else if complete {
                // Only a read that visited everything can say an element is
                // gone. A read that left a subtree unopened may simply not
                // have reached it, so it neither removes nor ages anything.
                if entry.in_baseline && !entry.refusing && had_baseline {
                    diff.removed.push(session_element_id(entry.number));
                }
                entry.in_baseline = false;
                entry.absent_reads = entry.absent_reads.saturating_add(1);
                if entry.absent_reads >= EVICT_AFTER_ABSENT_READS {
                    evicted.push(entry.number);
                }
            }
        }
        for number in &evicted {
            session.evict(*number);
        }
        if !had_baseline {
            diff = StateDiff::default();
        }
        session.has_baseline = true;
        let focused_number = read
            .focused
            .as_ref()
            .and_then(|handle| session.find(handle))
            .filter(|number| {
                seen.contains(number)
                    && session
                        .entries
                        .get(number)
                        .is_some_and(|entry| !entry.refusing)
            });
        let issued: Vec<u64> = (first_new..=last_new)
            .filter(|number| session.entries.contains_key(number))
            .collect();
        for number in issued {
            state.owners.insert(number, key.clone());
        }
        for number in evicted {
            state.owners.remove(&number);
        }

        let focused_element_id = focused_number.map(session_element_id);

        SessionRead {
            roots,
            focused_element_id,
            unreadable_subtrees: read.unreadable_subtrees,
            diff,
        }
    }

    /// Give an element found some other way than by a read -- a hit test --
    /// an id in the conversation's session for its process, so it can be
    /// named in the diff that follows an action on it.
    ///
    /// An element the session already numbered keeps its id. A new one is
    /// numbered but not yet part of the baseline, so the next read reports it
    /// as added if it is visible.
    pub fn adopt(
        &self,
        conversation_key: &str,
        target: &ProcessGrant,
        handle: &ElementHandle,
    ) -> Adoption {
        let key = SessionKey::new(conversation_key, target);
        let mut guard = self.lock();
        let state = &mut *guard;
        let Some(session) = state.sessions.get_mut(&key) else {
            return Adoption::NoSession;
        };
        if let Some(number) = session.find(handle) {
            return if session
                .entries
                .get(&number)
                .is_some_and(|entry| entry.refusing)
            {
                Adoption::Refusing
            } else {
                Adoption::Numbered(session.element_id(number))
            };
        }
        match session.insert(&mut state.last_number, handle.clone(), String::new(), false) {
            Some(number) => {
                state.owners.insert(number, key);
                Adoption::Numbered(session_element_id(number))
            }
            None => Adoption::Full,
        }
    }

    /// Whether a read differs from the conversation's baseline for this
    /// process, without moving the baseline. Used to wait for an action's
    /// effect to show before the diff is taken; a session with no baseline
    /// counts as changed, since there is nothing to wait against.
    pub fn differs_from_baseline(
        &self,
        conversation_key: &str,
        target: &ProcessGrant,
        read: &RawAppState,
    ) -> bool {
        let key = SessionKey::new(conversation_key, target);
        let state = self.lock();
        let Some(session) = state.sessions.get(&key) else {
            return true;
        };
        if !session.has_baseline {
            return true;
        }
        let mut seen = HashSet::new();
        let mut stack: Vec<&RawElement> = read.roots.iter().collect();
        while let Some(element) = stack.pop() {
            stack.extend(element.children.iter());
            match session.find(&element.handle) {
                Some(number) => {
                    let entry = &session.entries[&number];
                    if !entry.in_baseline || entry.signature != describe(element).signature() {
                        return true;
                    }
                    seen.insert(number);
                }
                None => return true,
            }
        }
        read.is_complete()
            && session
                .entries
                .values()
                .any(|entry| entry.in_baseline && !seen.contains(&entry.number))
    }

    /// Where an element id leads, for the conversation holding it.
    pub fn resolve(&self, conversation_key: &str, element_id: &str) -> ElementResolution {
        let Some(number) = parse_element_id(element_id) else {
            return ElementResolution::Stale;
        };
        let state = self.lock();
        let Some(key) = state.owners.get(&number) else {
            return ElementResolution::Stale;
        };
        if key.conversation_key != conversation_key {
            return ElementResolution::Stale;
        }
        let Some(session) = state.sessions.get(key) else {
            return ElementResolution::Stale;
        };
        match session.entries.get(&number) {
            Some(entry) if entry.refusing => ElementResolution::Refusing,
            Some(entry) if entry.in_baseline => ElementResolution::Live {
                handle: entry.handle.clone(),
                bundle_identity: key.bundle_identity.clone(),
                pid: key.pid,
                process_generation: key.process_generation.clone(),
            },
            _ => ElementResolution::Stale,
        }
    }

    /// Remember an image handed to a conversation, and name it.
    pub fn register_image(&self, conversation_key: &str, image: RegisteredImage) -> String {
        let mut state = self.lock();
        state.next_image += 1;
        let image_id = format!("i{}{}", self.salt, state.next_image);
        state
            .images
            .insert(image_id.clone(), (conversation_key.to_string(), image));
        let mut held: Vec<(u64, String)> = state
            .images
            .iter()
            .filter(|(_, (conversation, _))| conversation == conversation_key)
            .filter_map(|(id, _)| {
                id.strip_prefix('i')
                    .and_then(|rest| rest.strip_prefix(self.salt.as_str()))
                    .and_then(|number| number.parse().ok())
                    .map(|number| (number, id.clone()))
            })
            .collect();
        if held.len() > MAX_IMAGES_PER_CONVERSATION {
            held.sort();
            let excess = held.len() - MAX_IMAGES_PER_CONVERSATION;
            for (_, id) in held.into_iter().take(excess) {
                state.images.remove(&id);
            }
        }
        image_id
    }

    /// An image this conversation was given, if it is still remembered.
    pub fn resolve_image(&self, conversation_key: &str, image_id: &str) -> Option<RegisteredImage> {
        let state = self.lock();
        let (conversation, image) = state.images.get(image_id)?;
        (conversation == conversation_key).then(|| image.clone())
    }

    /// Forget everything held for a conversation that has ended.
    pub fn end_conversation(&self, conversation_key: &str) {
        let mut state = self.lock();
        let ended: Vec<SessionKey> = state
            .sessions
            .keys()
            .filter(|key| key.conversation_key == conversation_key)
            .cloned()
            .collect();
        for key in ended {
            state.remove_session(&key);
        }
        // The count goes on across conversations, so one that later starts
        // under the same key never resolves an id issued before.
        state
            .images
            .retain(|_, (conversation, _)| conversation != conversation_key);
    }

    /// How many sessions are held, for tests of their lifetime.
    pub fn session_count(&self) -> usize {
        self.lock().sessions.len()
    }
}

fn session_element_id(number: u64) -> String {
    number.to_string()
}

/// The number an element id names: digits only, so `"389"` and nothing
/// like `"+389"` or `"389 "`.
fn parse_element_id(element_id: &str) -> Option<u64> {
    if element_id.is_empty() || !element_id.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    element_id.parse().ok()
}

struct Walk<'a> {
    session: &'a mut Session,
    next_number: &'a mut u64,
    seen: HashSet<u64>,
    diff: StateDiff,
}

impl Walk<'_> {
    /// Number one element and its descendants.
    ///
    /// `parent_role` and `index` place the element among its siblings, which
    /// is how the Apple menu is recognised: it is the first item of a menu
    /// bar, whatever language titles it, so every menu item beneath it is
    /// refused by position rather than by an English title. `hazard` is set
    /// beneath a refused item, so nothing under it is shown either.
    fn node(
        &mut self,
        element: &RawElement,
        parent_role: Option<&str>,
        index: usize,
        mut hazard: bool,
        in_apple_menu: bool,
    ) -> ObservedNode {
        let description = describe(element);
        let is_apple_menu = parent_role == Some("AXMenuBar")
            && index == 0
            && element.role.as_deref() == Some("AXMenuBarItem");
        hazard |= is_session_ending_item(element)
            || (in_apple_menu && element.role.as_deref() == Some("AXMenuItem"));
        let signature = description.signature();

        let number = match self.session.find(&element.handle) {
            Some(number) => {
                let entry = self
                    .session
                    .entries
                    .get_mut(&number)
                    .expect("found entries exist");
                // A known element that has turned into a session-ending item
                // is refused from now on; one that stopped being one is not
                // re-admitted, because its id was never shown.
                entry.refusing |= hazard;
                if !entry.refusing && !self.seen.contains(&number) {
                    let id = session_element_id(number);
                    if !entry.in_baseline {
                        self.diff.added.push(id);
                    } else if entry.signature != signature {
                        self.diff.changed.push(id);
                    }
                }
                entry.signature = signature;
                Some(number)
            }
            None => {
                let number = self.session.insert(
                    self.next_number,
                    element.handle.clone(),
                    signature,
                    hazard,
                );
                if let Some(number) = number {
                    if !hazard {
                        self.diff.added.push(session_element_id(number));
                    }
                }
                number
            }
        };
        if let Some(number) = number {
            self.seen.insert(number);
        }

        let children = element
            .children
            .iter()
            .enumerate()
            .map(|(child_index, child)| {
                self.node(
                    child,
                    element.role.as_deref(),
                    child_index,
                    hazard,
                    in_apple_menu || is_apple_menu,
                )
            })
            .collect();

        ObservedNode {
            element_id: number.map(|number| self.session.element_id(number)),
            description,
            hazard,
            children,
        }
    }
}

// The render module owns the grammar; re-exported here so a caller holding a
// session read can render it without naming both modules.
pub use render::{render_diff, render_state};
