//! Fixed receive-to-terminal budgets shared by handlers, health and the catalog.
//! Delivery means a written and flushed terminal frame, or connection failure.

use std::time::{Duration, Instant};

use crate::management;

pub const CONSENT_PARK_LIMIT_MS: u64 = 120_000;
pub const HANDOFF_DURATION_MS: u64 = 600_000;
pub const COMPUTER_MAX_PARK_MS: u64 = CONSENT_PARK_LIMIT_MS;
pub const BROWSER_MAX_PARK_MS: u64 = CONSENT_PARK_LIMIT_MS;

pub const TARGET_CHECK_MS: u64 = 2_000;
pub const CODE_IDENTITY_MS: u64 = 2_000;
pub const GRANT_LOOKUP_MS: u64 = 1_000;
pub const PREFLIGHT_MS: u64 = TARGET_CHECK_MS + CODE_IDENTITY_MS + GRANT_LOOKUP_MS;
pub const AX_STEP_MS: u64 = 1_000;
pub const AX_TREE_PHASE_MS: u64 = 1_000;
pub const AX_MENU_PHASE_MS: u64 = 1_000;
pub const COMPUTER_SETTLE_MS: u64 = 500;
pub const COMPUTER_OBSERVE_MS: u64 = 1_000;
pub const KEYS_OBSERVE_MS: u64 = 1_500;
pub const MOVE_OBSERVE_MS: u64 = 200;
pub const DRAG_OBSERVE_MS: u64 = 2_000;
pub const SCROLL_OBSERVE_MS: u64 = 500;
pub const FRONTING_READ_MS: u64 = 300;
pub const FRONTING_BRACKET_MS: u64 = 100;
pub const SYNTHETIC_POST_PHASE_MS: u64 = 5_000;
pub const CAPTURE_IMAGE_MS: u64 = 2_000;
pub const INVENTORY_MS: u64 = 2_000;
pub const OPEN_APP_LAUNCH_MS: u64 = 120_000;
pub const WAIT_MS: u64 = 30_000;
pub const RESOLUTION_LIMIT_MS: u64 = 2_000;
pub const MAX_ELEMENT_PRESSES: u64 = 8;

// A command has its own cap as well as the enclosing phase and call caps.
// Variable traversals share one phase deadline; no iteration renews it.
pub const CDP_STEP_MS: u64 = 5_000;
pub const NAVIGATION_SETTLE_MS: u64 = 30_000;
pub const FRAME_DISCOVERY_PHASE_MS: u64 = 30_000;
pub const FRAME_SNAPSHOT_PHASE_MS: u64 = 30_000;
pub const AX_CHILDREN_PHASE_MS: u64 = 30_000;
pub const DIALOG_DISMISS_PHASE_MS: u64 = 30_000;
pub const CLICK_CANDIDATES_PHASE_MS: u64 = 30_000;
pub const FRAME_POINT_PHASE_MS: u64 = 30_000;
pub const BROWSER_LAUNCH_MS: u64 = 30_000;
pub const TERMINATION_GRACE_MS: u64 = 5_000;
pub const EXIT_OBSERVATION_MS: u64 = 5_000;
pub const TEARDOWN_MS: u64 = TERMINATION_GRACE_MS + EXIT_OBSERVATION_MS;
pub const IMPORT_DISCOVERY_PHASE_MS: u64 = 60_000;
pub const IMPORT_TRANSFER_MS: u64 = 60_000;
pub const EXCLUSION_COMMAND_MS: u64 = 10_000;
pub const LOGIN_VERIFY_MS: u64 = 10_000;
pub const VAULT_DEPOSIT_MS: u64 = 15_000;

// One store operation reserves a write, possible compaction, and sync_all.
pub const RECORD_WRITE_MS: u64 = 2_000;
pub const RECORD_COMPACT_MS: u64 = 2_000;
pub const RECORD_SYNC_MS: u64 = 2_000;
pub const STORE_MS: u64 = RECORD_WRITE_MS + RECORD_COMPACT_MS + RECORD_SYNC_MS;
pub const CALL_RECORD_BEGIN_MS: u64 = RECORD_WRITE_MS + RECORD_COMPACT_MS + RECORD_SYNC_MS;
pub const CALL_RECORD_SETTLE_MS: u64 = RECORD_WRITE_MS + RECORD_COMPACT_MS + RECORD_SYNC_MS;
// Five keyboard releases (four modifiers and a key), plus a mouse release.
pub const SYNTHETIC_RELEASE_MS: u64 = 6 * AX_STEP_MS;
pub const CDP_RELEASE_MS: u64 = CDP_STEP_MS;
pub const RELEASE_BUDGET_MS: u64 = max(SYNTHETIC_RELEASE_MS, CDP_RELEASE_MS);
pub const BOUNDARY_SLACK_MS: u64 = 5_000;
pub const IN_FLIGHT_MARGIN_MS: u64 = 5_000;
// Each executing computer call holds two permits (work and release), so 8
// lets four calls on different applications run at once, as computer calls
// on different applications could before permits existed.
// The bound exists to cap the threads stuck applications can hold, not to
// serialize healthy ones; no budget or reply formula depends on it.
pub const MAX_BLOCKING_WORKERS_COMPUTER: usize = 8;
// A browser call likewise holds a work and a release permit from the moment it
// acquires its conversation's lane. Each conversation drives its own session,
// so before permits existed calls in different conversations ran in parallel;
// with two per call, 8 lets four conversations' calls run at once. The closing of a session in execution
// quarantine uses a control permit kept outside this pool.
pub const MAX_BLOCKING_WORKERS_BROWSER: usize = 8;
pub const MAX_CALL_RECORD_WORKERS: usize = 2;

pub const EGRESS_BUFFER: usize = 64;
// The floor is a contract for the local peer, not an assumed delivery rate.
// A slower peer or a backlog outside the channel fails at the reply deadline.
pub const EGRESS_MIN_BYTES_PER_S: u64 = 64 * 1024 * 1024;
pub const MAX_WIRE_FRAME_BYTES: u64 =
    4 + subc_protocol::HEADER_LEN as u64 + subc_protocol::MAX_FRAME_BODY_LEN as u64;
pub const EGRESS_FLUSH_MS: u64 = 1_000;
pub const EGRESS_SEND_MS: u64 = (2 * EGRESS_BUFFER as u64 * MAX_WIRE_FRAME_BYTES * 1_000)
    .div_ceil(EGRESS_MIN_BYTES_PER_S)
    + 2 * EGRESS_FLUSH_MS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Phase {
    pub name: &'static str,
    pub cap_ms: u64,
    pub count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActionBudget {
    pub action: &'static str,
    pub work_ms: u64,
    pub phases: &'static [Phase],
}

/// An absolute phase deadline, retained across all iterations of a loop.
/// Reusing this value cannot grant a fresh phase allowance to a later command.
pub struct PhaseDeadline {
    phase_end: Instant,
    call_end: Instant,
}

impl PhaseDeadline {
    pub fn new(start: Instant, phase_cap_ms: u64, call_end: Instant) -> Self {
        Self {
            phase_end: start + Duration::from_millis(phase_cap_ms),
            call_end,
        }
    }

    pub fn step_deadline(&self, now: Instant, step_cap_ms: u64) -> Instant {
        (now + Duration::from_millis(step_cap_ms))
            .min(self.phase_end)
            .min(self.call_end)
    }
}

macro_rules! budget {
    ($id:ident, $action:expr, [$(($phase:literal, $cap:expr, $count:expr)),+ $(,)?]) => {
        pub const $id: ActionBudget = ActionBudget {
            action: $action,
            work_ms: 0 $(+ $cap * $count)+,
            phases: &[$(Phase { name: $phase, cap_ms: $cap, count: $count }),+],
        };
    };
}

budget!(
    COMPUTER_READ_STATE,
    "read_state",
    [
        ("preflight", PREFLIGHT_MS, 1),
        ("focus", AX_STEP_MS, 1),
        ("tree", AX_TREE_PHASE_MS, 1),
        ("menubar", AX_MENU_PHASE_MS, 1),
        ("fronting_read", FRONTING_READ_MS, 1),
        ("settle", COMPUTER_SETTLE_MS, 1),
        ("image", CAPTURE_IMAGE_MS, 1),
        ("journal", STORE_MS, 1),
    ]
);
budget!(
    COMPUTER_WAIT,
    "wait",
    [
        ("preflight", PREFLIGHT_MS, 1),
        ("poll", WAIT_MS, 1),
        ("final_read", AX_STEP_MS, 1),
        ("journal", STORE_MS, 1),
    ]
);
budget!(
    COMPUTER_OPEN_APP,
    "open_app",
    [
        ("preflight", PREFLIGHT_MS, 1),
        ("inventory", INVENTORY_MS, 1),
        ("url_scheme", TARGET_CHECK_MS, 1),
        ("launch", OPEN_APP_LAUNCH_MS, 1),
        ("ready_read", AX_STEP_MS, 1),
        ("journal", STORE_MS, 2),
    ]
);
budget!(
    COMPUTER_LIST_APPS,
    "list_apps",
    [
        ("running_apps", AX_STEP_MS, 1),
        ("installed_apps", INVENTORY_MS, 1),
        ("journal", STORE_MS, 1),
    ]
);
budget!(
    COMPUTER_PRESS_ELEMENT,
    "press_element",
    [
        ("preflight", PREFLIGHT_MS, 1),
        ("press", AX_STEP_MS, MAX_ELEMENT_PRESSES),
        ("settle", COMPUTER_SETTLE_MS, MAX_ELEMENT_PRESSES),
        ("observe", COMPUTER_OBSERVE_MS, MAX_ELEMENT_PRESSES),
        ("journal", STORE_MS, MAX_ELEMENT_PRESSES),
    ]
);
budget!(
    COMPUTER_PRESS_POINT,
    "press_point",
    [
        ("preflight", PREFLIGHT_MS, 1),
        ("hit_test", AX_STEP_MS, 1),
        ("press", AX_STEP_MS, 1),
        ("settle", COMPUTER_SETTLE_MS, 1),
        ("observe", COMPUTER_OBSERVE_MS, 1),
        ("journal", STORE_MS, 1),
    ]
);
budget!(
    COMPUTER_WRITE_TEXT,
    "write_text",
    [
        ("preflight", PREFLIGHT_MS, 1),
        ("target", AX_STEP_MS, 1),
        ("write", AX_STEP_MS, 1),
        ("read_back", AX_STEP_MS, 1),
        ("settle", COMPUTER_SETTLE_MS, 1),
        ("observe", COMPUTER_OBSERVE_MS, 1),
        ("journal", STORE_MS, 1),
    ]
);
budget!(
    COMPUTER_TYPE,
    "type",
    [
        ("preflight", PREFLIGHT_MS, 1),
        ("security", AX_STEP_MS, 1),
        ("fronting", FRONTING_BRACKET_MS, 1),
        ("focus", AX_STEP_MS, 1),
        ("post", SYNTHETIC_POST_PHASE_MS, 1),
        ("read_back", AX_STEP_MS, 1),
        ("settle", COMPUTER_SETTLE_MS, 1),
        ("observe", COMPUTER_OBSERVE_MS, 1),
        ("journal", STORE_MS, 2),
    ]
);
budget!(
    COMPUTER_KEYS,
    "keys",
    [
        ("preflight", PREFLIGHT_MS, 1),
        ("fronting", FRONTING_BRACKET_MS, 1),
        ("focus", AX_STEP_MS, 1),
        ("post", SYNTHETIC_POST_PHASE_MS, 1),
        ("settle", COMPUTER_SETTLE_MS, 1),
        ("observe", KEYS_OBSERVE_MS, 1),
        ("journal", STORE_MS, 2),
    ]
);
budget!(
    COMPUTER_TAKEOVER_MOVE,
    "takeover_move",
    [
        ("preflight", PREFLIGHT_MS, 1),
        ("placement", AX_STEP_MS, 2),
        ("focus", AX_STEP_MS, 1),
        ("post", SYNTHETIC_POST_PHASE_MS, 1),
        ("observe", MOVE_OBSERVE_MS, 1),
        ("journal", STORE_MS, 1),
    ]
);
budget!(
    COMPUTER_TAKEOVER_DRAG,
    "takeover_drag",
    [
        ("preflight", PREFLIGHT_MS, 1),
        ("placement", AX_STEP_MS, 2),
        ("focus", AX_STEP_MS, 1),
        ("post", SYNTHETIC_POST_PHASE_MS, 1),
        ("observe", DRAG_OBSERVE_MS, 1),
        ("journal", STORE_MS, 1),
    ]
);
budget!(
    COMPUTER_TAKEOVER_SCROLL,
    "takeover_scroll",
    [
        ("preflight", PREFLIGHT_MS, 1),
        ("placement", AX_STEP_MS, 2),
        ("focus", AX_STEP_MS, 1),
        ("post", SYNTHETIC_POST_PHASE_MS, 1),
        ("observe", SCROLL_OBSERVE_MS, 1),
        ("journal", STORE_MS, 1),
    ]
);
pub const COMPUTER_ACTIONS: [ActionBudget; 12] = [
    COMPUTER_READ_STATE,
    COMPUTER_WAIT,
    COMPUTER_OPEN_APP,
    COMPUTER_LIST_APPS,
    COMPUTER_PRESS_ELEMENT,
    COMPUTER_PRESS_POINT,
    COMPUTER_WRITE_TEXT,
    COMPUTER_TYPE,
    COMPUTER_KEYS,
    COMPUTER_TAKEOVER_MOVE,
    COMPUTER_TAKEOVER_DRAG,
    COMPUTER_TAKEOVER_SCROLL,
];

budget!(
    BROWSER_LAUNCH,
    "launch",
    [
        ("preflight", PREFLIGHT_MS, 1),
        ("launch", BROWSER_LAUNCH_MS, 1),
        ("journal", STORE_MS, 1),
    ]
);
budget!(BROWSER_STATUS, "status", [("metadata", GRANT_LOOKUP_MS, 1)]);
// open_tab and claim_tab ask the person's Chrome through the extension
// bridge: one bridge turn (queue wait then reply) for the tab request. The
// other user-target actions are served from the own-browser budgets above
// until the user target adopts the call envelope as its own follow-up.
pub const BRIDGE_TURN_MS: u64 = crate::user_browser_bridge::QUEUE_DEADLINE.as_millis() as u64
    + crate::user_browser_bridge::REPLY_DEADLINE.as_millis() as u64;
budget!(
    BROWSER_OPEN_TAB,
    "open_tab",
    [
        ("preflight", PREFLIGHT_MS, 1),
        ("bridge_turn", BRIDGE_TURN_MS, 1),
        ("journal", STORE_MS, 1),
    ]
);
budget!(
    BROWSER_CLAIM_TAB,
    "claim_tab",
    [
        ("preflight", PREFLIGHT_MS, 1),
        ("bridge_turn", BRIDGE_TURN_MS, 1),
        ("journal", STORE_MS, 1),
    ]
);
budget!(
    BROWSER_CLOSE,
    "close",
    [
        ("preflight", PREFLIGHT_MS, 1),
        ("teardown", TEARDOWN_MS, 1),
        ("journal", STORE_MS, 1),
    ]
);
// Cold attachment: deny downloads, create target, attach to target.
pub const ATTACHMENT_MS: u64 = 3 * CDP_STEP_MS;
// committed_document: Page.getNavigationHistory and Page.getFrameTree.
pub const COMMITTED_DOCUMENT_MS: u64 = 2 * CDP_STEP_MS;
budget!(
    BROWSER_SNAPSHOT,
    "snapshot",
    [
        ("preflight", PREFLIGHT_MS, 1),
        ("attachment", CDP_STEP_MS, 3),
        ("committed_document", CDP_STEP_MS, 2),
        ("prepare_frame", FRAME_DISCOVERY_PHASE_MS, 1),
        ("Accessibility.enable", CDP_STEP_MS, 1),
        // An element-directed snapshot uses getPartialAXTree instead of
        // getRootAXNode. Both root lookups share this one CDP setup allowance.
        ("Accessibility.getRootAXNode", CDP_STEP_MS, 1),
        ("AX_children", AX_CHILDREN_PHASE_MS, 1),
        ("DOM.enable", CDP_STEP_MS, 1),
        ("DOM.getFlattenedDocument", CDP_STEP_MS, 1),
        ("DOM.getDocument", CDP_STEP_MS, 1),
        ("DOM.getOuterHTML", CDP_STEP_MS, 1),
        ("frame_snapshots", FRAME_SNAPSHOT_PHASE_MS, 1),
        ("journal", STORE_MS, 1),
    ]
);
budget!(
    BROWSER_NAVIGATE_ONLY,
    "navigate",
    [
        ("preflight", PREFLIGHT_MS, 1),
        ("attachment", CDP_STEP_MS, 3),
        ("Page.enable", CDP_STEP_MS, 1),
        ("Network.enable", CDP_STEP_MS, 1),
        ("Page.navigate", CDP_STEP_MS, 1),
        ("settle", NAVIGATION_SETTLE_MS, 1),
        ("dialogs", DIALOG_DISMISS_PHASE_MS, 1),
        ("journal", STORE_MS, 1),
    ]
);
// browser_use permits navigate with read_page=true, so its maximum includes
// both the navigation and the snapshot that reads the resulting page.
budget!(
    BROWSER_NAVIGATE,
    "navigate",
    [
        ("navigation", BROWSER_NAVIGATE_ONLY.work_ms, 1),
        ("read_page", BROWSER_SNAPSHOT.work_ms, 1),
    ]
);
budget!(
    BROWSER_SCREENSHOT,
    "screenshot",
    [
        ("preflight", PREFLIGHT_MS, 1),
        ("attachment", CDP_STEP_MS, 3),
        ("committed_document", CDP_STEP_MS, 2),
        ("Page.getLayoutMetrics", CDP_STEP_MS, 2),
        ("Runtime.evaluate", CDP_STEP_MS, 2),
        ("Page.captureScreenshot", CDP_STEP_MS, 1),
        ("journal", STORE_MS, 1),
    ]
);
budget!(
    BROWSER_CLICK,
    "click",
    [
        ("preflight", PREFLIGHT_MS, 1),
        ("attachment", CDP_STEP_MS, 3),
        ("committed_document", CDP_STEP_MS, 2),
        ("prepare_frame", FRAME_DISCOVERY_PHASE_MS, 1),
        ("classification_DOM.enable", CDP_STEP_MS, 1),
        ("classification_DOM.getFlattenedDocument", CDP_STEP_MS, 1),
        ("label_candidates", CLICK_CANDIDATES_PHASE_MS, 1),
        ("Page.getLayoutMetrics", CDP_STEP_MS, 1),
        ("DOM.getNodeForLocation", CDP_STEP_MS, 1),
        ("DOM.describeNode", CDP_STEP_MS, 1),
        ("Accessibility.getPartialAXTree", CDP_STEP_MS, 1),
        ("recheck_DOM.enable", CDP_STEP_MS, 1),
        ("recheck_DOM.getFlattenedDocument", CDP_STEP_MS, 1),
        ("Page.enable", CDP_STEP_MS, 1),
        ("Network.enable", CDP_STEP_MS, 1),
        ("Input.mousePressed", CDP_STEP_MS, 1),
        ("Input.mouseReleased", CDP_STEP_MS, 1),
        ("settle", NAVIGATION_SETTLE_MS, 1),
        ("dialogs", DIALOG_DISMISS_PHASE_MS, 1),
        ("journal", STORE_MS, 1),
    ]
);
// Each of the two typing observations reads the document, resolves the
// frame, reads DOM classification and obtains content quads. Replacement
// is the longer tail: select, re-observe, Backspace, verify empty, insert.
budget!(
    BROWSER_TYPE,
    "type",
    [
        ("preflight", PREFLIGHT_MS, 1),
        ("attachment", CDP_STEP_MS, 3),
        ("committed_document", CDP_STEP_MS, 4),
        ("prepare_frame", FRAME_DISCOVERY_PHASE_MS, 2),
        ("DOM.enable", CDP_STEP_MS, 2),
        ("DOM.getFlattenedDocument", CDP_STEP_MS, 2),
        ("DOM.getContentQuads", CDP_STEP_MS, 2),
        ("Emulation.setFocusEmulationEnabled", CDP_STEP_MS, 1),
        ("DOM.focus", CDP_STEP_MS, 1),
        ("Runtime.enable", CDP_STEP_MS, 1),
        ("DOM.resolveNode", CDP_STEP_MS, 2),
        ("Runtime.select", CDP_STEP_MS, 1),
        ("Runtime.focus_check", CDP_STEP_MS, 1),
        ("Input.BackspaceDown", CDP_STEP_MS, 1),
        ("Input.BackspaceUp", CDP_STEP_MS, 1),
        ("Runtime.empty_check", CDP_STEP_MS, 1),
        ("Input.insertText", CDP_STEP_MS, 1),
        ("journal", STORE_MS, 2),
    ]
);
// Coordinate classification runs twice (admission and dispatch recheck).
budget!(
    BROWSER_CLICK_POINT,
    "click_point",
    [
        ("preflight", PREFLIGHT_MS, 1),
        ("attachment", CDP_STEP_MS, 3),
        ("committed_document", CDP_STEP_MS, 2),
        ("classification_Page.getLayoutMetrics", CDP_STEP_MS, 2),
        ("classification_DOM.getNodeForLocation", CDP_STEP_MS, 2),
        ("frame_point", FRAME_POINT_PHASE_MS, 2),
        ("classification_DOM.enable", CDP_STEP_MS, 2),
        ("classification_DOM.getFlattenedDocument", CDP_STEP_MS, 2),
        ("Page.getLayoutMetrics", CDP_STEP_MS, 1),
        ("Page.enable", CDP_STEP_MS, 1),
        ("Network.enable", CDP_STEP_MS, 1),
        ("Input.mousePressed", CDP_STEP_MS, 1),
        ("Input.mouseReleased", CDP_STEP_MS, 1),
        ("settle", NAVIGATION_SETTLE_MS, 1),
        ("dialogs", DIALOG_DISMISS_PHASE_MS, 1),
        ("journal", STORE_MS, 1),
    ]
);
pub const BROWSER_ACTIONS: [ActionBudget; 11] = [
    BROWSER_LAUNCH,
    BROWSER_OPEN_TAB,
    BROWSER_CLAIM_TAB,
    BROWSER_STATUS,
    BROWSER_CLOSE,
    BROWSER_NAVIGATE,
    BROWSER_SNAPSHOT,
    BROWSER_SCREENSHOT,
    BROWSER_CLICK,
    BROWSER_TYPE,
    BROWSER_CLICK_POINT,
];

budget!(
    MANAGEMENT_WOULD_ASK,
    management::WOULD_ASK,
    [("grants", GRANT_LOOKUP_MS, 1), ("journal", STORE_MS, 1),]
);
budget!(
    MANAGEMENT_OPEN_TARGET,
    management::OPEN_TARGET,
    [
        ("resolution", RESOLUTION_LIMIT_MS, 1),
        ("preflight", PREFLIGHT_MS, 1),
        ("revalidate", CODE_IDENTITY_MS, 1),
        ("journal", STORE_MS, 1),
    ]
);
budget!(
    MANAGEMENT_LIST_APP_GRANTS,
    management::LIST_APP_GRANTS,
    [("store", STORE_MS, 1)]
);
budget!(
    MANAGEMENT_REVOKE_APP_GRANT,
    management::REVOKE_APP_GRANT,
    [("store", STORE_MS, 1), ("journal", STORE_MS, 1),]
);
budget!(
    MANAGEMENT_OPEN_GRANT,
    management::OPEN_GRANT,
    [
        ("preflight", PREFLIGHT_MS, 1),
        ("store", STORE_MS, 1),
        ("journal", STORE_MS, 1),
    ]
);
budget!(
    MANAGEMENT_PRESENT,
    management::PRESENT,
    [
        ("preflight", PREFLIGHT_MS, 1),
        ("attachment", CDP_STEP_MS, 3),
        ("Page.getNavigationHistory", CDP_STEP_MS, 1),
        ("bring_to_front", CDP_STEP_MS, 1),
        ("Target.activateTarget", CDP_STEP_MS, 1),
        ("Network.getCookies", CDP_STEP_MS, 1),
        ("store", STORE_MS, 1),
        ("journal", STORE_MS, 1),
    ]
);
budget!(
    MANAGEMENT_RESUME,
    management::RESUME,
    [
        ("metadata", GRANT_LOOKUP_MS, 1),
        ("store", STORE_MS, 1),
        ("journal", STORE_MS, 1),
    ]
);
budget!(
    MANAGEMENT_IMPORT_LOGIN,
    management::IMPORT_LOGIN,
    [
        ("preflight", PREFLIGHT_MS, 1),
        ("discovery", IMPORT_DISCOVERY_PHASE_MS, 1),
        ("attachment", CDP_STEP_MS, 3),
        ("idle_URL", CDP_STEP_MS, 1),
        ("idle_close", TEARDOWN_MS, 1),
        ("transfer", IMPORT_TRANSFER_MS, 1),
        ("relaunch", BROWSER_LAUNCH_MS, 1),
        ("restore_navigation", BROWSER_NAVIGATE_ONLY.work_ms, 1),
        ("journal", STORE_MS, 1),
    ]
);
budget!(
    MANAGEMENT_CAPTURE_LOGIN,
    management::CAPTURE_LOGIN,
    [
        ("preflight", PREFLIGHT_MS, 1),
        ("exclusion", EXCLUSION_COMMAND_MS, 3),
        ("launch", BROWSER_LAUNCH_MS, 1),
        ("login_navigation", BROWSER_NAVIGATE_ONLY.work_ms, 1),
        ("bring_to_front", CDP_STEP_MS, 1),
        ("Target.activateTarget", CDP_STEP_MS, 1),
        ("opening_cookies", CDP_STEP_MS, 1),
        ("verify", LOGIN_VERIFY_MS, 1),
        ("cookie_header", CDP_STEP_MS, 1),
        ("cleanup", TEARDOWN_MS, 1),
        ("deposit", VAULT_DEPOSIT_MS, 1),
        ("journal", STORE_MS, 1),
    ]
);
budget!(
    MANAGEMENT_REBIND_PROFILE_ROOT,
    management::REBIND_PROFILE_ROOT,
    [
        ("preflight", PREFLIGHT_MS, 1),
        ("preview", STORE_MS, 1),
        ("journal", STORE_MS, 1),
    ]
);
budget!(
    MANAGEMENT_CLEAR_LAUNCH_RECOVERY,
    management::CLEAR_LAUNCH_RECOVERY,
    [
        ("preflight", PREFLIGHT_MS, 1),
        ("preview", STORE_MS, 1),
        ("journal", STORE_MS, 1),
    ]
);
budget!(
    MANAGEMENT_REVOKE_ACCESS,
    management::REVOKE_ACCESS,
    [("store", STORE_MS, 1), ("journal", STORE_MS, 1),]
);
budget!(
    MANAGEMENT_REVOKE_GRANT,
    management::REVOKE_GRANT,
    [("store", STORE_MS, 1), ("journal", STORE_MS, 1),]
);
budget!(
    MANAGEMENT_LIST_GRANTS,
    management::LIST_GRANTS,
    [("store", STORE_MS, 2)]
);
pub const MANAGEMENT_ACTIONS: [ActionBudget; 14] = [
    MANAGEMENT_WOULD_ASK,
    MANAGEMENT_OPEN_TARGET,
    MANAGEMENT_LIST_APP_GRANTS,
    MANAGEMENT_REVOKE_APP_GRANT,
    MANAGEMENT_OPEN_GRANT,
    MANAGEMENT_IMPORT_LOGIN,
    MANAGEMENT_PRESENT,
    MANAGEMENT_RESUME,
    MANAGEMENT_REBIND_PROFILE_ROOT,
    MANAGEMENT_CAPTURE_LOGIN,
    MANAGEMENT_CLEAR_LAUNCH_RECOVERY,
    MANAGEMENT_REVOKE_ACCESS,
    MANAGEMENT_REVOKE_GRANT,
    MANAGEMENT_LIST_GRANTS,
];
const FLAT_MANAGEMENT_ACTIONS: [ActionBudget; 6] = [
    MANAGEMENT_OPEN_GRANT,
    MANAGEMENT_PRESENT,
    MANAGEMENT_RESUME,
    MANAGEMENT_IMPORT_LOGIN,
    MANAGEMENT_CAPTURE_LOGIN,
    MANAGEMENT_REVOKE_ACCESS,
];

pub const fn max(a: u64, b: u64) -> u64 {
    if a > b {
        a
    } else {
        b
    }
}

const fn max_work(actions: &[ActionBudget]) -> u64 {
    let mut result = 0;
    let mut i = 0;
    while i < actions.len() {
        result = max(result, actions[i].work_ms);
        i += 1;
    }
    result
}

fn lookup(actions: &'static [ActionBudget], action: &str) -> Option<&'static ActionBudget> {
    actions.iter().find(|entry| entry.action == action)
}

pub fn computer(action: &str) -> Option<&'static ActionBudget> {
    lookup(&COMPUTER_ACTIONS, action)
}

pub fn browser(action: &str) -> Option<&'static ActionBudget> {
    lookup(&BROWSER_ACTIONS, action)
}

pub fn management(method: &str) -> Option<&'static ActionBudget> {
    lookup(&MANAGEMENT_ACTIONS, method)
}

pub const COMPUTER_MAX_WORK_MS: u64 = max_work(&COMPUTER_ACTIONS);
pub const BROWSER_MAX_WORK_MS: u64 = max(
    max_work(&BROWSER_ACTIONS),
    max_work(&FLAT_MANAGEMENT_ACTIONS),
);
pub const COMPUTER_QUEUE_WAIT_LIMIT_MS: u64 = CONSENT_PARK_LIMIT_MS
    + COMPUTER_MAX_WORK_MS
    + RELEASE_BUDGET_MS
    + BOUNDARY_SLACK_MS
    + RESOLUTION_LIMIT_MS;
pub const BROWSER_QUEUE_WAIT_LIMIT_MS: u64 =
    CONSENT_PARK_LIMIT_MS + BROWSER_MAX_WORK_MS + RELEASE_BUDGET_MS + BOUNDARY_SLACK_MS;
pub const TERMINAL_SUFFIX_MS: u64 = RELEASE_BUDGET_MS + CALL_RECORD_SETTLE_MS + EGRESS_SEND_MS;

const fn reply_max_ms(queue_ms: u64, park_ms: u64, work_ms: u64) -> u64 {
    CALL_RECORD_BEGIN_MS + queue_ms + park_ms + work_ms + TERMINAL_SUFFIX_MS
}

// Both tool sums are admission + queue + park + work + release + settle + egress.
// computer_use: 6,000 + 275,000 + 120,000 + 142,000 + 6,000 + 6,000
// + 130,001 = 685,001 ms. open_app's 120,000-ms launch ceiling dominates
// work and queue. Egress reserves 130,001 ms to write the current writer batch
// plus the queued channel buffer at EGRESS_MIN_BYTES_PER_S, and flush twice.
pub const COMPUTER_REPLY_MAX_MS: u64 = reply_max_ms(
    COMPUTER_QUEUE_WAIT_LIMIT_MS,
    COMPUTER_MAX_PARK_MS,
    COMPUTER_MAX_WORK_MS,
);
// browser_use: 6,000 + 423,000 + 120,000 + 292,000 + 6,000 + 6,000
// + 130,001 = 983,001 ms. Only waiting for the person's consent-card answer
// parks the call. The sign-in window returns a pending reply; a later result
// reports how sign-in ended. EGRESS_SEND_MS reserves 130,001 ms to send the
// active reply batch and queued channel buffer at EGRESS_MIN_BYTES_PER_S,
// including two flushes.
pub const BROWSER_REPLY_MAX_MS: u64 = reply_max_ms(
    BROWSER_QUEUE_WAIT_LIMIT_MS,
    BROWSER_MAX_PARK_MS,
    BROWSER_MAX_WORK_MS,
);
pub const COMPUTER_ENVELOPE_MS: u64 = COMPUTER_REPLY_MAX_MS - TERMINAL_SUFFIX_MS;
pub const BROWSER_ENVELOPE_MS: u64 = BROWSER_REPLY_MAX_MS - TERMINAL_SUFFIX_MS;
pub const MAX_ACTION_WORK_MS: u64 = max(
    max(COMPUTER_MAX_WORK_MS, BROWSER_MAX_WORK_MS),
    max_work(&MANAGEMENT_ACTIONS),
);
// The in-flight gauge excludes queue waits and parks on the person. Reserve
// active work and bounded release, then a scheduling margin; reply delivery
// allowances must not delay detecting an action whose work has stopped.
pub const IN_FLIGHT_AGE_STALE_MS: u64 =
    MAX_ACTION_WORK_MS + RELEASE_BUDGET_MS + IN_FLIGHT_MARGIN_MS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManagementLimits {
    pub method: &'static str,
    pub work_ms: u64,
    pub queue_wait_ms: u64,
    pub park_ms: u64,
    pub envelope_ms: u64,
    pub reply_max_ms: u64,
}

const fn management_limits(
    budget: ActionBudget,
    queue_wait_ms: u64,
    park_ms: u64,
) -> ManagementLimits {
    let reply_max_ms = reply_max_ms(queue_wait_ms, park_ms, budget.work_ms);
    ManagementLimits {
        method: budget.action,
        work_ms: budget.work_ms,
        queue_wait_ms,
        park_ms,
        envelope_ms: reply_max_ms - TERMINAL_SUFFIX_MS,
        reply_max_ms,
    }
}

// Only browser.* Management methods wait behind earlier browser calls in
// the same conversation. Park allowances cover waiting for the person to
// answer consent or complete sign-in. OPEN_GRANT, REBIND_PROFILE_ROOT and
// CLEAR_LAUNCH_RECOVERY ask on spawned tasks after the Management reply,
// so those replies need no park allowance.
pub const MANAGEMENT_LIMITS: [ManagementLimits; 14] = [
    management_limits(MANAGEMENT_WOULD_ASK, 0, 0),
    management_limits(MANAGEMENT_OPEN_TARGET, 0, CONSENT_PARK_LIMIT_MS),
    management_limits(MANAGEMENT_LIST_APP_GRANTS, 0, 0),
    management_limits(MANAGEMENT_REVOKE_APP_GRANT, 0, 0),
    management_limits(MANAGEMENT_OPEN_GRANT, BROWSER_QUEUE_WAIT_LIMIT_MS, 0),
    management_limits(
        MANAGEMENT_IMPORT_LOGIN,
        BROWSER_QUEUE_WAIT_LIMIT_MS,
        CONSENT_PARK_LIMIT_MS,
    ),
    management_limits(MANAGEMENT_PRESENT, BROWSER_QUEUE_WAIT_LIMIT_MS, 0),
    management_limits(MANAGEMENT_RESUME, BROWSER_QUEUE_WAIT_LIMIT_MS, 0),
    management_limits(
        MANAGEMENT_REBIND_PROFILE_ROOT,
        BROWSER_QUEUE_WAIT_LIMIT_MS,
        0,
    ),
    management_limits(
        MANAGEMENT_CAPTURE_LOGIN,
        BROWSER_QUEUE_WAIT_LIMIT_MS,
        BROWSER_MAX_PARK_MS,
    ),
    management_limits(
        MANAGEMENT_CLEAR_LAUNCH_RECOVERY,
        BROWSER_QUEUE_WAIT_LIMIT_MS,
        0,
    ),
    management_limits(MANAGEMENT_REVOKE_ACCESS, BROWSER_QUEUE_WAIT_LIMIT_MS, 0),
    management_limits(MANAGEMENT_REVOKE_GRANT, BROWSER_QUEUE_WAIT_LIMIT_MS, 0),
    management_limits(MANAGEMENT_LIST_GRANTS, 0, 0),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_budget_is_the_const_sum_of_its_phases() {
        for entry in COMPUTER_ACTIONS
            .iter()
            .chain(&BROWSER_ACTIONS)
            .chain(&MANAGEMENT_ACTIONS)
            .chain([&BROWSER_NAVIGATE_ONLY])
        {
            assert!(!entry.phases.is_empty(), "{}", entry.action);
            assert!(entry
                .phases
                .iter()
                .all(|phase| phase.cap_ms > 0 && phase.count > 0));
            assert_eq!(
                entry.work_ms,
                entry
                    .phases
                    .iter()
                    .map(|phase| phase.cap_ms * phase.count)
                    .sum::<u64>(),
                "{}",
                entry.action
            );
        }
    }

    #[test]
    fn computer_phase_accounting_matches_each_path() {
        let expected = [
            (
                COMPUTER_READ_STATE,
                PREFLIGHT_MS
                    + 2 * AX_STEP_MS
                    + AX_MENU_PHASE_MS
                    + FRONTING_READ_MS
                    + COMPUTER_SETTLE_MS
                    + CAPTURE_IMAGE_MS
                    + STORE_MS,
            ),
            (
                COMPUTER_WAIT,
                PREFLIGHT_MS + WAIT_MS + AX_STEP_MS + STORE_MS,
            ),
            (
                COMPUTER_OPEN_APP,
                PREFLIGHT_MS
                    + INVENTORY_MS
                    + TARGET_CHECK_MS
                    + OPEN_APP_LAUNCH_MS
                    + AX_STEP_MS
                    + 2 * STORE_MS,
            ),
            (COMPUTER_LIST_APPS, AX_STEP_MS + INVENTORY_MS + STORE_MS),
            (
                COMPUTER_PRESS_ELEMENT,
                PREFLIGHT_MS
                    + MAX_ELEMENT_PRESSES
                        * (AX_STEP_MS + COMPUTER_SETTLE_MS + COMPUTER_OBSERVE_MS + STORE_MS),
            ),
            (
                COMPUTER_PRESS_POINT,
                PREFLIGHT_MS + 2 * AX_STEP_MS + COMPUTER_SETTLE_MS + COMPUTER_OBSERVE_MS + STORE_MS,
            ),
            (
                COMPUTER_WRITE_TEXT,
                PREFLIGHT_MS + 3 * AX_STEP_MS + COMPUTER_SETTLE_MS + COMPUTER_OBSERVE_MS + STORE_MS,
            ),
            (
                COMPUTER_TYPE,
                PREFLIGHT_MS
                    + 3 * AX_STEP_MS
                    + FRONTING_BRACKET_MS
                    + SYNTHETIC_POST_PHASE_MS
                    + COMPUTER_SETTLE_MS
                    + COMPUTER_OBSERVE_MS
                    + 2 * STORE_MS,
            ),
            (
                COMPUTER_KEYS,
                PREFLIGHT_MS
                    + FRONTING_BRACKET_MS
                    + AX_STEP_MS
                    + SYNTHETIC_POST_PHASE_MS
                    + COMPUTER_SETTLE_MS
                    + 1_500
                    + 2 * STORE_MS,
            ),
            (
                COMPUTER_TAKEOVER_MOVE,
                PREFLIGHT_MS + 3 * AX_STEP_MS + SYNTHETIC_POST_PHASE_MS + 200 + STORE_MS,
            ),
            (
                COMPUTER_TAKEOVER_DRAG,
                PREFLIGHT_MS + 3 * AX_STEP_MS + SYNTHETIC_POST_PHASE_MS + 2_000 + STORE_MS,
            ),
            (
                COMPUTER_TAKEOVER_SCROLL,
                PREFLIGHT_MS + 3 * AX_STEP_MS + SYNTHETIC_POST_PHASE_MS + 500 + STORE_MS,
            ),
        ];
        assert_eq!(expected.len(), COMPUTER_ACTIONS.len());
        for (budget, total) in expected {
            assert_eq!(budget.work_ms, total, "{}", budget.action);
        }
    }

    #[test]
    fn browser_phase_accounting_includes_helpers_and_read_page() {
        let expected = [
            (BROWSER_LAUNCH, PREFLIGHT_MS + BROWSER_LAUNCH_MS + STORE_MS),
            (BROWSER_OPEN_TAB, PREFLIGHT_MS + 60_000 + STORE_MS),
            (BROWSER_CLAIM_TAB, PREFLIGHT_MS + 60_000 + STORE_MS),
            (BROWSER_STATUS, GRANT_LOOKUP_MS),
            (BROWSER_CLOSE, PREFLIGHT_MS + TEARDOWN_MS + STORE_MS),
            (
                BROWSER_NAVIGATE_ONLY,
                PREFLIGHT_MS
                    + ATTACHMENT_MS
                    + 3 * CDP_STEP_MS
                    + NAVIGATION_SETTLE_MS
                    + DIALOG_DISMISS_PHASE_MS
                    + STORE_MS,
            ),
            (
                BROWSER_NAVIGATE,
                BROWSER_NAVIGATE_ONLY.work_ms + BROWSER_SNAPSHOT.work_ms,
            ),
            (
                BROWSER_SNAPSHOT,
                PREFLIGHT_MS
                    + ATTACHMENT_MS
                    + COMMITTED_DOCUMENT_MS
                    + FRAME_DISCOVERY_PHASE_MS
                    + 6 * CDP_STEP_MS
                    + AX_CHILDREN_PHASE_MS
                    + FRAME_SNAPSHOT_PHASE_MS
                    + STORE_MS,
            ),
            (
                BROWSER_SCREENSHOT,
                PREFLIGHT_MS + ATTACHMENT_MS + COMMITTED_DOCUMENT_MS + 5 * CDP_STEP_MS + STORE_MS,
            ),
            (
                BROWSER_CLICK,
                PREFLIGHT_MS
                    + ATTACHMENT_MS
                    + COMMITTED_DOCUMENT_MS
                    + FRAME_DISCOVERY_PHASE_MS
                    + 12 * CDP_STEP_MS
                    + CLICK_CANDIDATES_PHASE_MS
                    + NAVIGATION_SETTLE_MS
                    + DIALOG_DISMISS_PHASE_MS
                    + STORE_MS,
            ),
            (
                BROWSER_TYPE,
                PREFLIGHT_MS
                    + ATTACHMENT_MS
                    + 21 * CDP_STEP_MS
                    + 2 * FRAME_DISCOVERY_PHASE_MS
                    + 2 * STORE_MS,
            ),
            (
                BROWSER_CLICK_POINT,
                PREFLIGHT_MS
                    + ATTACHMENT_MS
                    + COMMITTED_DOCUMENT_MS
                    + 13 * CDP_STEP_MS
                    + 2 * FRAME_POINT_PHASE_MS
                    + NAVIGATION_SETTLE_MS
                    + DIALOG_DISMISS_PHASE_MS
                    + STORE_MS,
            ),
        ];
        assert_eq!(expected.len(), BROWSER_ACTIONS.len() + 1);
        for (budget, total) in expected {
            assert_eq!(budget.work_ms, total, "{}", budget.action);
        }
        assert_eq!(
            BROWSER_CLICK
                .phases
                .iter()
                .find(|phase| phase.name == "label_candidates")
                .unwrap()
                .cap_ms,
            CLICK_CANDIDATES_PHASE_MS
        );
    }

    #[test]
    fn management_phase_accounting_matches_each_path() {
        let expected = [
            (MANAGEMENT_WOULD_ASK, GRANT_LOOKUP_MS + STORE_MS),
            (
                MANAGEMENT_OPEN_TARGET,
                RESOLUTION_LIMIT_MS + PREFLIGHT_MS + CODE_IDENTITY_MS + STORE_MS,
            ),
            (MANAGEMENT_LIST_APP_GRANTS, STORE_MS),
            (MANAGEMENT_REVOKE_APP_GRANT, 2 * STORE_MS),
            (MANAGEMENT_OPEN_GRANT, PREFLIGHT_MS + 2 * STORE_MS),
            (
                MANAGEMENT_PRESENT,
                PREFLIGHT_MS + ATTACHMENT_MS + 4 * CDP_STEP_MS + 2 * STORE_MS,
            ),
            (MANAGEMENT_RESUME, GRANT_LOOKUP_MS + 2 * STORE_MS),
            (
                MANAGEMENT_IMPORT_LOGIN,
                PREFLIGHT_MS
                    + IMPORT_DISCOVERY_PHASE_MS
                    + ATTACHMENT_MS
                    + CDP_STEP_MS
                    + TEARDOWN_MS
                    + IMPORT_TRANSFER_MS
                    + BROWSER_LAUNCH_MS
                    + BROWSER_NAVIGATE_ONLY.work_ms
                    + STORE_MS,
            ),
            (
                MANAGEMENT_CAPTURE_LOGIN,
                PREFLIGHT_MS
                    + 3 * EXCLUSION_COMMAND_MS
                    + BROWSER_LAUNCH_MS
                    + BROWSER_NAVIGATE_ONLY.work_ms
                    + 4 * CDP_STEP_MS
                    + LOGIN_VERIFY_MS
                    + TEARDOWN_MS
                    + VAULT_DEPOSIT_MS
                    + STORE_MS,
            ),
            (MANAGEMENT_REBIND_PROFILE_ROOT, PREFLIGHT_MS + 2 * STORE_MS),
            (
                MANAGEMENT_CLEAR_LAUNCH_RECOVERY,
                PREFLIGHT_MS + 2 * STORE_MS,
            ),
            (MANAGEMENT_REVOKE_ACCESS, 2 * STORE_MS),
            (MANAGEMENT_REVOKE_GRANT, 2 * STORE_MS),
            (MANAGEMENT_LIST_GRANTS, 2 * STORE_MS),
        ];
        assert_eq!(expected.len(), MANAGEMENT_ACTIONS.len());
        for (budget, total) in expected {
            assert_eq!(budget.work_ms, total, "{}", budget.action);
        }
    }

    #[test]
    fn derived_tool_limits_equal_their_formulas() {
        assert_eq!(
            COMPUTER_MAX_WORK_MS,
            COMPUTER_ACTIONS
                .iter()
                .map(|entry| entry.work_ms)
                .max()
                .unwrap()
        );
        assert_eq!(
            BROWSER_MAX_WORK_MS,
            BROWSER_ACTIONS
                .iter()
                .chain(&FLAT_MANAGEMENT_ACTIONS)
                .map(|entry| entry.work_ms)
                .max()
                .unwrap()
        );
        assert_eq!(
            COMPUTER_QUEUE_WAIT_LIMIT_MS,
            CONSENT_PARK_LIMIT_MS
                + COMPUTER_MAX_WORK_MS
                + RELEASE_BUDGET_MS
                + BOUNDARY_SLACK_MS
                + RESOLUTION_LIMIT_MS
        );
        assert_eq!(
            BROWSER_QUEUE_WAIT_LIMIT_MS,
            CONSENT_PARK_LIMIT_MS + BROWSER_MAX_WORK_MS + RELEASE_BUDGET_MS + BOUNDARY_SLACK_MS
        );
        assert_eq!(COMPUTER_MAX_PARK_MS, CONSENT_PARK_LIMIT_MS);
        assert_eq!(BROWSER_MAX_PARK_MS, CONSENT_PARK_LIMIT_MS);
        for (reply, queue, park, work, envelope) in [
            (
                COMPUTER_REPLY_MAX_MS,
                COMPUTER_QUEUE_WAIT_LIMIT_MS,
                COMPUTER_MAX_PARK_MS,
                COMPUTER_MAX_WORK_MS,
                COMPUTER_ENVELOPE_MS,
            ),
            (
                BROWSER_REPLY_MAX_MS,
                BROWSER_QUEUE_WAIT_LIMIT_MS,
                BROWSER_MAX_PARK_MS,
                BROWSER_MAX_WORK_MS,
                BROWSER_ENVELOPE_MS,
            ),
        ] {
            assert_eq!(
                reply,
                CALL_RECORD_BEGIN_MS
                    + queue
                    + park
                    + work
                    + RELEASE_BUDGET_MS
                    + CALL_RECORD_SETTLE_MS
                    + EGRESS_SEND_MS
            );
            assert_eq!(envelope, CALL_RECORD_BEGIN_MS + queue + park + work);
        }
        assert_eq!(COMPUTER_REPLY_MAX_MS, 685_001);
        assert_eq!(BROWSER_REPLY_MAX_MS, 983_001);
    }

    #[test]
    fn in_flight_age_stale_ms_uses_only_work_release_and_margin() {
        let longest_work = COMPUTER_ACTIONS
            .iter()
            .chain(&BROWSER_ACTIONS)
            .chain(&MANAGEMENT_ACTIONS)
            .map(|budget| budget.work_ms)
            .max()
            .unwrap();
        assert_eq!(MAX_ACTION_WORK_MS, longest_work);
        assert_eq!(
            IN_FLIGHT_AGE_STALE_MS,
            longest_work + RELEASE_BUDGET_MS + IN_FLIGHT_MARGIN_MS
        );
        assert_eq!(IN_FLIGHT_AGE_STALE_MS, 303_000);
    }

    #[test]
    fn longest_work_and_release_remain_healthy_until_the_margin_expires() {
        use cerebellum_core::clock::{FakeClock, MonotonicClock};
        use cerebellum_core::health::{health_check_with_clock, HealthState};
        use subc_protocol::session::HealthStatus;

        let state = HealthState::with_config(crate::HealthConfig {
            dispatch_heartbeat_stale_ms: 100,
            queue_age_stale_ms: 30_000,
            in_flight_age_stale_ms: IN_FLIGHT_AGE_STALE_MS,
        });
        let mut clock = FakeClock::new();
        state.stamp_oldest_in_flight(Some(clock.now()));
        let longest_work = COMPUTER_ACTIONS
            .iter()
            .chain(&BROWSER_ACTIONS)
            .chain(&MANAGEMENT_ACTIONS)
            .map(|budget| budget.work_ms)
            .max()
            .unwrap();
        let active_ms = longest_work + RELEASE_BUDGET_MS;
        let stale_after_ms = active_ms + IN_FLIGHT_MARGIN_MS;
        let mut previous_age_ms = 0;
        for (age_ms, expected) in [
            (active_ms, HealthStatus::Ok),
            (stale_after_ms, HealthStatus::Ok),
            (stale_after_ms + 1, HealthStatus::Degraded),
        ] {
            clock.advance(Duration::from_millis(age_ms - previous_age_ms));
            state.stamp_heartbeat_with_clock(&clock);
            let report = health_check_with_clock(&state, &clock);
            assert_eq!(report.status, expected, "in-flight age {age_ms} ms");
            assert_eq!(
                report.ages.oldest_in_flight_age,
                Some(Duration::from_millis(age_ms))
            );
            previous_age_ms = age_ms;
        }
    }

    #[test]
    fn management_parks_and_envelopes_are_exhaustive() {
        let expected = [
            (management::WOULD_ASK, 0, 0),
            (management::OPEN_TARGET, 0, CONSENT_PARK_LIMIT_MS),
            (management::LIST_APP_GRANTS, 0, 0),
            (management::REVOKE_APP_GRANT, 0, 0),
            (management::OPEN_GRANT, BROWSER_QUEUE_WAIT_LIMIT_MS, 0),
            (
                management::IMPORT_LOGIN,
                BROWSER_QUEUE_WAIT_LIMIT_MS,
                CONSENT_PARK_LIMIT_MS,
            ),
            (management::PRESENT, BROWSER_QUEUE_WAIT_LIMIT_MS, 0),
            (management::RESUME, BROWSER_QUEUE_WAIT_LIMIT_MS, 0),
            (
                management::REBIND_PROFILE_ROOT,
                BROWSER_QUEUE_WAIT_LIMIT_MS,
                0,
            ),
            (
                management::CAPTURE_LOGIN,
                BROWSER_QUEUE_WAIT_LIMIT_MS,
                BROWSER_MAX_PARK_MS,
            ),
            (
                management::CLEAR_LAUNCH_RECOVERY,
                BROWSER_QUEUE_WAIT_LIMIT_MS,
                0,
            ),
            (management::REVOKE_ACCESS, BROWSER_QUEUE_WAIT_LIMIT_MS, 0),
            (management::REVOKE_GRANT, BROWSER_QUEUE_WAIT_LIMIT_MS, 0),
            (management::LIST_GRANTS, 0, 0),
        ];
        assert_eq!(expected.len(), management::OPERATIONS.len());
        assert_eq!(expected.len(), MANAGEMENT_LIMITS.len());
        for (method, queue, park) in expected {
            let limits = management::call_limits(method).unwrap();
            assert_eq!(limits.queue_wait_ms, queue, "{method}");
            assert_eq!(limits.park_ms, park, "{method}");
            assert_eq!(limits.work_ms, management(method).unwrap().work_ms);
            assert_eq!(
                limits.reply_max_ms,
                CALL_RECORD_BEGIN_MS
                    + queue
                    + park
                    + limits.work_ms
                    + RELEASE_BUDGET_MS
                    + CALL_RECORD_SETTLE_MS
                    + EGRESS_SEND_MS,
                "{method}"
            );
            assert_eq!(
                limits.envelope_ms,
                CALL_RECORD_BEGIN_MS + queue + park + limits.work_ms,
                "{method}"
            );
        }
        for method in management::OPERATIONS {
            assert_eq!(
                MANAGEMENT_LIMITS
                    .iter()
                    .filter(|entry| entry.method == method)
                    .count(),
                1,
                "{method}"
            );
        }
        assert!(management::call_limits("unknown").is_none());
    }

    #[test]
    fn sizing_constants_cover_their_phases() {
        assert_eq!(
            CALL_RECORD_BEGIN_MS,
            RECORD_WRITE_MS + RECORD_COMPACT_MS + RECORD_SYNC_MS
        );
        assert_eq!(
            CALL_RECORD_SETTLE_MS,
            RECORD_WRITE_MS + RECORD_COMPACT_MS + RECORD_SYNC_MS
        );
        assert_eq!(RELEASE_BUDGET_MS, (6 * AX_STEP_MS).max(CDP_STEP_MS));
        let bytes = 2
            * EGRESS_BUFFER as u64
            * (4 + subc_protocol::HEADER_LEN as u64 + subc_protocol::MAX_FRAME_BODY_LEN as u64);
        let scaled = bytes * 1_000;
        let write_ms = scaled / EGRESS_MIN_BYTES_PER_S
            + u64::from(!scaled.is_multiple_of(EGRESS_MIN_BYTES_PER_S));
        assert_eq!(EGRESS_SEND_MS, write_ms + 2 * EGRESS_FLUSH_MS);
        assert_eq!(EGRESS_BUFFER, crate::EGRESS_BUFFER);
        assert_eq!(BOUNDARY_SLACK_MS, 5_000);
        for workers in [
            MAX_BLOCKING_WORKERS_COMPUTER,
            MAX_BLOCKING_WORKERS_BROWSER,
            MAX_CALL_RECORD_WORKERS,
        ] {
            assert!(workers >= 2);
        }
        assert_eq!(
            CONSENT_PARK_LIMIT_MS,
            crate::computer_grants::CONSENT_PARK_LIMIT.as_millis() as u64
        );
        assert_eq!(
            HANDOFF_DURATION_MS,
            crate::browser_session::HANDOFF_DURATION_MS
        );
        assert_eq!(WAIT_MS, crate::computer_capability::MAX_WAIT_TIMEOUT_MS);
    }

    #[test]
    fn repeated_commands_cannot_renew_a_phase_deadline() {
        for cap in [
            FRAME_DISCOVERY_PHASE_MS,
            FRAME_SNAPSHOT_PHASE_MS,
            AX_CHILDREN_PHASE_MS,
            DIALOG_DISMISS_PHASE_MS,
            CLICK_CANDIDATES_PHASE_MS,
            FRAME_POINT_PHASE_MS,
        ] {
            let start = Instant::now();
            let phase = PhaseDeadline::new(start, cap, start + Duration::from_millis(2 * cap));
            let mut now = start;
            let mut commands = 0;
            // Each fake command would consume a full step if allowed.
            // PhaseDeadline::step_deadline stops it at the shared phase end,
            // rather than relying on the number of iterations to bound work.
            for _ in 0..100 {
                let deadline = phase.step_deadline(now, CDP_STEP_MS);
                if deadline <= now {
                    break;
                }
                now = deadline;
                commands += 1;
            }
            assert_eq!(now.duration_since(start).as_millis() as u64, cap);
            assert_eq!(commands, cap.div_ceil(CDP_STEP_MS));
        }
        let start = Instant::now();
        let phase = PhaseDeadline::new(start, 10_000, start + Duration::from_millis(1_000));
        assert_eq!(
            phase.step_deadline(start, CDP_STEP_MS),
            start + Duration::from_millis(1_000)
        );
    }

    #[test]
    // Keep the failure in this test's report rather than turning an oversized
    // declaration into a compile error with no test name.
    #[allow(clippy::assertions_on_constants)]
    fn browser_reply_leaves_room_for_the_caller_deadline() {
        assert!(BROWSER_REPLY_MAX_MS < 30 * 60 * 1_000,
            "Prefrontal's caller deadline is about 31 minutes; browser reply.max_ms must stay below 30 minutes");
    }
}
