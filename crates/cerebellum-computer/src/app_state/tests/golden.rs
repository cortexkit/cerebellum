//! Whole reads of three recorded application shapes, rendered to the exact
//! text a caller gets: X's home timeline in Chrome, Bionic Reading's
//! settings panel, and the Magic Context dashboard.
//!
//! The fixtures are cut down from real accessibility trees read from those
//! applications, keeping what made each expensive to read before: X wraps
//! every post in empty containers and names the post's container with the
//! whole post; Bionic's panel is mostly unnamed groups around a few controls;
//! the dashboard has two hundred chart points with six-line labels, every
//! session row as a button and again as nine texts, and a full menu bar.

use super::super::render::{
    render_state, ObservedNode, StateHeader, StateRequest, TruncationReason, Zoom, MAX_DIFF_BYTES,
};
use super::super::session::{AppStateSessions, SessionRead};
use super::super::source::{ElementValue, RawAppState, RawElement};
use super::{grant, CONVERSATION};

/// The run tag every fixture's ids carry, fixed so the expected texts below
/// can be exact.
const RUN_TAG: &str = "kq";

/// Hands out element tokens in the order a fixture is written.
struct Tokens(std::cell::Cell<u64>);

impl Tokens {
    fn new() -> Self {
        Self(std::cell::Cell::new(0))
    }

    fn element(&self, role: &str) -> RawElement {
        self.0.set(self.0.get() + 1);
        RawElement::fixture(self.0.get(), role)
    }

    fn titled(&self, role: &str, title: &str) -> RawElement {
        self.element(role).titled(title)
    }

    fn link(&self, title: &str, url: &str) -> RawElement {
        self.titled("AXLink", title).with_url(url)
    }

    fn text(&self, text: &str) -> RawElement {
        let mut element = self.element("AXStaticText");
        element.value = ElementValue::Text(text.to_string());
        element
    }

    /// An unnamed group around `children`, the wrapper web pages are full of.
    fn wrap(&self, children: Vec<RawElement>) -> RawElement {
        self.element("AXGroup").with_children(children)
    }
}

fn observe(roots: Vec<RawElement>) -> SessionRead {
    AppStateSessions::with_run_tag(RUN_TAG).observe(
        CONVERSATION,
        &grant(),
        &RawAppState {
            roots,
            focused: None,
            unreadable_subtrees: 0,
            read_bound_reached: false,
        },
    )
}

fn outline_of(app: &str, read: &SessionRead) -> String {
    render_state(
        &StateHeader {
            app_name: app,
            focused_element_id: read.focused_element_id.as_deref(),
        },
        &read.roots,
        &StateRequest::default(),
    )
    .text
}

fn zoom_of(app: &str, read: &SessionRead, id: &str) -> String {
    render_state(
        &StateHeader {
            app_name: app,
            focused_element_id: None,
        },
        &read.roots,
        &StateRequest {
            zoom: Some(Zoom::Element(id)),
            ..Default::default()
        },
    )
    .text
}

fn find<'a>(nodes: &'a [ObservedNode], needle: &str) -> &'a ObservedNode {
    fn search<'a>(nodes: &'a [ObservedNode], needle: &str) -> Option<&'a ObservedNode> {
        nodes.iter().find_map(|node| {
            if node.description.label.starts_with(needle) {
                Some(node)
            } else {
                search(&node.children, needle)
            }
        })
    }
    search(nodes, needle).unwrap_or_else(|| panic!("no element labelled {needle}"))
}

fn id(node: &ObservedNode) -> &str {
    node.element_id.as_deref().expect("numbered")
}

// ---------------------------------------------------------------------------
// X's home timeline in Chrome
// ---------------------------------------------------------------------------

const POSTS: [(&str, &str, &str, &str); 7] = [
    (
        "Wren Workshop",
        "wren_example",
        "17 seconds ago",
        "The rain moved our seed swap indoors. Bring envelopes for the seed table and label any packets you would like others to take home.",
    ),
    (
        "Pebble Post",
        "pebble_post",
        "19 minutes ago",
        "A seed swap with @moss_example",
    ),
    (
        "Spindle Press",
        "spindle_press",
        "20 minutes ago",
        "We're planning a live garden tour with Sage. Curious about balcony gardening? Leave a question below.",
    ),
    (
        "Paper Kite Club",
        "paper_kite_club",
        "29 minutes ago",
        "Fold along with us!\n\nPocket kite\nPaper boat",
    ),
    (
        "Copper Lantern",
        "lantern_example",
        "18 hours ago",
        "How did those seedlings do?",
    ),
    (
        "Thimble Scouts",
        "thimble_example",
        "2 hours ago",
        "Our next sewing circle is on Tuesday.",
    ),
    (
        "River Loom",
        "river_example",
        "4 minutes ago",
        "I made a blue scarf from leftover yarn.",
    ),
];

/// One post. Its elements take tokens from a range of their own, so a post
/// is the same element in every read that shows it, whatever else changed.
fn post(index: usize) -> RawElement {
    let tokens = Tokens(std::cell::Cell::new(10_000 + 100 * index as u64));
    let (name, handle, age, body) = POSTS[index];
    let status = format!("example.com/{handle}/status/{}", 2001 + index);
    let views = format!("{} views", 59 + index * 100);
    // Chrome names a post's container with everything the post says, so the
    // container's line alone reads the post.
    let summary = format!("{name} Verified account @{handle} {age} {body} {views}");
    let header = tokens.wrap(vec![
        tokens.link(
            &format!("{name} Verified account"),
            &format!("example.com/{handle}"),
        ),
        tokens.wrap(vec![
            tokens.link(&format!("@{handle}"), &format!("example.com/{handle}"))
        ]),
        tokens.link(age, &status),
    ]);
    let header = tokens.wrap(vec![tokens.wrap(vec![header])]);
    let actions = tokens.titled("AXGroup", &views).with_children(vec![
        tokens.titled("AXButton", "0 Replies. Reply"),
        tokens.titled("AXButton", "0 reposts. Repost"),
        tokens.titled("AXButton", "0 Likes. Like"),
        tokens.link(
            &format!("{views}. View post analytics"),
            &format!("{status}/analytics"),
        ),
        tokens.titled("AXButton", "Bookmark"),
    ]);
    let text = tokens.text(body);
    tokens
        .titled("AXGroup", &summary)
        .with_children(vec![tokens.wrap(vec![header, text, actions])])
}

/// X's home timeline with the tab `selected` chosen and these posts shown.
fn x_timeline_with(selected: usize, posts: &[usize]) -> Vec<RawElement> {
    let t = Tokens::new();
    let mut address = t.element("AXTextField").described("Address and search bar");
    address.value = ElementValue::Text("example.com/home".into());
    address.value_settable = true;
    let toolbar = t.element("AXToolbar").with_children(vec![
        t.titled("AXButton", "Back"),
        t.titled("AXButton", "Reload"),
        address,
    ]);
    let navigation = t
        .element("AXGroup")
        .with_subrole("AXLandmarkNavigation")
        .described("Primary")
        .with_children(vec![
            t.link("Home", "example.com/home"),
            t.link("Explore", "example.com/explore"),
            t.link("Notifications", "example.com/notifications"),
            t.link("Direct Messages", "example.com/i/chat"),
            t.link("Profile", "example.com/juniper_example"),
            t.link("Post", "example.com/compose/post"),
        ]);
    let tabs: Vec<RawElement> = ["For you", "Following", "AI Developer Tools"]
        .iter()
        .enumerate()
        .map(|(index, title)| {
            let mut tab = t
                .element("AXRadioButton")
                .with_subrole("AXTabButton")
                .titled(title);
            tab.selected = index == selected;
            tab.value = ElementValue::Number(if index == selected { 1.0 } else { 0.0 });
            tab
        })
        .collect();
    let tabs = t.element("AXTabGroup").with_children(tabs);
    let heading = t
        .titled("AXHeading", "Your Home Timeline")
        .with_children(vec![t.text("Your Home Timeline")]);
    let timeline = t
        .titled("AXGroup", "Timeline: Your Home Timeline")
        .with_children(vec![
            heading,
            t.wrap(posts.iter().map(|index| post(*index)).collect()),
        ]);
    let main = t
        .element("AXGroup")
        .with_subrole("AXLandmarkMain")
        .described("Home timeline")
        .with_children(vec![t.wrap(vec![t.wrap(vec![tabs])]), timeline]);
    let trends = t
        .element("AXGroup")
        .with_subrole("AXLandmarkComplementary")
        .described("Trending")
        .with_children(vec![
            t.link(
                "Wren Workshop opens its seed library Trending now · News · 849 posts",
                "example.com/i/trending/1",
            ),
            t.link("Paper Kite Club shares a folding guide", "example.com/i/trending/2"),
        ]);
    let web = t
        .titled("AXWebArea", "Synthetic Kestrel Feed")
        .with_url("https://example.com/home")
        .with_children(vec![t.wrap(vec![navigation, main, trends])]);
    let window = t
        .titled("AXWindow", "Synthetic Kestrel Feed")
        .with_children(vec![t.wrap(vec![toolbar, t.wrap(vec![web])])]);
    let menu_bar = t.element("AXMenuBar").with_children(vec![
        t.titled("AXMenuBarItem", "Apple"),
        t.titled("AXMenuBarItem", "Chrome"),
        t.titled("AXMenuBarItem", "File"),
    ]);
    vec![window, menu_bar]
}

fn x_timeline() -> Vec<RawElement> {
    x_timeline_with(2, &[0, 1, 2, 3, 4])
}

// ---------------------------------------------------------------------------
// Bionic Reading's settings panel
// ---------------------------------------------------------------------------

fn bionic_settings() -> Vec<RawElement> {
    let t = Tokens::new();
    let mut enabled = t.titled("AXCheckBox", "Enable Bionic Reading");
    enabled.value = ElementValue::Number(1.0);
    let mut fixation = t.titled("AXSlider", "Fixation");
    fixation.value = ElementValue::Number(3.0);
    fixation.value_settable = true;
    let mut saccade = t.titled("AXSlider", "Saccade");
    saccade.value = ElementValue::Number(10.0);
    saccade.value_settable = true;
    let theme = t
        .titled("AXPopUpButton", "Theme")
        .with_children(vec![t.text("Theme")]);
    let mut shortcut = t.element("AXTextField").described("Shortcut");
    shortcut.value = ElementValue::Text("⌃⌥B".into());
    shortcut.value_settable = true;
    let reading = t.titled("AXGroup", "Reading").with_children(vec![
        t.wrap(vec![enabled]),
        t.wrap(vec![t.wrap(vec![fixation])]),
        t.wrap(vec![saccade]),
        t.wrap(vec![theme]),
        t.wrap(vec![t.text("Keyboard shortcut"), shortcut]),
    ]);
    let toolbar = t.element("AXToolbar").with_children(vec![
        t.titled("AXButton", "General"),
        t.titled("AXButton", "Reading"),
        t.titled("AXButton", "Account"),
    ]);
    let window = t.titled("AXWindow", "Settings").with_children(vec![
        t.wrap(vec![t.wrap(vec![toolbar])]),
        t.wrap(vec![t.wrap(vec![reading])]),
        t.wrap(vec![t.element("AXGroup")]),
    ]);
    vec![window]
}

// ---------------------------------------------------------------------------
// The Magic Context dashboard
// ---------------------------------------------------------------------------

/// One point of the cache-hit chart. Its label is six lines, as the chart
/// library writes it.
fn chart_point(t: &Tokens, index: usize) -> RawElement {
    let minute = index % 60;
    let hour = index / 60;
    t.titled(
        "AXButton",
        &format!(
            "Sep 30 {hour:02}:{minute:02}\nFULL BUST\nhit rate {}%\n{} tokens cached\n{} tokens read\nsession {}",
            index % 100,
            1000 + index,
            2000 + index,
            index % 7
        ),
    )
}

/// One session row: a button naming the whole row, and the row again as nine
/// texts.
fn session_row(t: &Tokens, index: usize) -> RawElement {
    let cells = [
        format!("ses_{index:04}"),
        "opencode".to_string(),
        format!("{} msgs", 10 + index),
        format!("{}%", 40 + index),
        format!("{} KB", 100 + index),
        "anthropic".to_string(),
        "claude".to_string(),
        format!("{} min", index),
        "idle".to_string(),
    ];
    let button = t.titled("AXButton", &cells.join(" "));
    let texts: Vec<RawElement> = cells.iter().map(|cell| t.text(cell)).collect();
    t.element("AXRow")
        .with_children(vec![button, t.wrap(texts)])
}

fn dashboard() -> Vec<RawElement> {
    dashboard_with(0)
}

/// The dashboard, its chart drawn by elements whose tokens start past
/// `chart_generation`: a redrawn chart is all new elements to a reader.
fn dashboard_with(chart_generation: u64) -> Vec<RawElement> {
    let t = Tokens::new();
    let navigation = t
        .element("AXGroup")
        .with_subrole("AXLandmarkNavigation")
        .with_children(
            [
                "Projects",
                "Workspaces",
                "Cache",
                "User Directives",
                "Config",
                "Logs",
            ]
            .iter()
            .map(|title| t.titled("AXButton", title))
            .collect(),
        );
    let mut controls: Vec<RawElement> = Vec::new();
    for (role, title) in [
        ("AXPopUpButton", "Project"),
        ("AXPopUpButton", "Range"),
        ("AXButton", "Refresh"),
        ("AXButton", "Export"),
    ] {
        controls.push(t.titled(role, title));
    }
    for title in ["Hits", "Partial", "Busts", "Bytes"] {
        controls.push(t.wrap(vec![t.text(title), t.text("1,204")]));
    }
    let mut auto = t.titled("AXCheckBox", "Auto refresh");
    auto.value = ElementValue::Number(1.0);
    controls.push(auto);
    let region = t
        .element("AXGroup")
        .with_subrole("AXLandmarkRegion")
        .described("Cache Diagnostics")
        .with_children(controls);
    let recent = t.titled("AXList", "Recent Sessions").with_children(
        (0..8)
            .map(|index| {
                t.element("AXGroup").with_children(vec![t.link(
                    &format!("ses_{index:04}"),
                    &format!("http://localhost:5173/s/{index}"),
                )])
            })
            .collect(),
    );
    let chart_tokens = Tokens(std::cell::Cell::new(100_000 + 1_000 * chart_generation));
    let points: Vec<RawElement> = (0..200)
        .map(|index| chart_point(&chart_tokens, index))
        .collect();
    let chart = t
        .titled("AXGroup", "Cache Hit Timeline")
        .with_children(vec![t.wrap(points)]);
    let rows: Vec<RawElement> = (0..31).map(|index| session_row(&t, index)).collect();
    let table = t.element("AXList").with_children(rows);
    let footer = t.text("DB: 7208.9 MB · 17927 memories · 11834 compartments · 3170 notes");
    let web = t
        .titled("AXWebArea", "Magic Context Dashboard")
        .with_url("http://localhost:5173/cache")
        .with_children(vec![t.wrap(vec![
            navigation,
            t.wrap(vec![region, recent, chart, table]),
            footer,
        ])]);
    let window = t
        .titled("AXWindow", "Magic Context")
        .with_children(vec![t.wrap(vec![web])]);
    let menus = ["Magic Context", "File", "Edit", "View", "Window", "Help"]
        .iter()
        .map(|menu| {
            let items: Vec<RawElement> = (1..=8)
                .map(|item| t.titled("AXMenuItem", &format!("{menu} item {item}")))
                .collect();
            t.titled("AXMenuBarItem", menu)
                .with_children(vec![t.element("AXMenu").with_children(items)])
        })
        .collect();
    let menu_bar = t.element("AXMenuBar").with_children(menus);
    vec![window, menu_bar]
}

fn diff_between(
    before: Vec<RawElement>,
    after: Vec<RawElement>,
) -> (String, Option<super::super::render::Truncation>) {
    let sessions = AppStateSessions::with_run_tag(RUN_TAG);
    let raw = |roots| RawAppState {
        roots,
        focused: None,
        unreadable_subtrees: 0,
        read_bound_reached: false,
    };
    sessions.observe(CONVERSATION, &grant(), &raw(before));
    let mut after = raw(after);
    after.focused = Some(std::sync::Arc::new(
        super::super::source::FixtureElementToken(5),
    ));
    let observed = sessions.observe(CONVERSATION, &grant(), &after);
    let diff = super::super::render::render_diff(
        &observed.roots,
        &observed.diff,
        observed.focused_element_id.as_deref(),
    );
    (diff.text, diff.truncation)
}

/// Every `+` and `~` line of a diff names the element by its whole line: id,
/// role words and label. A bare id tells a caller nothing it can act on.
/// (The goldens pin the labels; this pins that no line is an id alone.)
fn assert_every_change_is_labelled(diff: &str) {
    for line in diff.lines().filter(|line| line.starts_with(['+', '~'])) {
        let mut words = line[1..].split_whitespace();
        let id = words.next().unwrap_or_default();
        assert!(
            id.strip_prefix(RUN_TAG).is_some_and(
                |number| !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
            ),
            "no id leads {line:?}"
        );
        assert!(
            words
                .next()
                .is_some_and(|role| role.chars().all(|c| c.is_ascii_lowercase())),
            "{line:?} names no role after its id"
        );
    }
}

const X_OUTLINE: &str = "\
Google Chrome · window \"Synthetic Kestrel Feed\" · https://example.com/home
kq3 toolbar
  kq4 button Back
  kq5 button Reload
  kq6 text field (settable) Address and search bar, Value: example.com/home
kq10 navigation Primary
  kq11 link Home, Value: example.com/home
  kq12 link Explore, Value: example.com/explore
  kq13 link Notifications, Value: example.com/notifications
  kq14 link Direct Messages, Value: example.com/i/chat
  kq15 link Profile, Value: example.com/juniper_example
  kq16 link Post, Value: example.com/compose/post
kq17 main Home timeline  [2 elements: Timeline: Your Home Timeline, ~3.8 KB]
  kq20 tab group  [3 tabs: For you, Following, AI Developer Tools, ~126 B]
  kq24 group Timeline: Your Home Timeline  [2 elements: Your Home Timeline, ~3.6 KB]
    kq28 group Wren Workshop Verified account @wren_example 17 seconds ago The rain moved our seed swap indoors. Bring envelopes for the seed table and label any packets you would like others to take home. 59 views  [3 elements: The rain moved our seed swap indoors. Br…, 59 views, ~815 B]
    kq44 group Pebble Post Verified account @pebble_post 19 minutes ago A seed swap with @moss_example 159 views  [3 elements: A seed swap with @moss_example, 159 views, ~588 B]
    kq60 group Spindle Press Verified account @spindle_press 20 minutes ago We're planning a live garden tour with Sage. Curious about balcony gardening? Leave a question below. 259 views  [3 elements: We're planning a live garden tour with S…, 259 views, ~754 B]
    kq76 group Paper Kite Club Verified account @paper_kite_club 29 minutes ago Fold along with us! · Pocket kite · Paper boat 359 views  [3 elements: Fold along with us! · Pocket kite · Pape…, 359 views, ~604 B]
    kq92 group Copper Lantern Verified account @lantern_example 18 hours ago How did those seedlings do? 459 views  [3 elements: How did those seedlings do?, 459 views, ~566 B]
kq108 complementary Trending
  kq109 link Wren Workshop opens its seed library Trending now · News · 849 posts, Value: example.com/i/trending/1
  kq110 link Paper Kite Club shares a folding guide, Value: example.com/i/trending/2
menu bar (zoom: menubar)
";

/// X's timeline outlines to its landmarks, its tabs and one line per post,
/// each post readable from its container's label, in under 3 KB.
#[test]
fn x_timeline_outline_is_golden() {
    let read = observe(x_timeline());
    let outline = outline_of("Google Chrome", &read);
    assert_eq!(outline, X_OUTLINE);
    assert!(outline.len() < 3 * 1024, "{} bytes", outline.len());
}

const X_POST: &str = "\
Google Chrome · window \"Synthetic Kestrel Feed\" · https://example.com/home
kq28 group Wren Workshop Verified account @wren_example 17 seconds ago The rain moved our seed swap indoors. Bring envelopes for the seed table and label any packets you would like others to take home. 59 views
  kq30 group
    kq33 link Wren Workshop Verified account, Value: example.com/wren_example
    kq35 link @wren_example, Value: example.com/wren_example
    kq36 link 17 seconds ago, Value: example.com/wren_example/status/2001
  kq37 text The rain moved our seed swap indoors. Bring envelopes for the seed table and label any packets you would like others to take home.
  kq38 group 59 views
    kq39 button 0 Replies. Reply
    kq40 button 0 reposts. Repost
    kq41 button 0 Likes. Like
    kq42 link 59 views. View post analytics, Value: example.com/wren_example/status/2001/analytics
    kq43 button Bookmark
";

/// One zoom into a post from the outline shows the whole post: its text,
/// its author and time with their links, and its actions.
#[test]
fn an_x_post_reads_after_one_zoom() {
    let read = observe(x_timeline());
    let post = find(&read.roots, "Wren Workshop");
    assert!(
        outline_of("Google Chrome", &read).contains(&format!("\n    {} group Wren Workshop", id(post)))
    );
    assert_eq!(zoom_of("Google Chrome", &read, id(post)), X_POST);
}

const BIONIC_OUTLINE: &str = "\
Bionic Reading · window \"Settings\"
kq1 window Settings
  kq4 toolbar
    kq5 button General
    kq6 button Reading
    kq7 button Account
  kq10 group Reading
    kq12 check box (checked) Enable Bionic Reading
    kq15 slider (settable) Fixation, Value: 3
    kq17 slider (settable) Saccade, Value: 10
    kq19 pop up button Theme
    kq21 group
      kq22 text Keyboard shortcut
      kq23 text field (settable) Shortcut, Value: ⌃⌥B
";

/// A small panel is printed whole: every control, none of the unnamed groups
/// around them, and not the pop-up button's own title a second time.
#[test]
fn bionic_settings_outline_is_golden() {
    let read = observe(bionic_settings());
    assert_eq!(outline_of("Bionic Reading", &read), BIONIC_OUTLINE);
}

/// A search lands in one call: the match, under the labelled ancestors that
/// place it.
#[test]
fn a_filter_prints_each_match_under_its_labelled_ancestors() {
    let read = observe(bionic_settings());
    let found = render_state(
        &StateHeader {
            app_name: "Bionic Reading",
            focused_element_id: None,
        },
        &read.roots,
        &StateRequest {
            text: Some("fixation"),
            ..Default::default()
        },
    )
    .text;
    assert_eq!(
        found,
        "Bionic Reading · window \"Settings\"\n\
         kq1 window Settings\n  \
         kq10 group Reading\n    \
         kq15 slider (settable) Fixation, Value: 3\n"
    );
}

const DASHBOARD_OUTLINE: &str = "\
Magic Context Dashboard · window \"Magic Context\" · http://localhost:5173/cache
kq5 navigation
  kq6 button Projects
  kq7 button Workspaces
  kq8 button Cache
  kq9 button User Directives
  kq10 button Config
  kq11 button Logs
kq12 group
  kq13 region Cache Diagnostics
    kq14 pop up button Project
    kq15 pop up button Range
    kq16 button Refresh
    kq17 button Export
    4 groups (zoom: kq13)
    kq30 check box (checked) Auto refresh
  kq31 list Recent Sessions
    8 links, like \"ses_0000\" (zoom: kq31)
  kq48 group Cache Hit Timeline
    200 buttons, like \"Sep 30 00:00 · FULL BUST · hit rate 0% ·…\" (zoom: kq48)
  kq250 list
    31 rows (zoom: kq250)
kq623 text DB: 7208.9 MB · 17927 memories · 11834 compartments · 3170 notes
menu bar (zoom: menubar)
";

/// The dashboard that read as 49 KB outlines in under 1.5 KB: two hundred
/// chart points and thirty-one rows are one line each, and the menu bar is
/// one line.
#[test]
fn dashboard_outline_is_golden() {
    let read = observe(dashboard());
    let outline = outline_of("Magic Context Dashboard", &read);
    assert_eq!(outline, DASHBOARD_OUTLINE);
    assert!(outline.len() < 1536, "{} bytes", outline.len());
}

/// Zooming into the element whose children repeat lists every one of them,
/// and `zoom: menubar` prints the menu bar the outline left out.
#[test]
fn zoom_lists_the_zoomed_elements_repeated_children_and_the_menu_bar() {
    let read = observe(dashboard());
    let chart = find(&read.roots, "Cache Hit Timeline");
    let zoomed = zoom_of("Magic Context Dashboard", &read, id(chart));
    assert_eq!(zoomed.matches(" button Sep 30 ").count(), 200, "{zoomed}");

    let menus = render_state(
        &StateHeader {
            app_name: "Magic Context Dashboard",
            focused_element_id: None,
        },
        &read.roots,
        &StateRequest {
            zoom: Some(Zoom::MenuBar),
            ..Default::default()
        },
    );
    assert!(menus.zoom_found);
    assert!(
        menus.text.contains(" menu bar item File\n"),
        "{}",
        menus.text
    );
    assert!(
        menus.text.contains(" menu item File item 8\n"),
        "{}",
        menus.text
    );
    assert!(!outline_of("Magic Context Dashboard", &read).contains("menu item"));
}

/// Up to three siblings of one shape are listed; a fourth makes them one
/// line naming how many there are and what the first says.
#[test]
fn repeated_siblings_collapse_past_three() {
    let t = Tokens::new();
    let list = |count: usize| {
        let items: Vec<RawElement> = (0..count)
            .map(|index| t.titled("AXButton", &format!("Row {index}")))
            .collect();
        t.titled("AXList", "Rows").with_children(items)
    };
    let three = observe(vec![list(3)]);
    let outline = outline_of("App", &three);
    assert_eq!(outline.matches(" button Row ").count(), 3, "{outline}");

    let four = observe(vec![list(4)]);
    let list_id = four.roots[0].element_id.clone().unwrap();
    assert_eq!(
        outline_of("App", &four),
        format!("App\n{list_id} list Rows\n  4 buttons, like \"Row 0\" (zoom: {list_id})\n")
    );
}

/// Unnamed single-child wrappers go, and their child is printed at their
/// depth; an empty unnamed group goes; a text repeating its parent's label
/// goes.
#[test]
fn collapse_drops_what_carries_nothing() {
    let t = Tokens::new();
    let button = t
        .titled("AXButton", "Send")
        .with_children(vec![t.wrap(vec![t.text("Send")])]);
    let window = t.titled("AXWindow", "Chat").with_children(vec![
        t.wrap(vec![t.wrap(vec![t.wrap(vec![button])])]),
        t.wrap(vec![]),
        t.text("Draft saved"),
    ]);
    let read = observe(vec![window]);
    let window_id = read.roots[0].element_id.clone().unwrap();
    let send = find(&read.roots, "Send");
    let draft = find(&read.roots, "Draft");
    assert_eq!(
        zoom_of("Chat", &read, &window_id),
        format!(
            "Chat · window \"Chat\"\n{window_id} window Chat\n  {} button Send\n  {} text Draft saved\n",
            id(send),
            id(draft)
        )
    );
}

fn actionable(node: &ObservedNode) -> bool {
    matches!(
        node.description.role.as_deref(),
        Some(
            "AXButton"
                | "AXLink"
                | "AXTextField"
                | "AXTextArea"
                | "AXCheckBox"
                | "AXRadioButton"
                | "AXSlider"
                | "AXPopUpButton"
                | "AXMenuItem"
                | "AXMenuBarItem"
                | "AXComboBox"
        )
    ) || !node.description.markers.is_empty()
}

/// Collapse never removes an element a caller could act on: zooming into
/// the parent of every actionable element of every fixture shows its line.
#[test]
fn collapse_keeps_every_actionable_element() {
    fn check(app: &str, read: &SessionRead, parent: &ObservedNode, checked: &mut usize) {
        for child in &parent.children {
            if actionable(child) && !child.hazard {
                let zoomed = zoom_of(app, read, id(parent));
                assert!(
                    zoomed
                        .lines()
                        .any(|line| line.trim_start().starts_with(&format!("{} ", id(child)))),
                    "{} {} is missing from the zoom into {}:\n{zoomed}",
                    id(child),
                    child.description.label,
                    id(parent)
                );
                *checked += 1;
            }
            check(app, read, child, checked);
        }
    }
    let mut checked = 0;
    for (app, roots) in [
        ("Google Chrome", x_timeline()),
        ("Bionic Reading", bionic_settings()),
        ("Magic Context Dashboard", dashboard()),
    ] {
        let read = observe(roots);
        for root in &read.roots {
            check(app, &read, root, &mut checked);
        }
    }
    assert!(
        checked > 300,
        "only {checked} actionable elements were checked"
    );
}

const X_TAB_SWITCH_DIFF: &str = "\
~         kq21 tab (selected) For you, Value: 1
~         kq23 tab AI Developer Tools, Value: 0
+           kq115 group Thimble Scouts Verified account @thimble_example 2 hours ago Our next sewing circle is on Tuesday. 559 views
+               kq120 link Thimble Scouts Verified account, Value: example.com/thimble_example
+               kq122 link @thimble_example, Value: example.com/thimble_example
+               kq123 link 2 hours ago, Value: example.com/thimble_example/status/2006
+             kq124 text Our next sewing circle is on Tuesday.
+             kq125 group 559 views
+               kq126 button 0 Replies. Reply
+               kq127 button 0 reposts. Repost
+               kq128 button 0 Likes. Like
+               kq129 link 559 views. View post analytics, Value: example.com/thimble_example/status/2006/analytics
+               kq130 button Bookmark
+           kq131 group River Loom Verified account @river_example 4 minutes ago I made a blue scarf from leftover yarn. 659 views
+               kq136 link River Loom Verified account, Value: example.com/river_example
+               kq138 link @river_example, Value: example.com/river_example
+               kq139 link 4 minutes ago, Value: example.com/river_example/status/2007
+             kq140 text I made a blue scarf from leftover yarn.
+             kq141 group 659 views
+               kq142 button 0 Replies. Reply
+               kq143 button 0 reposts. Repost
+               kq144 button 0 Likes. Like
+               kq145 link 659 views. View post analytics, Value: example.com/river_example/status/2007/analytics
+               kq146 button Bookmark
Removed element IDs: kq28-59
focused: kq10 navigation Primary
";

/// A tab switch on X: the two tabs that changed, the posts that appeared
/// with everything they say, the posts that went as one id range, and what
/// has focus.
#[test]
fn x_tab_switch_diff_is_golden() {
    let (diff, truncation) = diff_between(x_timeline(), x_timeline_with(0, &[2, 3, 4, 5, 6]));
    assert_eq!(diff, X_TAB_SWITCH_DIFF);
    assert_eq!(truncation, None);
    assert_every_change_is_labelled(&diff);
}

/// A redrawn chart adds two hundred elements; the diff stops at its cap,
/// says how many it left out and where to see them, and still names every
/// element it shows by its whole line.
#[test]
fn a_diff_past_the_cap_counts_what_it_left_out() {
    let (diff, truncation) = diff_between(dashboard(), dashboard_with(1));
    assert!(diff.len() <= MAX_DIFF_BYTES, "{} bytes", diff.len());
    let truncation = truncation.expect("the cap is disclosed");
    assert_eq!(truncation.reason, TruncationReason::DiffCapReached);
    let shown = diff.lines().filter(|line| line.starts_with('+')).count();
    assert_eq!(shown + truncation.omitted_elements, 200);
    assert!(
        diff.contains(&format!(
            "… 0 more changed and {} more added elements are not shown: the diff stops at 4 KB; read_state to see the rest\n",
            truncation.omitted_elements
        )),
        "{diff}"
    );
    assert!(diff.contains("\nRemoved element IDs: kq50-249\n"), "{diff}");
    assert!(
        diff.ends_with("focused: kq9 button User Directives\n"),
        "{diff}"
    );
    assert_every_change_is_labelled(&diff);
}
