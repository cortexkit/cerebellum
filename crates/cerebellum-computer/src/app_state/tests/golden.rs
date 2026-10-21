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
kq111 menu bar
  kq112 menu bar item Apple  [0 children; closed]
  kq113 menu bar item Chrome  [0 children; closed]
  kq114 menu bar item File  [0 children; closed]
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
kq624 menu bar
  kq625 menu bar item Magic Context  [8 children; closed]
  kq635 menu bar item File  [8 children; closed]
  kq645 menu bar item Edit  [8 children; closed]
  kq655 menu bar item View  [8 children; closed]
  kq665 menu bar item Window  [8 children; closed]
  kq675 menu bar item Help  [8 children; closed]
";

/// The dashboard that read as 49 KB outlines in under 1.5 KB: two hundred
/// chart points and thirty-one rows are one line each, and closed menus show
/// only their titles and child counts.
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

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

/// A memories table as a web dashboard exposes it: each cell unlabelled, its
/// words in static text wrapped in a group, one cell holding a button.
fn memories_table(tokens: &Tokens, rows: usize) -> RawElement {
    let rows = (0..rows)
        .map(|index| {
            let cell = |text: &str| {
                tokens
                    .element("AXCell")
                    .with_children(vec![tokens.wrap(vec![tokens.text(text)])])
            };
            tokens.element("AXRow").with_children(vec![
                cell(&format!("Memory {index}")),
                cell("Maps each memory to its source"),
                cell("2 days ago"),
                tokens
                    .element("AXCell")
                    .with_children(vec![tokens.text("Open"), tokens.titled("AXButton", "Edit")]),
            ])
        })
        .collect();
    tokens.titled("AXTable", "Memories").with_children(rows)
}

fn window_with(table: RawElement, tokens: &Tokens) -> RawElement {
    tokens.titled("AXWindow", "Dashboard").with_children(vec![
        tokens.wrap(vec![table, tokens.titled("AXButton", "Refresh")])
    ])
}

#[test]
fn a_short_table_reads_row_by_row_with_each_cells_text_on_its_line() {
    let tokens = Tokens::new();
    let read = observe(vec![window_with(memories_table(&tokens, 6), &tokens)]);
    let outline = outline_of("Dashboard", &read);
    assert!(
        !outline.contains("cells (zoom") && !outline.contains("rows (zoom"),
        "{outline}"
    );
    let cells = outline
        .lines()
        .filter(|line| line.trim_start().split(' ').nth(1) == Some("cell"))
        .collect::<Vec<_>>();
    assert_eq!(cells.len(), 24, "{outline}");
    assert!(cells[0].ends_with(" cell Memory 0"), "{outline}");
    assert!(
        cells[1].ends_with(" cell Maps each memory to its source"),
        "{outline}"
    );
    assert!(cells[2].ends_with(" cell 2 days ago"), "{outline}");
    // A cell's button stays a line of its own beneath the cell, so it can
    // still be pressed by id; only the plain text joined the cell's line.
    assert!(cells[3].ends_with(" cell Open"), "{outline}");
    assert_eq!(outline.matches(" button Edit").count(), 6, "{outline}");
    assert_eq!(outline.matches(" text ").count(), 0, "{outline}");
}

#[test]
fn a_long_table_keeps_its_summary_and_the_outline_cap() {
    let tokens = Tokens::new();
    let read = observe(vec![window_with(memories_table(&tokens, 40), &tokens)]);
    let outline = outline_of("Dashboard", &read);
    assert!(
        outline.contains(" table Memories\n    40 rows (zoom: "),
        "{outline}"
    );
    assert!(!outline.contains("Memory 39"), "{outline}");
    // Zooming into one row prints its cells with their text.
    let row = &find(&read.roots, "Dashboard").children[0].children[0].children[5];
    let zoomed = zoom_of("Dashboard", &read, id(row));
    assert!(zoomed.contains(" cell Memory 5\n"), "{zoomed}");
    assert!(!zoomed.contains("cells (zoom"), "{zoomed}");
}

// ---------------------------------------------------------------------------
// A WebKit window: the page under a scroll area, next to the window buttons
// ---------------------------------------------------------------------------

/// The Magic Context dashboard as its Tauri build exposes it in WKWebView:
/// the page sits in a scroll area under the window, beside the window's own
/// buttons, and the application has a second, status-item menu bar.
/// `projects` is how many project buttons the main region lists.
fn tauri_dashboard(projects: usize) -> Vec<RawElement> {
    tauri_dashboard_with(projects, 0, 0)
}

/// [`tauri_dashboard`] with a banner of `banner_sections` named sections
/// ahead of the main region, each a few kilobytes' worth of outline lines
/// between them, and the main region wrapped in `named_wrappers` nested
/// named groups.
fn tauri_dashboard_with(
    projects: usize,
    banner_sections: usize,
    named_wrappers: usize,
) -> Vec<RawElement> {
    let t = Tokens::new();
    let control = |subrole: &str| t.element("AXButton").with_subrole(subrole);
    let mut themes = Vec::new();
    for (title, on) in [("Light", false), ("Dark", true), ("System", false)] {
        let mut check = t.titled("AXCheckBox", title);
        check.value = ElementValue::Number(if on { 1.0 } else { 0.0 });
        themes.push(check);
    }
    let mut navigation_items: Vec<RawElement> = [
        "Projects",
        "Workspaces",
        "Cache",
        "User Directives",
        "Config",
        "Logs",
    ]
    .iter()
    .map(|title| t.titled("AXButton", title))
    .collect();
    navigation_items.push(t.titled("AXGroup", "THEME").with_children(themes));
    let navigation = t
        .element("AXGroup")
        .with_subrole("AXLandmarkNavigation")
        .with_children(navigation_items);
    let mut heading = t.titled("AXHeading", "Projects");
    heading.value = ElementValue::Number(1.0);
    let mut search = t.element("AXTextField");
    search.value_settable = true;
    let mut main_items = vec![
        heading,
        t.text("42 tracked"),
        t.titled("AXButton", "↻ Refresh"),
        search,
    ];
    main_items.extend((0..projects).map(|index| {
        t.titled(
            "AXButton",
            &format!("project-{index:02} · /Users/me/Work/project-{index:02} · 1,204 memories"),
        )
    }));
    let main = t
        .element("AXGroup")
        .with_subrole("AXLandmarkMain")
        .with_children(main_items);
    let main = (0..named_wrappers).fold(main, |inner, level| {
        let mut children = vec![inner];
        for action in ["Collapse", "Expand", "Pin"] {
            children.push(t.titled(
                "AXButton",
                &format!(
                    "{action} the layout level {level} pane, which holds every panel below it and keeps its size"
                ),
            ));
        }
        t.titled("AXGroup", &format!("Layout level {level}"))
            .with_children(children)
    });
    // Sections alternate between a group and a list, so no two neighbours
    // share a role and the outline names each one on its own line.
    let banner = t
        .element("AXGroup")
        .with_subrole("AXLandmarkBanner")
        .with_children(
            (0..banner_sections)
                .map(|section| {
                    t.titled(
                        if section % 2 == 0 { "AXGroup" } else { "AXList" },
                        &format!("Announcement {section:02}: a release note long enough to fill its line"),
                    )
                    .with_children(
                        (0..5)
                            .map(|index| {
                                t.titled(
                                    "AXButton",
                                    &format!("Action {index} of announcement {section:02}, with a long accessible name"),
                                )
                            })
                            .collect(),
                    )
                })
                .collect(),
        );
    let footer = t
        .element("AXGroup")
        .with_subrole("AXLandmarkContentInfo")
        .with_children(
            [
                "DB",
                "7208.9 MB",
                "Memories",
                "17927",
                "Compartments",
                "11834",
                "Notes",
                "3170",
                "Version",
                "0.9.4",
            ]
            .iter()
            .map(|text| t.text(text))
            .collect(),
        );
    let web = t
        .titled("AXWebArea", "Magic Context Dashboard")
        .with_url("tauri://localhost")
        .with_children(if banner_sections > 0 {
            vec![banner, navigation, main, footer]
        } else {
            vec![navigation, main, footer]
        });
    let scroll = t.element("AXScrollArea").with_children(vec![web]);
    let mut window = t.titled("AXWindow", "Magic Context").with_children(vec![
        scroll,
        control("AXCloseButton"),
        control("AXFullScreenButton"),
        control("AXMinimizeButton"),
    ]);
    window.main_window = true;
    window.focused_window = true;
    let closed = |title: &str, items: usize| {
        let mut menu = t.element("AXMenu");
        menu.closed_menu_children = items;
        t.titled("AXMenuBarItem", title).with_children(vec![menu])
    };
    let menu_bar = t.element("AXMenuBar").with_children(vec![
        closed("Apple", 21),
        closed("Magic Context Dashboard", 9),
        closed("Edit", 11),
    ]);
    let extras = t.element("AXMenuBar").with_children(vec![closed("", 4)]);
    vec![window, menu_bar, extras]
}

const TAURI_OUTLINE: &str = "\
Magic Context Dashboard · window \"Magic Context\" · tauri://localhost
kq4 navigation
  kq5 button Projects
  kq6 button Workspaces
  kq7 button Cache
  kq8 button User Directives
  kq9 button Config
  kq10 button Logs
  kq11 group THEME
    kq12 check box Light
    kq13 check box (checked) Dark
    kq14 check box System
kq15 main
  kq16 heading Projects, Value: 1
  kq17 text 42 tracked
  kq18 button ↻ Refresh
  kq19 text field (settable)
  42 buttons, like \"project-00 · /Users/me/Work/project-00 ·…\" (zoom: kq15)
kq62 content info
  kq63 text DB
  kq64 text 7208.9 MB
  kq65 text Memories
  kq66 text 17927
  kq67 text Compartments
  kq68 text 11834
  kq69 text Notes
  kq70 text 3170
  kq71 text Version
  kq72 text 0.9.4
kq73 close button
kq74 full screen button
kq75 minimize button
kq76 menu bar
  kq77 menu bar item Apple  [21 children; closed]
  kq79 menu bar item Magic Context Dashboard  [9 children; closed]
  kq81 menu bar item Edit  [11 children; closed]
kq83 menu bar
  kq84 menu bar item  [4 children; closed]
";

/// The page under a WebKit window's scroll area is the outline: the scroll
/// area and the web area are looked through (the header names the page by
/// its address), and the navigation, the main region with its project
/// buttons counted, and the footer come before the window's own buttons
/// and the menu bars.
#[test]
fn a_webkit_window_outlines_the_page_beneath_its_scroll_area() {
    let read = observe(tauri_dashboard(42));
    assert_eq!(outline_of("Magic Context Dashboard", &read), TAURI_OUTLINE);
}

fn bounded_outline_of(read: &SessionRead, limit: usize) -> String {
    super::super::render::render_state_bounded(
        &StateHeader {
            app_name: "Magic Context Dashboard",
            focused_element_id: None,
        },
        &read.roots,
        &StateRequest::default(),
        limit,
    )
    .text
}

/// The line the main region of [`tauri_dashboard_with`] gets when the outline
/// has no room left to print it: its id and a count of what it holds.
const SUMMARISED_MAIN: &str = "\nkq376 main  [46 elements, like \"Projects\", ~208 B]\n";

/// A banner ahead of the main region spends the outline's whole budget. The
/// main region is still there, as one line with its count and an id to zoom
/// into, after which the outline says what it cut.
#[test]
fn an_outline_past_its_budget_still_summarises_the_main_region() {
    let read = observe(tauri_dashboard_with(42, 60, 0));
    let outline = outline_of("Magic Context Dashboard", &read);
    assert!(outline.contains(SUMMARISED_MAIN), "{outline}");
    assert!(
        outline.ends_with("outline elements cut (menus and sidebars after main content); zoom or filter to see the rest\n"),
        "{outline}"
    );
    assert!(!outline.contains("menu bar item"), "{outline}");
}

/// An action reply that shows a replaced page as an outline has less room
/// than a read; the main region keeps its line there too, because the
/// outline stops short of the reply's bound to leave room for it.
#[test]
fn an_action_replys_outline_keeps_room_for_the_main_region() {
    let read = observe(tauri_dashboard_with(42, 60, 0));
    let outline = bounded_outline_of(&read, MAX_DIFF_BYTES - 32);
    assert!(outline.contains(SUMMARISED_MAIN), "{outline}");
    assert!(outline.len() < MAX_DIFF_BYTES, "{} bytes", outline.len());
}

/// A main region nested below more named regions than the outline opens is
/// still named, under the innermost region shown.
#[test]
fn a_main_region_below_the_deepest_region_shown_is_still_named() {
    let read = observe(tauri_dashboard_with(42, 0, 3));
    let outline = outline_of("Magic Context Dashboard", &read);
    assert!(
        outline.contains("\n    kq17 group Layout level 0  ["),
        "{outline}"
    );
    assert!(
        outline.contains("\n      kq18 main  [46 elements, like \"Projects\", ~202 B]\n"),
        "{outline}"
    );
}
