# ck-cerebellum

Browser and desktop control for CortexKit agents.

Cerebellum lets an agent use a web browser and desktop applications on your
computer, under approvals you give. It runs as a module of the CortexKit daemon
(`ck-subc`), talks only over the daemon's wire, and holds no credentials of its
own. Agents see two tools: `browser_use` and `computer_use`.

## What it does

**The agent's own browser.** Cerebellum starts your installed Chrome-family
browser with a profile of its own for each agent, and drives it over the
DevTools protocol through an inherited pipe, never a debugging port. A login you
set up once in an agent's profile stays there. Actions: open and close the
browser, open and claim tabs, navigate, read the page as an outline, take
screenshots, scroll, click, type, fill a saved login from your vault, and hand
a sign-in page to you and take it back.

**Your own Chrome.** With the CortexKit Chrome extension installed, you can
hand a tab to an agent by moving it into the extension's Agent group. The agent
works only in tabs you hand over.

**Desktop applications.** Cerebellum reads an application's accessibility tree
and acts on it: press a button or menu item, write text into a field, type,
send key shortcuts, open and list applications, and wait for a condition. Most
actions run in the background without bringing the application to the front.
Where an action needs the application in front (some shortcuts, a picture of a
covered window), cerebellum brings it forward briefly and puts your application
back within a fixed time limit. Pointer actions that take over your mouse
("takeover" move, scroll, click and drag) need your approval for each action
and stop the moment you touch the mouse or keyboard.

## Approvals

Nothing runs on its own authority. Every browser site and every desktop
application needs your approval first, and you give it on an approval card in
the CortexKit apps. Approvals are scoped to a site or an application and a
level of action, and can be time-limited. Sign-in and payment forms, local
network addresses, and actions that make lasting changes always need a specific
approval. Cerebellum refuses to type into password and payment fields, and
refuses key combinations that would end your session. You can revoke any
approval from the apps.

Every action is written to an audit journal before it runs, so an interrupted
action leaves a record. The journal never stores typed text, page text or
screen text.

## Platforms

| | Agent's browser | Your Chrome | Desktop applications |
| --- | --- | --- | --- |
| macOS | Yes | Yes | Yes |
| Linux | Yes | Not yet | Not yet |
| Windows | Not yet | Not yet | Not yet |

On macOS, desktop control needs Accessibility, Screen Recording and Input
Monitoring permission for `ck-cerebellum`, granted in System Settings.

## Installing

Cerebellum is installed with the CortexKit daemon by `ck setup`. It needs a
Chrome-family browser installed, and the CortexKit apps to answer approval
cards. To let agents use your own Chrome, also install the CortexKit Chrome
extension.

## Building

    git clone https://github.com/cortexkit/cerebellum.git
    cd cerebellum && cargo build --locked

Dependencies come from crates.io at exact versions; no other checkout is
needed. Desktop control is advertised only by builds that carry the security
review stamps that `scripts/release-build.sh` adds at compile time, so a plain
development build offers the browser tools only.

## Layout

    crates/cerebellum            module binary: wire loop, both tools, browser control
    crates/cerebellum-core       shared pieces: identity, approvals, health, journal storage
    crates/cerebellum-computer   desktop control, independent of the operating system
    crates/cerebellum-ability    read-only calendar, contacts and mail readers (in development)
    crates/cerebellum-macos      macOS system calls
    crates/cerebellum-linux      Linux system calls
    crates/cerebellum-windows    Windows system calls
    crates/cerebellum-bridge-protocol  messages between the Chrome extension and the module
    crates/cerebellum-native-host  bridge between the Chrome extension and the module
    extension/                   the CortexKit Chrome extension

## Contributing

Open an issue first (`bug` or `design discussion`) and wait for a go before
sending a pull request. Details in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE).
