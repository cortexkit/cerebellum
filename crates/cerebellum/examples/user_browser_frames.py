"""Hand-run-only headless CfT chrome.debugger diagnostic, not an automated gate.

Run: python3 crates/cerebellum/examples/user_browser_frames.py --chrome ABS_CFT
No native host or personal profile is used.
Raw events/replies contain only this process's loopback fixtures. This tests the
extension API, not the browser_use consent/native-host path. A 45s deadline and
process-group cleanup bound the run, including Chrome startup failures.
"""
import argparse
import http.server
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import threading
import time

from browser_iframe_mechanism import CDP


def run(chrome):
    extension = Path(__file__).resolve().parents[3] / "extension"

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = (f'<title>Frame diagnostic</title><input aria-label="Top input">'
                    f'<iframe title="Embedded probe" src="http://localhost:{self.server.server_port}/child"></iframe>'
                    if self.path == "/" else '<input aria-label="Iframe input">')
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *_):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    origin = f"http://127.0.0.1:{server.server_port}"
    with tempfile.TemporaryDirectory(prefix="ckub-frames-", dir=os.environ.get("TMPDIR", "/tmp")) as scratch:
        root = Path(scratch)
        env = os.environ.copy()
        for name, directory in [("HOME", "home"), ("TMPDIR", "tmp"),
                                ("XDG_DATA_HOME", "data"), ("XDG_CONFIG_HOME", "config"),
                                ("XDG_STATE_HOME", "state"), ("XDG_CACHE_HOME", "cache"),
                                ("XDG_RUNTIME_DIR", "runtime")]:
            (root / directory).mkdir(mode=0o700)
            env[name] = str(root / directory)
        profile = root / "profile"
        args = [str(chrome), "--headless=new", "--no-startup-window",
                "--use-mock-keychain", "--password-store=basic", "--no-first-run",
                "--no-default-browser-check", "--disable-background-networking",
                "--disable-component-update", "--disable-sync", "--metrics-recording-only",
                "--noerrdialogs", "--remote-debugging-port=0", "--remote-debugging-address=127.0.0.1",
                f"--user-data-dir={profile}", f"--load-extension={extension}",
                f"--disable-extensions-except={extension}"]
        with open(root / "stderr", "w+") as stderr:
            proc = subprocess.Popen(args, env=env, start_new_session=True,
                                    stdout=subprocess.DEVNULL, stderr=stderr)
            timer = threading.Timer(45, lambda: os.killpg(proc.pid, signal.SIGKILL))
            timer.start()
            try:
                deadline = time.monotonic() + 20
                port_file = profile / "DevToolsActivePort"
                while not port_file.exists():
                    if proc.poll() is not None or time.monotonic() > deadline:
                        stderr.seek(0)
                        raise RuntimeError("Chrome startup failed: " + stderr.read()[-4000:])
                    time.sleep(.05)
                port, path = port_file.read_text().splitlines()[:2]
                cdp = CDP(f"ws://127.0.0.1:{port}{path}")
                version = cdp.call("Browser.getVersion")
                print(json.dumps({"version": version}), flush=True)
                if not version["product"].endswith("/155.0.8059.39"):
                    raise RuntimeError("Only pinned CfT 155.0.8059.39 is supported")
                cdp.call("Target.createTarget", {"url": "about:blank", "background": True})
                while True:
                    targets = cdp.call("Target.getTargets")["targetInfos"]
                    worker = next((t for t in targets if t["type"] == "service_worker"
                                   and t["url"].startswith("chrome-extension://bfmlflnlaflnibiellpjjifdbcifciei/")), None)
                    if worker:
                        break
                    if time.monotonic() > deadline:
                        raise RuntimeError("Extension worker did not start")
                    time.sleep(.05)
                session = cdp.call("Target.attachToTarget", {"targetId": worker["targetId"], "flatten": True})["sessionId"]
                print(json.dumps({"worker_target": worker}), flush=True)
                # The worker target appears before Chrome installs its extension
                # bindings. Attaching successfully does not mean chrome exists yet.
                while True:
                    ready = cdp.call("Runtime.evaluate", {
                        "expression": "typeof chrome !== 'undefined' && !!chrome.debugger && !!chrome.tabs",
                        "returnByValue": True}, session)
                    if ready.get("result", {}).get("value") is True:
                        break
                    if time.monotonic() > deadline:
                        raise RuntimeError("Worker extension bindings did not appear: " + json.dumps(ready))
                    time.sleep(.05)
                # Module workers forbid dynamic import. Evaluate the same source
                # inline, stripping only module syntax, without changing shipped code.
                sources = (extension / "errors.mjs").read_text() + "\n" + "\n".join(
                    line for line in (extension / "frames.mjs").read_text().splitlines()
                    if not line.startswith("import "))
                expression = SCRIPT.replace("FRAME_IMPLEMENTATION", sources.replace("export ", ""))
                expression = expression.replace("FIXTURE_ORIGIN", json.dumps(origin))
                reply = cdp.call("Runtime.evaluate", {"expression": expression, "awaitPromise": True,
                                                     "returnByValue": True}, session)
                print(json.dumps({"worker_reply": reply}), flush=True)
                if "exceptionDetails" in reply:
                    raise RuntimeError("Diagnostic evaluation failed")
                trace = reply["result"]["value"]
                for row in trace:
                    print(json.dumps(row), flush=True)
                if any(row.get("kind") == "failure" for row in trace):
                    raise RuntimeError("Frame diagnostic failed; see raw trace")
            finally:
                timer.cancel()
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
                server.shutdown()


SCRIPT = r"""(async () => {
  FRAME_IMPLEMENTATION
  const trace = [];
  const record = (kind, data) => trace.push({kind, ...JSON.parse(JSON.stringify(data))});
  const send = chrome.debugger.sendCommand.bind(chrome.debugger);
  const navigation = chrome.webNavigation.getAllFrames.bind(chrome.webNavigation);
  chrome.debugger.sendCommand = async (target, method, params = {}) => {
    record('command', {target, method, params});
    try { const result = await send(target, method, params); record('reply', {target, method, result}); return result; }
    catch (error) { record('error', {target, method, error: String(error)}); throw error; }
  };
  chrome.webNavigation.getAllFrames = async params => {
    const result = await navigation(params); record('navigation', {params, result}); return result;
  };
  const listener = (source, method, params) => record('event', {source, method, params});
  chrome.debugger.onEvent.addListener(listener);
  let tab, frames;
  try {
    tab = await chrome.tabs.create({url: FIXTURE_ORIGIN, active: false});
    const deadline = Date.now() + 10000;
    while ((await chrome.tabs.get(tab.id)).status !== 'complete') {
      if (Date.now() > deadline) throw new Error('Fixture load deadline');
      await new Promise(resolve => setTimeout(resolve, 25));
    }
    await chrome.debugger.attach({tabId: tab.id}, '1.3');
    frames = new Frames(chrome, {tabId: tab.id}, async () => { await chrome.tabs.get(tab.id); });
    await frames.start();
    const result = await frames.read();
    record('mapped', result);
    const targets = [{tabId: tab.id}, ...frames.sessions.values()];
    for (const target of targets) {
      const tree = await chrome.debugger.sendCommand(target, 'Page.getFrameTree');
      for (const params of [{}, {frameId: tree.frameTree.frame.id}]) {
        await chrome.debugger.sendCommand(target, 'Accessibility.getFullAXTree', params);
      }
    }
    const child = result.mappings.find(frame => frame.parent_id);
    if (!child) throw new Error('OOPIF missing from mappings');
    const {target} = await frames.resolve(child);
    const ax = await chrome.debugger.sendCommand(target, 'Accessibility.getFullAXTree', {frameId: child.frame_id});
    if (!ax.nodes.some(node => node.name?.value === 'Iframe input')) throw new Error('OOPIF input absent');
    record('check', {name: 'mapped OOPIF session reads Iframe input', passed: true});
  } catch (error) {
    record('failure', {error: String(error)});
  } finally {
    frames?.close();
    if (tab) {
      await chrome.debugger.detach({tabId: tab.id}).catch(() => {});
      await chrome.tabs.remove(tab.id);
    }
    chrome.debugger.sendCommand = send;
    chrome.webNavigation.getAllFrames = navigation;
    chrome.debugger.onEvent.removeListener(listener);
  }
  return trace;
})()"""


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chrome", type=Path, required=True)
    options = parser.parse_args()
    if not options.chrome.is_absolute() or options.chrome.name != "Google Chrome for Testing":
        parser.error("--chrome must be the absolute pinned Chrome for Testing executable")
    run(options.chrome)
