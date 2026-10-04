"""Headless CDP mechanism probe; uses only a throwaway profile and local HTTP."""
import base64
import http.server
import json
import os
import socket
import struct
import subprocess
import tempfile
import threading
import time
import urllib.request


class CDP:
    def __init__(self, url):
        from urllib.parse import urlparse
        u = urlparse(url)
        self.sock = socket.create_connection((u.hostname, u.port), timeout=10)
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall((f"GET {u.path} HTTP/1.1\r\nHost: {u.netloc}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        header = b""
        while not header.endswith(b"\r\n\r\n"):
            header += self.sock.recv(1)
        assert header.startswith(b"HTTP/1.1 101 "), header
        self.seq = 0
        self.events = []

    def read(self, n):
        data = b""
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise RuntimeError("CDP socket closed")
            data += chunk
        return data

    def receive(self):
        a, b = self.read(2)
        size = b & 127
        if size == 126:
            size = struct.unpack("!H", self.read(2))[0]
        elif size == 127:
            size = struct.unpack("!Q", self.read(8))[0]
        return json.loads(self.read(size))

    def call(self, method, params=None, session=None):
        self.seq += 1
        msg = dict(id=self.seq, method=method, params=params or {})
        if session:
            msg["sessionId"] = session
        data = json.dumps(msg).encode()
        mask = os.urandom(4)
        prefix = bytes([129, 128 | len(data)]) if len(data) < 126 else bytes([129, 254]) + struct.pack("!H", len(data))
        self.sock.sendall(prefix + mask + bytes(c ^ mask[i % 4] for i, c in enumerate(data)))
        while True:
            reply = self.receive()
            if reply.get("id") == self.seq:
                if "error" in reply:
                    raise RuntimeError(f"{method}: {reply['error']}")
                return reply.get("result", {})
            self.events.append(reply)


def run():
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/":
                body = f'''<iframe style="position:absolute;left:0;top:0" src="/same"></iframe><iframe style="position:absolute;left:320px;top:0" src="http://127.0.0.1:{other.server_port}/cross"></iframe><iframe style="position:absolute;left:640px;top:0" src="http://localhost:{other.server_port}/oop"></iframe><div id="shadow" role="button" style="position:absolute;left:0;top:180px;padding:12px"></div><script>shadow.attachShadow({{mode:'open'}}).innerHTML='<span>Shadow menu link</span>';</script>'''
            else:
                body = '<button id="inside">Frame button</button><a href="/next">Frame link</a><input autocomplete="cc-number">'
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    top = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    other = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    for server in (top, other):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    chrome = os.environ.get("CK_CHROME", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
    with tempfile.TemporaryDirectory(prefix="ck-iframe-", dir="/tmp") as profile:
        proc = subprocess.Popen([chrome, "--headless=new", "--remote-debugging-port=0", "--no-first-run", "--no-default-browser-check", f"--user-data-dir={profile}", "about:blank"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 20
            path = os.path.join(profile, "DevToolsActivePort")
            while not os.path.exists(path):
                if time.monotonic() > deadline:
                    raise RuntimeError("Chrome did not start")
                time.sleep(.05)
            with open(path) as f:
                port = int(f.readline())
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/version") as f:
                version = json.load(f)
            c = CDP(version["webSocketDebuggerUrl"])
            print("browser:", c.call("Browser.getVersion")["product"])
            target = c.call("Target.createTarget", {"url": "about:blank"})["targetId"]
            session = c.call("Target.attachToTarget", {"targetId": target, "flatten": True})["sessionId"]
            def call(method, params=None):
                return c.call(method, params, session)
            call("Page.enable")
            call("Target.setAutoAttach", {"autoAttach": True, "waitForDebuggerOnStart": False, "flatten": True})
            call("Page.navigate", {"url": f"http://127.0.0.1:{top.server_port}/"})
            for _ in range(100):
                tree = call("Page.getFrameTree")["frameTree"]
                if len(tree.get("childFrames", [])) == 3 and all(ch['frame'].get('url', '').startswith('http') for ch in tree['childFrames']) and call('Runtime.evaluate', {'expression': 'document.readyState'})['result']['value'] == 'complete':
                    break
                time.sleep(.05)
            call("DOM.enable")
            dom = call("DOM.getFlattenedDocument", {"depth": -1, "pierce": True})
            call("Accessibility.enable")
            root = call("Accessibility.getRootAXNode")["node"]
            print("main AX root frame:", root.get("frameId"))
            children = call("Accessibility.getChildAXNodes", {"id": root["nodeId"]})["nodes"]
            print("AX descendants from main root:", [(n.get("role", {}).get("value"), n.get("name", {}).get("value"), len(n.get("childIds", []))) for n in children])
            count = sum("inside" in n.get("attributes", []) for n in dom["nodes"])
            assert count == 2, f'parent session should expose two same-process frames, found {count}'
            print("parent flattened DOM frame buttons:", count)
            attached = [e["params"] for e in c.events if e.get("method") == "Target.attachedToTarget" and e.get("sessionId") == session]
            print("OOPIF attached sessions:", [(e["targetInfo"]["url"], e["sessionId"]) for e in attached])
            assert attached, "cross-site localhost frame must create an OOPIF"
            for e in attached:
                sub = e["sessionId"]
                c.call("Target.setAutoAttach", {"autoAttach": True, "waitForDebuggerOnStart": False, "flatten": True}, sub)
                c.call("DOM.enable", session=sub)
                subdom = c.call("DOM.getFlattenedDocument", {"depth": -1, "pierce": True}, sub)
                assert any("inside" in n.get("attributes", []) for n in subdom["nodes"])
                print("OOPIF session exposes frame button: PASS")
                remote_frame = c.call('Page.getFrameTree', session=sub)['frameTree']['frame']['id']
                owner = call('DOM.getFrameOwner', {'frameId':remote_frame})
                print('OOPIF owner content quad:', call('DOM.getContentQuads', {'backendNodeId':owner['backendNodeId']}))
                print('OOPIF visual viewport:', c.call('Page.getLayoutMetrics', session=sub).get('cssVisualViewport'))
                print('OOPIF local hit:', c.call('DOM.getNodeForLocation', {'x':20,'y':25,'includeUserAgentShadowDOM':True}, sub))
                c.call('Runtime.evaluate', {'expression': 'window.clicks=0;inside.onclick=()=>window.clicks++'}, sub)
                for kind in ('mousePressed', 'mouseReleased'):
                    c.call('Input.dispatchMouseEvent', {'type':kind,'x':20,'y':25,'button':'left','clickCount':1}, sub)
                print('OOPIF own-session click count:', c.call('Runtime.evaluate', {'expression':'window.clicks'}, sub)['result'].get('value'))
                for kind in ('mousePressed', 'mouseReleased'):
                    call('Input.dispatchMouseEvent', {'type':kind,'x':660,'y':25,'button':'left','clickCount':1})
                print('OOPIF parent-session global point count:', c.call('Runtime.evaluate', {'expression':'window.clicks'}, sub)['result'].get('value'))
            for x in (30, 345, 660):
                hit = call("DOM.getNodeForLocation", {"x": x, "y": 25, "includeUserAgentShadowDOM": True})
                present = any(n["backendNodeId"] == hit["backendNodeId"] for n in dom["nodes"])
                if x != 660:
                    assert present, f'same-process frame hit {x} missing from parent DOM'
                elif present:
                    owner = next(n for n in dom['nodes'] if n.get('localName') == 'iframe' and any('localhost' in str(a) for a in n.get('attributes', [])))
                    assert hit['backendNodeId'] == owner['backendNodeId'], 'remote hit must be either the iframe owner or a node absent from parent DOM'
                print("frame hit", x, "present in parent DOM:", present, "frame:", hit.get("frameId"))
            node = next(n for n in dom["nodes"] if "shadow" in n.get("attributes", []))
            backend = node["backendNodeId"]
            call("DOM.scrollIntoViewIfNeeded", {"backendNodeId": backend})
            quad = call("DOM.getContentQuads", {"backendNodeId": backend})["quads"][0]
            x, y = sum(quad[::2]) / 4, sum(quad[1::2]) / 4
            hit = call("DOM.getNodeForLocation", {"x": round(x), "y": round(y), "includeUserAgentShadowDOM": True})
            described = call("DOM.describeNode", {"backendNodeId": backend, "depth": -1, "pierce": True})["node"]
            def contains(n, shadow=False):
                return n["backendNodeId"] == hit["backendNodeId"] or any(contains(ch, shadow) for key in (("children", "shadowRoots") if shadow else ("children",)) for ch in n.get(key, []))
            assert not contains(described) and contains(described, True)
            call("Runtime.evaluate", {"expression": "window.clicked=0; shadow.onclick=()=>window.clicked++"})
            for kind in ("mousePressed", "mouseReleased"):
                call("Input.dispatchMouseEvent", {"type": kind, "x": x, "y": y, "button": "left", "clickCount": 1})
            assert call("Runtime.evaluate", {"expression": "window.clicked"})["result"]["value"] == 1
            print("interception reproduced: same center, same frame, shadow descendant omitted by children-only describe walk; point dispatch clicks: PASS")
            print("mechanism assertions: 5 groups passed")
        finally:
            proc.terminate()
            proc.wait(timeout=10)
            top.shutdown()
            other.shutdown()


if __name__ == "__main__":
    run()
