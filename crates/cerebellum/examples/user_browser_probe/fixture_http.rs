//! Bounded HTTP/1 fixture serving shared by the live probe and socket controls.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub(super) type Reports = Arc<Mutex<(usize, String, String)>>;
const HEADER_LIMIT: usize = 16 * 1024;
const BODY_LIMIT: usize = 8 * 1024;

struct Request {
    method: String,
    target: String,
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid fixture HTTP request")
}

fn request_from(mut read: impl FnMut(&mut [u8]) -> io::Result<usize>) -> io::Result<Request> {
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 1024];
    let end = loop {
        if let Some(at) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break at + 4;
        }
        if bytes.len() == HEADER_LIMIT {
            return Err(invalid());
        }
        let limit = buffer.len().min(HEADER_LIMIT - bytes.len());
        let size = read(&mut buffer[..limit])?;
        if size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "incomplete fixture HTTP request",
            ));
        }
        bytes.extend_from_slice(&buffer[..size]);
    };
    let header = std::str::from_utf8(&bytes[..end]).map_err(|_| invalid())?;
    if !header.is_ascii() {
        return Err(invalid());
    }
    let mut lines = header.split("\r\n");
    let parts: Vec<_> = lines.next().ok_or_else(invalid)?.split(' ').collect();
    if parts.len() != 3
        || !matches!(parts[2], "HTTP/1.0" | "HTTP/1.1")
        || !parts[1].starts_with('/')
        || parts[1].bytes().any(|byte| byte <= b' ' || byte == 127)
    {
        return Err(invalid());
    }
    let request = Request {
        method: parts[0].into(),
        target: parts[1].into(),
    };
    let mut length = None;
    for line in lines.take_while(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or_else(invalid)?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(invalid());
        }
        if name.eq_ignore_ascii_case("content-length") {
            let value = value.trim();
            if length.is_some()
                || value.is_empty()
                || !value.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(invalid());
            }
            let parsed: usize = value.parse().map_err(|_| invalid())?;
            if parsed > BODY_LIMIT {
                return Err(invalid());
            }
            length = Some(parsed);
        }
    }
    let mut remaining = length.unwrap_or(0).saturating_sub(bytes.len() - end);
    while remaining != 0 {
        let limit = remaining.min(buffer.len());
        let size = read(&mut buffer[..limit])?;
        if size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "incomplete fixture HTTP body",
            ));
        }
        remaining -= size;
    }
    Ok(request)
}

fn page(target: &str, child_origin: &str) -> Option<String> {
    let body = match target {
        "/outside-secret" => "<!doctype html><title>OUTSIDE_SECRET</title><p>OUTSIDE_SECRET</p>",
        "/" => {
            r#"<!doctype html><meta charset="utf-8"><title>Local user browser probe</title><script>window.__clicks = 0</script><button aria-label="Probe button" onclick="window.__clicks++; navigator.sendBeacon('/click')">Probe button</button><input aria-label="Probe input" oninput="navigator.sendBeacon('/type?'+encodeURIComponent(this.value))"><iframe src="IFRAME_ORIGIN/iframe" title="Embedded probe"></iframe>"#
        }
        "/handed-active" | "/handed-background" => {
            r##"<!doctype html><meta charset="utf-8"><title>Handed fixture</title><script>window.__links=0;addEventListener('load',()=>scrollTo(0,900))</script><a style="position:fixed;left:8px;top:8px" href="#clicked" onclick="event.preventDefault(); window.__links++">Probe link</a><form style="position:fixed;left:8px;top:40px" method="post" action="/submitted"><button aria-label="Probe submit">Submit</button></form><div style="height:2000px"></div>"##
        }
        "/iframe" => {
            r#"<!doctype html><meta charset="utf-8"><title>Embedded probe</title><input aria-label="Iframe input" oninput="navigator.sendBeacon('/child-type?'+encodeURIComponent(this.value))">"#
        }
        _ => return None,
    };
    Some(body.replace("IFRAME_ORIGIN", child_origin))
}

fn serve_from(
    read: impl FnMut(&mut [u8]) -> io::Result<usize>,
    stream: &mut TcpStream,
    child_origin: &str,
    reports: &Reports,
) -> io::Result<()> {
    // A TCP read can stop anywhere, and Chrome can leave a preconnected socket
    // idle. Never send a page response until a complete request was received.
    let request = request_from(read)?;
    let (status, body) = if request.method == "GET" {
        match page(&request.target, child_origin) {
            Some(body) => ("200 OK", body),
            None => ("404 Not Found", "Unknown fixture route".into()),
        }
    } else if request.method == "POST" {
        let mut state = reports.lock().unwrap();
        if request.target == "/click" {
            state.0 += 1;
            ("204 No Content", String::new())
        } else if let Some(text) = request.target.strip_prefix("/type?") {
            state.1 = text.into();
            ("204 No Content", String::new())
        } else if let Some(text) = request.target.strip_prefix("/child-type?") {
            state.2 = text.into();
            ("204 No Content", String::new())
        } else {
            ("404 Not Found", "Unknown fixture route".into())
        }
    } else {
        (
            "405 Method Not Allowed",
            "Unsupported fixture method".into(),
        )
    };
    let method = match request.method.as_str() {
        "GET" => "GET",
        "POST" => "POST",
        _ => "other",
    };
    let route = match request.target.as_str() {
        "/" => "root",
        "/outside-secret" => "outside",
        "/iframe" => "iframe",
        "/handed-active" => "handed-active",
        "/handed-background" => "handed-background",
        "/click" => "click-beacon",
        target if target.starts_with("/type?") => "type-beacon",
        target if target.starts_with("/child-type?") => "child-type-beacon",
        _ => "unmatched",
    };
    // Route labels are fixed; do not print query strings containing typed data.
    eprintln!(
        "fixture HTTP: method={method} route={route} status={status} body_bytes={}",
        body.len()
    );
    stream.set_write_timeout(Some(Duration::from_secs(1)))?;
    write!(stream, "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())
}

pub(super) fn serve(
    stream: &mut TcpStream,
    child_origin: &str,
    reports: &Reports,
) -> io::Result<()> {
    // Normalize accepted sockets instead of relying on platform-specific mode inheritance.
    stream.set_nonblocking(false)?;
    let mut reader = stream.try_clone()?;
    let deadline = Instant::now() + Duration::from_secs(1);
    serve_from(
        |buffer| {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "fixture HTTP request deadline",
                ));
            }
            reader.set_read_timeout(Some(remaining))?;
            reader.read(buffer)
        },
        stream,
        child_origin,
        reports,
    )
}

fn exchange(request: &[u8]) -> Result<(String, (usize, String, String)), String> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
    let address = listener.local_addr().map_err(|error| error.to_string())?;
    let reports: Reports = Arc::new(Mutex::new((0, String::new(), String::new())));
    let state = Arc::clone(&reports);
    let server = std::thread::spawn(move || -> io::Result<()> {
        let (mut stream, _) = listener.accept()?;
        stream.set_nonblocking(true)?;
        serve(&mut stream, "http://localhost:12345", &state)
    });
    let mut client = TcpStream::connect(address).map_err(|error| error.to_string())?;
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| error.to_string())?;
    client
        .write_all(request)
        .map_err(|error| error.to_string())?;
    client
        .shutdown(std::net::Shutdown::Write)
        .map_err(|error| error.to_string())?;
    let mut response = String::new();
    let read = client.read_to_string(&mut response);
    let served = server
        .join()
        .map_err(|_| "fixture server control panicked")?;
    read.map_err(|error| error.to_string())?;
    served.map_err(|error| error.to_string())?;
    let reports = reports.lock().unwrap().clone();
    Ok((response, reports))
}

fn fragmented_background_get() -> Result<(), String> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
    let address = listener.local_addr().map_err(|error| error.to_string())?;
    let (read_tx, read_rx) = std::sync::mpsc::channel();
    let (written_tx, written_rx) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || -> io::Result<()> {
        let (mut stream, _) = listener.accept()?;
        let mut reader = stream.try_clone()?;
        reader.set_read_timeout(Some(Duration::from_secs(2)))?;
        let reports = Arc::new(Mutex::new((0, String::new(), String::new())));
        let mut first = true;
        serve_from(
            |buffer| {
                let size = reader.read(buffer)?;
                if first {
                    first = false;
                    read_tx.send(()).map_err(|_| invalid())?;
                    written_rx
                        .recv_timeout(Duration::from_secs(2))
                        .map_err(|_| invalid())?;
                }
                Ok(size)
            },
            &mut stream,
            "http://localhost:12345",
            &reports,
        )
    });
    let mut client = TcpStream::connect(address).map_err(|error| error.to_string())?;
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| error.to_string())?;
    client
        .write_all(b"GET /handed-back")
        .map_err(|error| error.to_string())?;
    read_rx
        .recv_timeout(Duration::from_secs(2))
        .map_err(|error| error.to_string())?;
    // The server's first read has already returned the prefix. Do not rely on
    // TCP packet boundaries or a sleep to force the request-line split.
    client
        .write_all(b"ground HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .map_err(|error| error.to_string())?;
    written_tx.send(()).map_err(|error| error.to_string())?;
    let mut response = String::new();
    let read = client.read_to_string(&mut response);
    let served = server
        .join()
        .map_err(|_| "fragmented fixture control panicked")?;
    read.map_err(|error| error.to_string())?;
    served.map_err(|error| error.to_string())?;
    if !response.starts_with("HTTP/1.1 200 OK\r\n")
        || !response.contains("Probe link")
        || !response.contains("Probe submit")
    {
        return Err("fragmented background GET did not receive the complete handed fixture".into());
    }
    Ok(())
}

fn idle_preconnect() -> Result<(), String> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").map_err(|error| error.to_string())?;
    let address = listener.local_addr().map_err(|error| error.to_string())?;
    let server = std::thread::spawn(move || -> io::Result<bool> {
        let (mut stream, _) = listener.accept()?;
        let mut reader = stream.try_clone()?;
        reader.set_read_timeout(Some(Duration::from_millis(20)))?;
        let reports = Arc::new(Mutex::new((0, String::new(), String::new())));
        Ok(serve_from(
            |buffer| reader.read(buffer),
            &mut stream,
            "http://localhost:12345",
            &reports,
        )
        .is_err())
    });
    let mut client = TcpStream::connect(address).map_err(|error| error.to_string())?;
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| error.to_string())?;
    let mut response = Vec::new();
    let read = client.read_to_end(&mut response);
    let rejected = server
        .join()
        .map_err(|_| "idle fixture control panicked")?
        .map_err(|error| error.to_string())?;
    read.map_err(|error| error.to_string())?;
    if !rejected || !response.is_empty() {
        return Err("idle preconnect received an unsolicited fixture response".into());
    }
    Ok(())
}

fn routes_and_beacons() -> Result<(), String> {
    for request in [
        b"GET /missing HTTP/1.1\r\nHost: localhost\r\n\r\n".as_slice(),
        b"POST /submitted HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
        b"GET /click HTTP/1.1\r\nHost: localhost\r\n\r\n",
    ] {
        let (response, reports) = exchange(request)?;
        if !response.starts_with("HTTP/1.1 404 Not Found\r\n")
            || response.ends_with("\r\n\r\nok")
            || reports.0 != 0
        {
            return Err(
                "unknown route or navigation to a beacon masqueraded as a fixture page".into(),
            );
        }
    }
    let (response, reports) =
        exchange(b"POST /click HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\ndata")?;
    if !response.starts_with("HTTP/1.1 204 No Content\r\n")
        || !response.ends_with("\r\n\r\n")
        || reports.0 != 1
    {
        return Err("beacon response or declared-body handling changed".into());
    }
    Ok(())
}

pub(super) fn controls() -> Vec<(&'static str, Result<(), String>)> {
    vec![
        (
            "fixture_http_fragmented_background_get",
            fragmented_background_get(),
        ),
        (
            "fixture_http_idle_preconnect_has_no_response",
            idle_preconnect(),
        ),
        (
            "fixture_http_routes_and_beacons_are_distinct",
            routes_and_beacons(),
        ),
    ]
}
