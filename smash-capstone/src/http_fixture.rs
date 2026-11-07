//! Deterministic, std-only loopback HTTP/1.1 fixture for the M3 capstones.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MAX_REQUEST_BYTES: usize = 8192;
const IO_TIMEOUT: Duration = Duration::from_millis(500);
const CREDENTIAL: &str = "Bearer fixture-secret-not-real";
const FAILURE_BODY: &str = "{\"accepted\":false}";

/// Selects the intended duplicate-effect behavior of the commit endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlVariant {
    /// A new valid commit records two effects.
    Broken,
    /// A new valid commit records one effect.
    Fixed,
}

/// A serial loopback HTTP server which shuts down when dropped.
pub struct HttpFixture {
    local_addr: SocketAddr,
    origin: String,
    variant: ControlVariant,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl HttpFixture {
    /// Bind an ephemeral loopback port and start serving requests.
    pub fn start(variant: ControlVariant) -> std::io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let local_addr = listener.local_addr()?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = thread::Builder::new()
            .name("smash-http-fixture".into())
            .spawn(move || run(listener, worker_stop, variant))?;

        Ok(Self {
            local_addr,
            origin: format!("http://{local_addr}"),
            variant,
            stop,
            worker: Some(worker),
        })
    }

    /// The HTTP origin, without a trailing slash.
    pub fn origin(&self) -> String {
        self.origin.clone()
    }

    /// The bound loopback address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The behavior selected at startup.
    pub fn variant(&self) -> ControlVariant {
        self.variant
    }
}

impl Drop for HttpFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        // Wake a worker blocked in accept. The nonblocking listener also bounds accept.
        let _ = TcpStream::connect_timeout(&self.local_addr, Duration::from_millis(100));
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[derive(Clone, Copy)]
struct Attempt {
    effect_count: u64,
    authorized: bool,
}

fn run(listener: TcpListener, stop: Arc<AtomicBool>, variant: ControlVariant) {
    let mut attempts = BTreeMap::new();
    while !stop.load(Ordering::Acquire) {
        match listener.accept() {
            Ok((stream, _)) => serve(stream, variant, &mut attempts),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(_) => thread::sleep(Duration::from_millis(5)),
        }
    }
}

fn serve(mut stream: TcpStream, variant: ControlVariant, attempts: &mut BTreeMap<String, Attempt>) {
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let response = match read_request(&mut stream) {
        Ok(Some(request)) => route(request, variant, attempts),
        Ok(None) => return,
        Err(response) => response,
    };
    let headers = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        response.reason,
        response.body.len()
    );
    let _ = stream.write_all(headers.as_bytes());
    let _ = stream.write_all(response.body.as_bytes());
}

struct Response {
    status: u16,
    reason: &'static str,
    body: String,
}

impl Response {
    fn success(body: String) -> Self {
        Self {
            status: 200,
            reason: "OK",
            body,
        }
    }
}

fn failure(status: u16, reason: &'static str) -> Response {
    Response {
        status,
        reason,
        body: FAILURE_BODY.into(),
    }
}

fn bad_request() -> Response {
    failure(400, "Bad Request")
}

fn too_large() -> Response {
    failure(413, "Payload Too Large")
}

struct Head {
    method: String,
    target: String,
    headers: BTreeMap<String, String>,
    body_length: usize,
}

struct Request {
    head: Head,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> Result<Option<Request>, Response> {
    let deadline = Instant::now() + IO_TIMEOUT;
    let mut input = Vec::with_capacity(1024);
    let mut buffer = [0_u8; 1024];

    loop {
        if let Some(header_end) = find_header_end(&input) {
            let body_start = header_end + 4;
            let head = parse_head(&input[..header_end])?;
            let total = body_start
                .checked_add(head.body_length)
                .ok_or_else(too_large)?;
            if total > MAX_REQUEST_BYTES {
                return Err(too_large());
            }
            if input.len() > total {
                return Err(bad_request());
            }
            if input.len() == total {
                return Ok(Some(Request {
                    head,
                    body: input[body_start..].to_vec(),
                }));
            }
        } else if input.len() == MAX_REQUEST_BYTES {
            return Err(too_large());
        }

        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| failure(408, "Request Timeout"))?;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|_| bad_request())?;
        match stream.read(&mut buffer) {
            Ok(0) if input.is_empty() => return Ok(None),
            Ok(0) => return Err(bad_request()),
            Ok(count) => {
                input.extend_from_slice(&buffer[..count]);
                if input.len() > MAX_REQUEST_BYTES {
                    return Err(too_large());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                return Err(failure(408, "Request Timeout"));
            }
            Err(_) => return Err(bad_request()),
        }
    }
}

fn find_header_end(input: &[u8]) -> Option<usize> {
    input.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_head(input: &[u8]) -> Result<Head, Response> {
    let text = std::str::from_utf8(input).map_err(|_| bad_request())?;
    if !text.is_ascii() {
        return Err(bad_request());
    }
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or_else(bad_request)?;
    let mut parts = request_line.split(' ');
    let method = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(bad_request)?;
    let target = parts
        .next()
        .filter(|part| !part.is_empty())
        .ok_or_else(bad_request)?;
    if parts.next() != Some("HTTP/1.1") || parts.next().is_some() {
        return Err(bad_request());
    }

    let mut headers = BTreeMap::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or_else(bad_request)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || value
                .bytes()
                .any(|byte| (byte < b' ' && byte != b'\t') || byte == 0x7f)
        {
            return Err(bad_request());
        }
        let name = name.to_ascii_lowercase();
        let value = value.trim_matches([' ', '\t']).to_owned();
        if headers.insert(name, value).is_some() {
            return Err(bad_request());
        }
    }
    if headers.contains_key("transfer-encoding") {
        return Err(bad_request());
    }
    let body_length = match headers.get("content-length") {
        Some(value) if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) => {
            value.parse().map_err(|_| bad_request())?
        }
        Some(_) => return Err(bad_request()),
        None => 0,
    };

    Ok(Head {
        method: method.into(),
        target: target.into(),
        headers,
        body_length,
    })
}

fn route(
    request: Request,
    variant: ControlVariant,
    attempts: &mut BTreeMap<String, Attempt>,
) -> Response {
    let Request { head, body } = request;
    let (path, query) = match head.target.split_once('?') {
        Some((path, query)) if !query.contains('?') => (path, Some(query)),
        Some(_) => return bad_request(),
        None => (head.target.as_str(), None),
    };

    match (head.method.as_str(), path) {
        ("GET", "/v1/health") if head.body_length == 0 => match attempt_query(query) {
            Some(_) => Response::success("{\"ready\":true}".into()),
            None => bad_request(),
        },
        ("GET", "/v1/receipt") if head.body_length == 0 => {
            if head.headers.get("authorization").map(String::as_str) != Some(CREDENTIAL) {
                return failure(401, "Unauthorized");
            }
            let Some(attempt_id) = attempt_query(query) else {
                return bad_request();
            };
            let (effect_count, authorized) =
                attempts.get(&attempt_id).map_or((0, false), |attempt| {
                    (attempt.effect_count, attempt.authorized)
                });
            Response::success(format!(
                "{{\"effect_count\":{effect_count},\"authorized\":{authorized}}}"
            ))
        }
        ("POST", "/v1/commit") if query.is_none() => {
            if head.headers.get("authorization").map(String::as_str) != Some(CREDENTIAL) {
                return failure(401, "Unauthorized");
            }
            if head.headers.get("content-type").map_or(true, |value| {
                !value.eq_ignore_ascii_case("application/json")
            }) {
                return failure(415, "Unsupported Media Type");
            }
            let Some(attempt_id) = parse_commit_body(&body).filter(|id| valid_attempt_id(id))
            else {
                return bad_request();
            };
            attempts.entry(attempt_id).or_insert_with(|| Attempt {
                effect_count: match variant {
                    ControlVariant::Broken => 2,
                    ControlVariant::Fixed => 1,
                },
                authorized: true,
            });
            Response::success("{\"accepted\":true}".into())
        }
        _ => failure(404, "Not Found"),
    }
}

fn attempt_query(query: Option<&str>) -> Option<String> {
    let query = query?;
    if query.contains('&') {
        return None;
    }
    let (key, value) = query.split_once('=')?;
    if percent_decode(key)? != "attempt_id" {
        return None;
    }
    let attempt_id = percent_decode(value)?;
    valid_attempt_id(&attempt_id).then_some(attempt_id)
}

fn percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = hex(*bytes.get(index + 1)?)?;
            let low = hex(*bytes.get(index + 2)?)?;
            output.push(high * 16 + low);
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(output).ok()
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn valid_attempt_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn parse_commit_body(body: &[u8]) -> Option<String> {
    let mut parser = JsonParser { input: body, at: 0 };
    parser.whitespace();
    parser.expect(b'{')?;
    parser.whitespace();
    let mut attempt_id = None;
    if parser.consume(b'}') {
        return None;
    }
    loop {
        parser.whitespace();
        let key = parser.string()?;
        parser.whitespace();
        parser.expect(b':')?;
        parser.whitespace();
        let value = parser.string()?;
        if key != "attempt_id" || attempt_id.replace(value).is_some() {
            return None;
        }
        parser.whitespace();
        if parser.consume(b'}') {
            break;
        }
        parser.expect(b',')?;
    }
    parser.whitespace();
    (parser.at == body.len()).then_some(attempt_id)?
}

struct JsonParser<'a> {
    input: &'a [u8],
    at: usize,
}

impl JsonParser<'_> {
    fn whitespace(&mut self) {
        while self
            .input
            .get(self.at)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
        {
            self.at += 1;
        }
    }

    fn consume(&mut self, expected: u8) -> bool {
        if self.input.get(self.at) == Some(&expected) {
            self.at += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, expected: u8) -> Option<()> {
        self.consume(expected).then_some(())
    }

    fn string(&mut self) -> Option<String> {
        self.expect(b'"')?;
        let mut output = String::new();
        loop {
            let byte = *self.input.get(self.at)?;
            self.at += 1;
            match byte {
                b'"' => return Some(output),
                b'\\' => {
                    let escaped = *self.input.get(self.at)?;
                    self.at += 1;
                    let character = match escaped {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{0008}',
                        b'f' => '\u{000c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let mut value = 0_u32;
                            for _ in 0..4 {
                                value = value * 16 + u32::from(hex(*self.input.get(self.at)?)?);
                                self.at += 1;
                            }
                            let character = char::from_u32(value)?;
                            if !character.is_ascii() {
                                return None;
                            }
                            character
                        }
                        _ => return None,
                    };
                    output.push(character);
                }
                b' '..=b'~' => output.push(char::from(byte)),
                _ => return None,
            }
        }
    }
}
