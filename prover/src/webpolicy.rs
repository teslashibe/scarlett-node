//! Policy for proven web fetches (`web.fetch`, policy `web-relay-v1`).
//!
//! A web job names one public https URL. The verifier is the TLS client for
//! each hop through the supplier's connection, as for keyed X reads, but a
//! public page carries no secret: the request has no hidden bytes and the
//! supplier never receives the page. The verifier authorizes exactly the
//! request bytes `request` builds for the hop URL, and a later hop only for
//! the canonical `Location` of the previous verified redirect.
//!
//! The URL rules here are the "strict" rules every implementation shares
//! (`api/web-vectors.json`). The response is framed incrementally and kept
//! still content-encoded; decoding and rendering happen in the app.

use std::{fmt, time::Duration};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const WEB_POLICY: &str = "web-relay-v1";
pub const PAYLOAD_TYPE: &str = "web.fetch";
pub const MAX_REDIRECTS: usize = 5;
pub const MAX_URL: usize = 2048;
/// Decrypted response bytes per hop, heads and chunk framing included.
pub const MAX_RESPONSE: usize = 10 << 20;
/// All response heads of one hop, interim 1xx heads included.
pub const MAX_HEAD: usize = 64 << 10;
const MAX_TRAILERS: usize = 8 << 10;
const MAX_CHUNK_LINE: usize = 4 << 10;
/// Longest a single hop's session may run on either side.
pub const HOP_LIMIT: Duration = Duration::from_secs(30);
/// Payload header names in the only order they may appear, and their wire spelling.
const HEADERS: [(&str, &str); 3] = [("user-agent", "User-Agent"), ("accept", "Accept"), ("accept-language", "Accept-Language")];
const MAX_HEADER_VALUE: usize = 512;
const X_HOSTS: [&str; 2] = ["x.com", "twitter.com"];
const RESERVED: [&str; 9] = ["localhost", "local", "internal", "home.arpa", "lan", "localdomain", "onion", "invalid", "test"];
/// Statuses whose `Location` the verifier follows.
pub const REDIRECTS: [u16; 5] = [301, 302, 303, 307, 308];

/// Why a URL is not a fetchable canonical https URL, or a redirect not followable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UrlError {
    Scheme,
    Userinfo,
    Port,
    IpLiteral,
    Host,
    XHost,
    TooLong,
    Invalid,
    /// Redirects only: an empty `Location`.
    Empty,
    /// Redirects only: a `Location` that leaves https.
    Insecure,
}

impl UrlError {
    pub const ALL: [Self; 10] = [Self::Scheme, Self::Userinfo, Self::Port, Self::IpLiteral, Self::Host, Self::XHost, Self::TooLong, Self::Invalid, Self::Empty, Self::Insecure];

    pub fn code(self) -> &'static str {
        match self {
            Self::Scheme => "scheme",
            Self::Userinfo => "userinfo",
            Self::Port => "port",
            Self::IpLiteral => "ip_literal",
            Self::Host => "host",
            Self::XHost => "x_host",
            Self::TooLong => "too_long",
            Self::Invalid => "invalid",
            Self::Empty => "empty",
            Self::Insecure => "insecure",
        }
    }
}

impl fmt::Display for UrlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "URL refused: {}", self.code())
    }
}

impl std::error::Error for UrlError {}

/// Whether `host` is X's, which web jobs never fetch.
pub fn x_host(host: &str) -> bool {
    X_HOSTS.iter().any(|x| host == *x || host.strip_suffix(x).is_some_and(|rest| rest.ends_with('.')))
}

fn reserved(host: &str) -> bool {
    RESERVED.iter().any(|r| host == *r || host.strip_suffix(r).is_some_and(|rest| rest.ends_with('.')))
}

/// Splits `scheme://authority<tail>`; the scheme comes back lowercased.
fn split(url: &str) -> Result<(String, &str, &str), UrlError> {
    let colon = url.find(':').ok_or(UrlError::Invalid)?;
    let scheme = &url[..colon];
    if !scheme_like(scheme) {
        return Err(UrlError::Invalid);
    }
    let rest = url[colon + 1..].strip_prefix("//").ok_or(UrlError::Invalid)?;
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    Ok((scheme.to_ascii_lowercase(), &rest[..end], &rest[end..]))
}

fn scheme_like(scheme: &str) -> bool {
    let mut bytes = scheme.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_alphabetic()) && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'.' | b'-'))
}

/// A canonical host name, or why the authority's host is not one.
fn host(raw: &str) -> Result<String, UrlError> {
    if raw.starts_with('[') {
        return Err(UrlError::IpLiteral);
    }
    if !raw.is_ascii() {
        return Err(UrlError::Host);
    }
    let mut host = raw.to_ascii_lowercase();
    if host.ends_with('.') {
        host.pop();
    }
    let last = host.rsplit('.').next().unwrap_or_default();
    if (!last.is_empty() && last.bytes().all(|b| b.is_ascii_digit()))
        || last.starts_with("0x")
        || (!host.is_empty() && host.bytes().all(|b| b.is_ascii_digit() || b == b'.'))
    {
        return Err(UrlError::IpLiteral);
    }
    let labels: Vec<&str> = host.split('.').collect();
    if host.is_empty() || host.len() > 253 || labels.len() < 2 {
        return Err(UrlError::Host);
    }
    let label_ok = |l: &&str| {
        (1..=63).contains(&l.len()) && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') && !l.starts_with('-') && !l.ends_with('-')
    };
    if !labels.iter().all(label_ok) || !last.bytes().any(|b| b.is_ascii_lowercase()) || reserved(&host) {
        return Err(UrlError::Host);
    }
    if x_host(&host) {
        return Err(UrlError::XHost);
    }
    Ok(host)
}

/// Percent-encodes every byte outside the allowed set. A `%` stays only in
/// front of two hex digits, which keep their case.
fn encode(raw: &str, query: bool) -> String {
    let bytes = raw.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' && bytes.get(i + 1).is_some_and(u8::is_ascii_hexdigit) && bytes.get(i + 2).is_some_and(u8::is_ascii_hexdigit) {
            out.push_str(&raw[i..i + 3]);
            i += 3;
            continue;
        }
        if b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/".contains(&b) || (query && b == b'?') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
        i += 1;
    }
    out
}

/// RFC 3986 section 5.2.4.
fn remove_dot_segments(path: &str) -> String {
    let mut input = path;
    let mut out = String::with_capacity(path.len());
    let pop = |out: &mut String| out.truncate(out.rfind('/').unwrap_or(0));
    while !input.is_empty() {
        if let Some(rest) = input.strip_prefix("../") {
            input = rest;
        } else if let Some(rest) = input.strip_prefix("./") {
            input = rest;
        } else if input.starts_with("/./") {
            input = &input[2..];
        } else if input == "/." {
            input = "/";
        } else if input.starts_with("/../") {
            input = &input[3..];
            pop(&mut out);
        } else if input == "/.." {
            input = "/";
            pop(&mut out);
        } else if input == "." || input == ".." {
            input = "";
        } else {
            let end = input.as_bytes()[1..].iter().position(|&b| b == b'/').map_or(input.len(), |i| i + 1);
            out.push_str(&input[..end]);
            input = &input[end..];
        }
    }
    out
}

/// The strict canonical form of an absolute https URL. A URL is canonical
/// exactly when this returns it unchanged.
pub fn canonical_url(input: &str) -> Result<String, UrlError> {
    if input.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(UrlError::Invalid);
    }
    let (scheme, authority, tail) = split(input)?;
    if scheme != "https" {
        return Err(UrlError::Scheme);
    }
    if authority.contains('@') {
        return Err(UrlError::Userinfo);
    }
    if authority.starts_with('[') {
        return Err(UrlError::IpLiteral);
    }
    let (raw_host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    let host = host(raw_host)?;
    if !matches!(port, None | Some("" | "443")) {
        return Err(UrlError::Port);
    }
    let tail = tail.split_once('#').map_or(tail, |(before, _)| before);
    let (path, query) = match tail.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (tail, None),
    };
    let mut path = remove_dot_segments(&encode(if path.is_empty() { "/" } else { path }, false));
    if path.is_empty() {
        path.push('/');
    }
    let mut out = format!("https://{host}{path}");
    if let Some(query) = query {
        out.push('?');
        out.push_str(&encode(query, true));
    }
    if out.len() > MAX_URL {
        return Err(UrlError::TooLong);
    }
    Ok(out)
}

/// The host of a canonical URL.
pub fn url_host(url: &str) -> &str {
    let rest = url.strip_prefix("https://").unwrap_or(url);
    &rest[..rest.find('/').unwrap_or(rest.len())]
}

/// Resolves a redirect's `Location` against the canonical URL of the hop
/// that returned it, and returns the canonical URL to fetch next.
pub fn resolve_location(base: &str, location: &str) -> Result<String, UrlError> {
    let location = location.trim_matches([' ', '\t']);
    if location.is_empty() {
        return Err(UrlError::Empty);
    }
    if let Some((scheme, _)) = location.split_once(':')
        && scheme_like(scheme)
    {
        return match scheme.to_ascii_lowercase().as_str() {
            "https" => canonical_url(location),
            "http" => Err(UrlError::Insecure),
            _ => Err(UrlError::Scheme),
        };
    }
    if location.starts_with("//") {
        return canonical_url(&format!("https:{location}"));
    }
    let (_, authority, tail) = split(base)?;
    let tail = tail.split_once('#').map_or(tail, |(before, _)| before);
    let (base_path, base_query) = tail.split_once('?').map_or((tail, None), |(p, q)| (p, Some(q)));
    let location = location.split_once('#').map_or(location, |(before, _)| before);
    let (path, query) = location.split_once('?').map_or((location, None), |(p, q)| (p, Some(q)));
    let (path, query) = if path.is_empty() {
        (base_path.to_owned(), query.or(base_query))
    } else if path.starts_with('/') {
        (remove_dot_segments(path), query)
    } else {
        let directory = &base_path[..base_path.rfind('/').map_or(0, |i| i + 1)];
        (remove_dot_segments(&format!("{directory}{path}")), query)
    };
    let query = query.map(|q| format!("?{q}")).unwrap_or_default();
    canonical_url(&format!("https://{authority}{path}{query}"))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub name: String,
    pub value: String,
}

/// A validated web job.
#[derive(Debug, PartialEq, Eq)]
pub struct Job {
    pub url: String,
    pub max_redirects: usize,
    pub max_response_bytes: usize,
    pub headers: Vec<Header>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    #[serde(rename = "type")]
    kind: String,
    proof_mode: String,
    proof_policy: String,
    url: String,
    max_redirects: u64,
    max_response_bytes: u64,
    headers: Vec<Header>,
}

/// Validates a `web.fetch` payload as the coordinator registers it and the
/// node receives it: every field present, nothing else, integers only.
pub fn validate_job(payload: &Value) -> Result<Job> {
    let p = Payload::deserialize(payload).context("invalid web job")?;
    if p.kind != PAYLOAD_TYPE || p.proof_mode != "relay" || p.proof_policy != WEB_POLICY {
        bail!("web jobs must be {PAYLOAD_TYPE} under relay proof policy {WEB_POLICY}");
    }
    if canonical_url(&p.url).ok().as_deref() != Some(p.url.as_str()) {
        bail!("web job URL must be a canonical public https URL");
    }
    if p.max_redirects > MAX_REDIRECTS as u64 || !(1..=MAX_RESPONSE as u64).contains(&p.max_response_bytes) {
        bail!("web job limits are out of range");
    }
    if p.headers.len() > HEADERS.len() {
        bail!("web job has too many headers");
    }
    let mut next = 0;
    for header in &p.headers {
        let Some(at) = HEADERS[next..].iter().position(|(name, _)| *name == header.name) else {
            bail!("web job headers must be user-agent, accept and accept-language, each at most once and in that order");
        };
        next += at + 1;
        let value = header.value.as_bytes();
        if !(1..=MAX_HEADER_VALUE).contains(&value.len()) || !value.iter().all(|b| (0x20..=0x7e).contains(b)) || value[0] == b' ' || value[value.len() - 1] == b' ' {
            bail!("web job header value is not allowed");
        }
    }
    Ok(Job { url: p.url, max_redirects: p.max_redirects as usize, max_response_bytes: p.max_response_bytes as usize, headers: p.headers })
}

/// The exact request bytes for one hop. Both sides build them with this
/// function, and the verifier authorizes nothing else.
pub fn request(url: &str, headers: &[Header]) -> Vec<u8> {
    let host = url_host(url);
    let rest = &url["https://".len() + host.len()..];
    let target = if rest.is_empty() { "/" } else { rest };
    let mut out = format!("GET {target} HTTP/1.1\r\nHost: {host}\r\n");
    for header in headers {
        let name = HEADERS.iter().find(|(lower, _)| *lower == header.name).map_or(header.name.as_str(), |(_, wire)| wire);
        out.push_str(&format!("{name}: {}\r\n", header.value));
    }
    out.push_str("Accept-Encoding: gzip, deflate, br\r\nConnection: close\r\n\r\n");
    out.into_bytes()
}

/// How a response's body ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    None,
    ContentLength,
    Chunked,
    Close,
}

impl Framing {
    pub fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ContentLength => "content_length",
            Self::Chunked => "chunked",
            Self::Close => "close",
        }
    }
}

/// Why a response could not be framed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// More decrypted bytes than the job allows.
    TooLarge,
    /// A malformed head or body framing.
    Invalid,
    /// The server closed before the response was complete.
    Closed,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLarge => "response exceeds the job's size limit",
            Self::Invalid => "response head or framing is invalid",
            Self::Closed => "server closed before the response was complete",
        })
    }
}

impl std::error::Error for FrameError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Head,
    Length(usize),
    ChunkSize,
    ChunkData(usize),
    /// Bytes of the CRLF after a chunk's data already seen.
    ChunkEnd(u8),
    Trailers,
    Close,
    Done,
}

/// One complete response as the verifier decrypted it.
pub struct Response {
    pub status: u16,
    /// The final (non-1xx) status line and header lines, through the blank line.
    pub head: Vec<u8>,
    /// The entity body: transfer-decoded, still content-encoded.
    pub body: Vec<u8>,
    pub framing: Framing,
    /// Decrypted bytes up to completion, interim heads and chunk framing included.
    pub received: usize,
    /// SHA-256 of those bytes.
    pub response_sha256: [u8; 32],
    locations: Vec<Vec<u8>>,
}

impl Response {
    /// The `Location` header, if exactly one value was sent.
    pub fn location(&self) -> Option<Result<&str, UrlError>> {
        let first = self.locations.first()?;
        if self.locations.iter().any(|l| l != first) {
            return Some(Err(UrlError::Invalid));
        }
        Some(std::str::from_utf8(first).map_err(|_| UrlError::Invalid))
    }
}

/// Frames an HTTP/1.x response as its bytes arrive. Each byte is examined
/// once: the head search resumes where it stopped, and the body is parsed
/// as a stream.
pub struct Framer {
    max: usize,
    received: usize,
    hasher: Sha256,
    state: State,
    head: Vec<u8>,
    /// Bytes of earlier interim heads.
    interim: usize,
    line: Vec<u8>,
    trailers: usize,
    status: u16,
    framing: Framing,
    body: Vec<u8>,
    locations: Vec<Vec<u8>>,
}

impl Framer {
    pub fn new(max_response_bytes: usize) -> Self {
        Self {
            max: max_response_bytes,
            received: 0,
            hasher: Sha256::new(),
            state: State::Head,
            head: Vec::new(),
            interim: 0,
            line: Vec::new(),
            trailers: 0,
            status: 0,
            framing: Framing::None,
            body: Vec::new(),
            locations: Vec::new(),
        }
    }

    pub fn complete(&self) -> bool {
        self.state == State::Done
    }

    /// Takes decrypted bytes and returns whether the response is complete.
    /// Bytes after the end of the response are not part of it.
    pub fn push(&mut self, mut data: &[u8]) -> Result<bool, FrameError> {
        while !data.is_empty() && self.state != State::Done {
            let used = self.step(data)?;
            self.received += used;
            if self.received > self.max {
                return Err(FrameError::TooLarge);
            }
            self.hasher.update(&data[..used]);
            data = &data[used..];
            if self.state == State::Head && self.head.ends_with(b"\r\n\r\n") {
                self.parse_head()?;
            }
        }
        Ok(self.complete())
    }

    /// The server's authenticated close_notify. It ends a close-delimited
    /// body; anything else still in progress is incomplete.
    pub fn close_notify(&mut self) -> Result<(), FrameError> {
        match self.state {
            State::Close => {
                self.state = State::Done;
                Ok(())
            }
            State::Done => Ok(()),
            _ => Err(FrameError::Closed),
        }
    }

    /// The complete response. Panics if it is not complete.
    pub fn finish(&mut self) -> Response {
        assert!(self.complete(), "response is not complete");
        Response {
            status: self.status,
            head: std::mem::take(&mut self.head),
            body: std::mem::take(&mut self.body),
            framing: self.framing,
            received: self.received,
            response_sha256: std::mem::take(&mut self.hasher).finalize().into(),
            locations: std::mem::take(&mut self.locations),
        }
    }

    /// Consumes a prefix of `data` in the current state and returns its length.
    fn step(&mut self, data: &[u8]) -> Result<usize, FrameError> {
        Ok(match self.state {
            State::Head => {
                let room = MAX_HEAD.saturating_sub(self.interim + self.head.len());
                let take = data.len().min(room);
                let from = self.head.len().saturating_sub(3);
                self.head.extend_from_slice(&data[..take]);
                match find(&self.head[from..], b"\r\n\r\n") {
                    Some(at) => {
                        let end = from + at + 4;
                        let used = take - (self.head.len() - end);
                        self.head.truncate(end);
                        used
                    }
                    None if take < data.len() => return Err(FrameError::Invalid),
                    None => take,
                }
            }
            State::Length(remaining) => {
                let take = remaining.min(data.len());
                self.body.extend_from_slice(&data[..take]);
                self.state = if take == remaining { State::Done } else { State::Length(remaining - take) };
                take
            }
            State::ChunkSize => {
                let (used, line) = self.line(data, MAX_CHUNK_LINE)?;
                if let Some(line) = line {
                    let size = chunk_size(&line)?;
                    self.state = if size == 0 { State::Trailers } else { State::ChunkData(size) };
                }
                used
            }
            State::ChunkData(remaining) => {
                let take = remaining.min(data.len());
                self.body.extend_from_slice(&data[..take]);
                self.state = if take == remaining { State::ChunkEnd(0) } else { State::ChunkData(remaining - take) };
                take
            }
            State::ChunkEnd(seen) => {
                if data[0] != b"\r\n"[seen as usize] {
                    return Err(FrameError::Invalid);
                }
                self.state = if seen == 0 { State::ChunkEnd(1) } else { State::ChunkSize };
                1
            }
            State::Trailers => {
                let (used, line) = self.line(data, MAX_TRAILERS.saturating_sub(self.trailers))?;
                if let Some(line) = line {
                    if line.is_empty() {
                        self.state = State::Done;
                    } else {
                        self.trailers += line.len() + 2;
                    }
                }
                used
            }
            State::Close => {
                self.body.extend_from_slice(data);
                data.len()
            }
            State::Done => 0,
        })
    }

    /// Collects one CRLF-terminated line of at most `max` bytes. Returns the
    /// bytes used and, once the line is whole, the line without its CRLF.
    fn line(&mut self, data: &[u8], max: usize) -> Result<(usize, Option<Vec<u8>>), FrameError> {
        let (used, done) = match data.iter().position(|&b| b == b'\n') {
            Some(at) => (at + 1, true),
            None => (data.len(), false),
        };
        self.line.extend_from_slice(&data[..used]);
        if self.line.len() > max {
            return Err(FrameError::Invalid);
        }
        if !done {
            return Ok((used, None));
        }
        let mut line = std::mem::take(&mut self.line);
        if !line.ends_with(b"\r\n") {
            return Err(FrameError::Invalid);
        }
        line.truncate(line.len() - 2);
        Ok((used, Some(line)))
    }

    /// Parses a complete head and sets up the body, or waits for the next
    /// head after an interim response.
    fn parse_head(&mut self) -> Result<(), FrameError> {
        let head = &self.head;
        let status_line_end = find(head, b"\r\n").ok_or(FrameError::Invalid)?;
        let status_line = &head[..status_line_end];
        if !(status_line.starts_with(b"HTTP/1.1 ") || status_line.starts_with(b"HTTP/1.0 ")) || status_line.len() < 12 {
            return Err(FrameError::Invalid);
        }
        let digits = &status_line[9..12];
        if !digits.iter().all(u8::is_ascii_digit) || !matches!(status_line.get(12), None | Some(b' ')) {
            return Err(FrameError::Invalid);
        }
        let status = digits.iter().fold(0u16, |n, d| n * 10 + u16::from(d - b'0'));
        if status < 100 {
            return Err(FrameError::Invalid);
        }
        // Only CRLF ends a line: a bare CR or LF would be read differently by other parsers.
        let body = &head[..head.len() - 2];
        if body.iter().enumerate().any(|(i, &b)| (b == b'\n' && (i == 0 || body[i - 1] != b'\r')) || (b == b'\r' && body.get(i + 1) != Some(&b'\n'))) {
            return Err(FrameError::Invalid);
        }
        let (mut codings, mut lengths, mut locations, mut transfer_encoding) = (Vec::new(), Vec::new(), Vec::new(), false);
        for line in head[status_line_end + 2..head.len() - 2].split_inclusive(|&b| b == b'\n') {
            let line = line.strip_suffix(b"\r\n").ok_or(FrameError::Invalid)?;
            let colon = line.iter().position(|&b| b == b':').ok_or(FrameError::Invalid)?;
            let (name, value) = (&line[..colon], trim(&line[colon + 1..]));
            if name.is_empty() || !name.iter().all(|&b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)) {
                return Err(FrameError::Invalid);
            }
            if name.eq_ignore_ascii_case(b"transfer-encoding") {
                transfer_encoding = true;
                codings.extend(value.split(|&b| b == b',').map(trim).filter(|c| !c.is_empty()).map(<[u8]>::to_ascii_lowercase));
            } else if name.eq_ignore_ascii_case(b"content-length") {
                lengths.extend(value.split(|&b| b == b',').map(trim).map(<[u8]>::to_vec));
            } else if name.eq_ignore_ascii_case(b"location") {
                locations.push(value.to_vec());
            }
        }
        if (100..200).contains(&status) {
            if status == 101 {
                return Err(FrameError::Invalid);
            }
            // An interim response: its head counts, and the real one follows.
            self.interim += self.head.len();
            self.head.clear();
            return Ok(());
        }
        self.status = status;
        self.locations = locations;
        (self.framing, self.state) = if matches!(status, 204 | 304) {
            (Framing::None, State::Done)
        } else if transfer_encoding {
            if codings.last().is_some_and(|c| c == b"chunked") { (Framing::Chunked, State::ChunkSize) } else { (Framing::Close, State::Close) }
        } else if let Some(first) = lengths.first() {
            if lengths.iter().any(|l| l != first) || first.is_empty() || first.len() > 19 || !first.iter().all(u8::is_ascii_digit) {
                return Err(FrameError::Invalid);
            }
            let length = std::str::from_utf8(first).ok().and_then(|s| s.parse::<usize>().ok()).ok_or(FrameError::Invalid)?;
            if length > self.max.saturating_sub(self.received) {
                return Err(FrameError::TooLarge);
            }
            (Framing::ContentLength, if length == 0 { State::Done } else { State::Length(length) })
        } else {
            (Framing::Close, State::Close)
        };
        Ok(())
    }
}

fn trim(mut value: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = value {
        value = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = value {
        value = rest;
    }
    value
}

fn chunk_size(line: &[u8]) -> Result<usize, FrameError> {
    let size = trim(line.split(|&b| b == b';').next().unwrap_or_default());
    if size.is_empty() || size.len() > 15 || !size.iter().all(u8::is_ascii_hexdigit) {
        return Err(FrameError::Invalid);
    }
    usize::from_str_radix(std::str::from_utf8(size).map_err(|_| FrameError::Invalid)?, 16).map_err(|_| FrameError::Invalid)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../../api/web-vectors.json")).unwrap()
    }

    #[test]
    fn strict_vectors() {
        for v in vectors()["strict"].as_array().unwrap() {
            let input = v["input"].as_str().unwrap();
            match (canonical_url(input), v["output"].as_str(), v["error"].as_str()) {
                (Ok(out), Some(expected), None) => {
                    assert_eq!(out, expected, "{input}");
                    assert_eq!(canonical_url(&out).unwrap(), out, "{input}: output is not canonical");
                }
                (Err(e), None, Some(expected)) => assert_eq!(e.code(), expected, "{input}"),
                (got, ..) => panic!("{input}: got {got:?}, want {v}"),
            }
        }
    }

    #[test]
    fn redirect_vectors() {
        for v in vectors()["redirects"].as_array().unwrap() {
            let (base, location) = (v["base"].as_str().unwrap(), v["location"].as_str().unwrap());
            match (resolve_location(base, location), v["next"].as_str(), v["refused"].as_str()) {
                (Ok(next), Some(expected), None) => assert_eq!(next, expected, "{location}"),
                (Err(e), None, Some(expected)) => assert_eq!(e.code(), expected, "{location}"),
                (got, ..) => panic!("{location}: got {got:?}, want {v}"),
            }
        }
    }

    #[test]
    fn request_vectors() {
        let vectors = vectors();
        for v in vectors["requests"].as_array().unwrap() {
            let headers: Vec<Header> = serde_json::from_value(v["headers"].clone()).unwrap();
            let bytes = request(v["url"].as_str().unwrap(), &headers);
            assert_eq!(bytes, v["bytes"].as_str().unwrap().as_bytes());
            assert_eq!(format!("{:x}", Sha256::digest(&bytes)), v["sha256"].as_str().unwrap());
        }
        let defaults: Vec<Header> = serde_json::from_value(vectors["default_headers"].clone()).unwrap();
        assert_eq!(request("https://example.com/", &defaults), vectors["requests"][0]["bytes"].as_str().unwrap().as_bytes());
    }

    #[test]
    fn more_url_rules() {
        let ok = |input: &str, want: &str| assert_eq!(canonical_url(input).as_deref(), Ok(want), "{input}");
        let err = |input: &str, want: UrlError| assert_eq!(canonical_url(input), Err(want), "{input}");
        ok("https://example.com/%7euser", "https://example.com/%7euser");
        ok("https://example.com/100%", "https://example.com/100%25");
        ok("https://example.com/?", "https://example.com/?");
        ok("https://example.com/a/../../b", "https://example.com/b");
        ok("https://example.com/é?q=ü", "https://example.com/%C3%A9?q=%C3%BC");
        ok("https://example.com/a?b=c?d", "https://example.com/a?b=c?d");
        ok("https://example.com/a#b?c", "https://example.com/a");
        ok("https://example.com.", "https://example.com/");
        ok("https://EXAMPLE.com:/", "https://example.com/");
        err("https://example.com/\n", UrlError::Invalid);
        err("https://exa mple.com/", UrlError::Host);
        ok("https://0x7f.example/", "https://0x7f.example/");
        err("https://example.0x10/", UrlError::IpLiteral);
        err("https://[::1]:443/", UrlError::IpLiteral);
        err("https://example.local/", UrlError::Host);
        err("https://a.home.arpa/", UrlError::Host);
        err("https://localhost:8443/", UrlError::Host);
        err("https://twitter.com.", UrlError::XHost);
        ok("https://notx.com/", "https://notx.com/");
        err(&format!("https://example.com/{}", "a".repeat(2030)), UrlError::TooLong);
        err(&format!("https://{}.com/", "a".repeat(64)), UrlError::Host);
        assert!(!x_host("notx.com") && !x_host("x.co") && x_host("api.x.com") && x_host("twitter.com"));
    }

    fn payload() -> Value {
        json!({"type":"web.fetch","proof_mode":"relay","proof_policy":"web-relay-v1","url":"https://example.com/","max_redirects":5,"max_response_bytes":10485760,"headers":vectors()["default_headers"]})
    }

    #[test]
    fn validates_the_contract_payload_and_rejects_every_mutation() {
        let job = validate_job(&payload()).unwrap();
        assert_eq!((job.url.as_str(), job.max_redirects, job.max_response_bytes, job.headers.len()), ("https://example.com/", 5, 10 << 20, 3));
        let mut minimal = payload();
        minimal["headers"] = json!([]);
        minimal["max_redirects"] = 0.into();
        minimal["max_response_bytes"] = 1.into();
        assert!(validate_job(&minimal).is_ok());
        let mutations: Vec<(&str, Box<dyn Fn(&mut Value)>)> = vec![
            ("type", Box::new(|p| p["type"] = "x.read".into())),
            ("mode", Box::new(|p| p["proof_mode"] = "mpc".into())),
            ("policy", Box::new(|p| p["proof_policy"] = "x-relay-v1".into())),
            ("unknown", Box::new(|p| p["extra"] = 1.into())),
            ("missing", Box::new(|p| drop(p.as_object_mut().unwrap().remove("headers")))),
            ("float", Box::new(|p| p["max_redirects"] = json!(5.0))),
            ("string int", Box::new(|p| p["max_redirects"] = "5".into())),
            ("redirects", Box::new(|p| p["max_redirects"] = 6.into())),
            ("negative", Box::new(|p| p["max_redirects"] = (-1).into())),
            ("zero bytes", Box::new(|p| p["max_response_bytes"] = 0.into())),
            ("bytes", Box::new(|p| p["max_response_bytes"] = (MAX_RESPONSE + 1).into())),
            ("non-canonical", Box::new(|p| p["url"] = "https://Example.com/".into())),
            ("http", Box::new(|p| p["url"] = "http://example.com/".into())),
            ("x host", Box::new(|p| p["url"] = "https://x.com/".into())),
            ("private name", Box::new(|p| p["url"] = "https://printer.local/".into())),
            ("too many headers", Box::new(|p| p["headers"].as_array_mut().unwrap().push(json!({"name":"accept","value":"*/*"})))),
            ("header order", Box::new(|p| p["headers"].as_array_mut().unwrap().swap(0, 1))),
            ("repeated header", Box::new(|p| p["headers"] = json!([{"name":"accept","value":"a"},{"name":"accept","value":"b"}]))),
            ("other header", Box::new(|p| p["headers"][0]["name"] = "cookie".into())),
            ("header case", Box::new(|p| p["headers"][0]["name"] = "User-Agent".into())),
            ("empty value", Box::new(|p| p["headers"][0]["value"] = "".into())),
            ("long value", Box::new(|p| p["headers"][0]["value"] = "a".repeat(513).into())),
            ("crlf value", Box::new(|p| p["headers"][0]["value"] = "a\r\nCookie: b".into())),
            ("padded value", Box::new(|p| p["headers"][0]["value"] = " a".into())),
            ("header field", Box::new(|p| p["headers"][0]["extra"] = 1.into())),
        ];
        for (name, mutate) in mutations {
            let mut p = payload();
            mutate(&mut p);
            assert!(validate_job(&p).is_err(), "{name} accepted");
        }
    }

    fn frame(response: &[u8], max: usize) -> Result<Response, FrameError> {
        let mut framer = Framer::new(max);
        if !framer.push(response)? {
            framer.close_notify()?;
        }
        Ok(framer.finish())
    }

    #[test]
    fn content_length_and_bodyless_responses() {
        let r = frame(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhelloEXTRA", 1 << 20).unwrap();
        assert_eq!((r.status, r.body.as_slice(), r.framing, r.received), (200, &b"hello"[..], Framing::ContentLength, 62));
        assert_eq!(r.head, b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n");
        assert_eq!(r.response_sha256, <[u8; 32]>::from(Sha256::digest(&b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello"[..])));
        for head in [&b"HTTP/1.1 204 No Content\r\nContent-Length: 10\r\n\r\n"[..], b"HTTP/1.0 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n", b"HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n"] {
            let mut framer = Framer::new(1 << 20);
            assert!(framer.push(head).unwrap());
            assert!(framer.finish().body.is_empty());
        }
        let r = frame(b"HTTP/1.1 301 Moved\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n", 1 << 20).unwrap();
        assert_eq!((r.framing, r.location()), (Framing::ContentLength, Some(Ok("/next"))));
        let mut framer = Framer::new(1 << 20);
        assert!(framer.push(b"HTTP/1.1 302 Found\r\nLocation: /a\r\nLocation: /b\r\nContent-Length: 0\r\n\r\n").unwrap());
        assert_eq!(framer.finish().location(), Some(Err(UrlError::Invalid)));
        // Conflicting lengths are refused, whether on one line or several.
        for head in [&b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n"[..], b"HTTP/1.1 200 OK\r\nContent-Length: 5, 6\r\n\r\n", b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n", b"HTTP/1.1 200 OK\r\nContent-Length: 0x5\r\n\r\n"] {
            assert_eq!(Framer::new(1 << 20).push(head).err(), Some(FrameError::Invalid));
        }
    }

    #[test]
    fn chunked_bodies_parse_at_every_split_without_rescanning() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n5;name=value\r\nhello\r\n7 ; x\r\n, world\r\n0\r\nX-Trailer: yes\r\nOther: 1\r\n\r\nNEXT";
        let whole = frame(response, 1 << 20).unwrap();
        assert_eq!((whole.body.as_slice(), whole.framing, whole.received), (&b"hello, world"[..], Framing::Chunked, response.len() - 4));
        for split in 0..response.len() {
            let mut framer = Framer::new(1 << 20);
            let first = framer.push(&response[..split]).unwrap();
            assert!(!first || split >= response.len() - 4, "complete early at {split}");
            assert!(framer.push(&response[split..]).unwrap(), "split at {split}");
            let r = framer.finish();
            assert_eq!((r.body, r.received, r.response_sha256), (whole.body.clone(), whole.received, whole.response_sha256));
        }
        // Byte by byte as well.
        let mut framer = Framer::new(1 << 20);
        for byte in response {
            framer.push(std::slice::from_ref(byte)).unwrap();
        }
        assert_eq!(framer.finish().body, b"hello, world");
        for bad in [
            &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n"[..],
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloXX",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\nhello\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1000000000000000\r\n",
        ] {
            assert_eq!(Framer::new(1 << 20).push(bad).err(), Some(FrameError::Invalid), "{}", String::from_utf8_lossy(bad));
        }
        let mut trailers = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n".to_vec();
        trailers.extend(b"T: 0123456789\r\n".repeat(600));
        assert_eq!(Framer::new(1 << 20).push(&trailers).err(), Some(FrameError::Invalid));
    }

    #[test]
    fn interim_responses_are_skipped_and_switching_protocols_refused() {
        let response = b"HTTP/1.1 103 Early Hints\r\nLink: </a.css>\r\n\r\nHTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let r = frame(response, 1 << 20).unwrap();
        assert_eq!((r.status, r.body.as_slice()), (200, &b"ok"[..]));
        assert_eq!(r.head, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n");
        assert_eq!(r.received, response.len());
        assert_eq!(Framer::new(1 << 20).push(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\n\r\n").err(), Some(FrameError::Invalid));
    }

    #[test]
    fn close_delimited_bodies_complete_only_on_close_notify() {
        for head in [&b"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n"[..], b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nContent-Length: 3\r\n\r\n"] {
            let mut framer = Framer::new(1 << 20);
            assert!(!framer.push(head).unwrap());
            assert!(!framer.push(b"partial page").unwrap());
            framer.close_notify().unwrap();
            let r = framer.finish();
            assert_eq!((r.body.as_slice(), r.framing), (&b"partial page"[..], Framing::Close));
        }
        // A close_notify ends nothing that has its own length.
        let mut framer = Framer::new(1 << 20);
        framer.push(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort").unwrap();
        assert_eq!(framer.close_notify(), Err(FrameError::Closed));
        let mut framer = Framer::new(1 << 20);
        framer.push(b"HTTP/1.1 200 OK\r\n").unwrap();
        assert_eq!(framer.close_notify(), Err(FrameError::Closed));
        assert_eq!(Framer::new(1 << 20).close_notify(), Err(FrameError::Closed));
    }

    #[test]
    fn heads_and_bodies_are_bounded() {
        let mut big = b"HTTP/1.1 200 OK\r\n".to_vec();
        big.extend(b"X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n".repeat(1200));
        assert_eq!(Framer::new(1 << 20).push(&big).err(), Some(FrameError::Invalid));
        // The limit also covers interim heads.
        let mut interim = b"HTTP/1.1 103 Early Hints\r\n".to_vec();
        interim.extend(b"Link: </aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa>\r\n".repeat(1000));
        interim.extend(b"\r\nHTTP/1.1 200 OK\r\nX: ");
        interim.extend([b'a'; 4000]);
        assert_eq!(Framer::new(1 << 20).push(&interim).err(), Some(FrameError::Invalid));
        // A head of exactly the limit is fine.
        let mut exact = b"HTTP/1.1 200 OK\r\nX: ".to_vec();
        exact.resize(MAX_HEAD - 4 - 19, b'a');
        exact.extend(b"\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(exact.len(), MAX_HEAD);
        assert!(Framer::new(1 << 20).push(&exact).unwrap());
        let body = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n";
        assert_eq!(Framer::new(100).push(body).err(), Some(FrameError::TooLarge));
        let mut framer = Framer::new(60);
        framer.push(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap();
        assert_eq!(framer.push(b"20\r\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n").err(), Some(FrameError::TooLarge));
        let mut framer = Framer::new(50);
        framer.push(b"HTTP/1.0 200 OK\r\n\r\n").unwrap();
        assert_eq!(framer.push(&[b'a'; 40]).err(), Some(FrameError::TooLarge));
    }

    #[test]
    fn malformed_heads_are_refused() {
        for head in [
            &b"HTTP/2 200 OK\r\n\r\n"[..],
            b"HTTP/1.1 20 OK\r\n\r\n",
            b"HTTP/1.1 2000 OK\r\n\r\n",
            b"HTTP/1.1 099 OK\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nNo colon\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nBad Name: x\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n folded: x\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nA: b\nC: d\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nA: b\rC: d\r\n\r\n",
        ] {
            assert_eq!(Framer::new(1 << 20).push(head).err(), Some(FrameError::Invalid), "{}", String::from_utf8_lossy(head));
        }
        // Non-standard statuses and binary bodies are fine.
        let r = frame(b"HTTP/1.1 999 Request denied\r\nContent-Length: 3\r\n\r\n\xff\x00\xfe", 1 << 20).unwrap();
        assert_eq!((r.status, r.body.as_slice()), (999, &b"\xff\x00\xfe"[..]));
    }
}
