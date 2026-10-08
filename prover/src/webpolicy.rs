//! Policy for proven web fetches (`web.fetch`, policies `web-relay-v1` and
//! `web-browser-v1`).
//!
//! A web job names one public https URL. The verifier is the TLS client for
//! each hop through the supplier's connection, as for keyed X reads, but a
//! public page carries no secret: the request has no hidden bytes and the
//! supplier never receives the page. The verifier authorizes exactly the
//! request bytes `request` builds for the hop URL, and a later hop only for
//! the canonical `Location` of the previous verified redirect.
//!
//! A `web-browser-v1` job is the proven re-fetch of a page the node's
//! browser rendered. Its request also carries two headers the node chooses
//! per hop, in public bytes the verifier sees: the browser's User-Agent,
//! which must be one of the pinned strings `user_agent` builds, and
//! optionally the anti-bot clearance cookies the browser earned, whose names
//! must all be on the clearance allowlist. Hidden bytes are never used for
//! them, because the verifier cannot check hidden content. The receipt keeps
//! the User-Agent, the cookie names and a hash of the cookie value, never
//! the value.
//!
//! The URL rules here are the "strict" rules every implementation shares
//! (`api/web-vectors.json`). The response is framed incrementally and kept
//! still content-encoded; decoding and rendering happen in the app.

use std::{fmt, time::Duration};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const WEB_POLICY: &str = "web-relay-v1";
pub const BROWSER_POLICY: &str = "web-browser-v1";
pub const PAYLOAD_TYPE: &str = "web.fetch";
pub const MAX_REDIRECTS: usize = 5;
pub const MAX_URL: usize = 2048;
/// The page ceiling: a hop's entity bytes (de-chunked, still
/// content-encoded). Every web job's `max_response_bytes` must equal it.
pub const PAGE_MAX: usize = 64 << 20;
/// All response heads of one hop, interim 1xx heads included.
pub const MAX_HEAD: usize = 64 << 10;
const MAX_TRAILERS: usize = 8 << 10;
const MAX_CHUNK_LINE: usize = 4 << 10;
/// Longest a single hop's session may run on either side: a 64 MiB page at
/// 1.92 Mbit/s.
pub const HOP_LIMIT: Duration = Duration::from_secs(280);

/// Every decrypted byte one hop may take for an entity of at most
/// `max_entity` bytes: the entity, its heads (interim heads included),
/// trailers and chunk framing. Chunks of 1 KiB or more always fit.
pub const fn max_wire(max_entity: usize) -> usize {
    max_entity + MAX_HEAD + max_entity / 64
}
/// Payload header names in the only order they may appear, and their wire spelling.
const HEADERS: [(&str, &str); 3] = [("user-agent", "User-Agent"), ("accept", "Accept"), ("accept-language", "Accept-Language")];
const MAX_HEADER_VALUE: usize = 512;
/// The only payload headers of a `web-browser-v1` job, in this order.
const BROWSER_HEADERS: [(&str, &str); 2] = [("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"), ("accept-language", "en-US,en;q=0.9")];
/// The headers a `web-browser-v1` job lets the node choose per hop.
const NODE_HEADERS: [&str; 2] = ["user-agent", "cookie"];
/// The Chrome majors whose User-Agent the verifier accepts. A Chrome for
/// Testing pin bump changes these with the node's and the app's.
pub const MIN_BROWSER_MAJOR: u32 = 155;
pub const MAX_BROWSER_MAJOR: u32 = 155;
/// The node platforms a browser User-Agent may name, and what it says for each.
const UA_PLATFORMS: [(&str, &str); 3] = [("darwin", "Macintosh; Intel Mac OS X 10_15_7"), ("windows", "Windows NT 10.0; Win64; x64"), ("linux", "X11; Linux x86_64")];
const UA_PREFIX: &str = "Mozilla/5.0 (";
const UA_ENGINE: &str = ") AppleWebKit/537.36 (KHTML, like Gecko) Chrome/";
const UA_SUFFIX: &str = ".0.0.0 Safari/537.36";
/// Bytes of a node-supplied Cookie value, and its pairs.
pub const MAX_COOKIE: usize = 4096;
pub const MAX_COOKIE_PAIRS: usize = 50;
const MAX_COOKIE_NAME: usize = 256;
/// Anti-bot clearance cookies a re-fetch may carry: these names exactly
/// (Cloudflare; DataDome; Akamai Bot Manager with its sensor and SEC-CPT
/// cookies; HUMAN; Imperva; AWS WAF; Kasada's token mirror)...
const CLEARANCE_COOKIES: [&str; 24] = [
    "cf_clearance", "__cf_bm", "_cfuvid", "datadome", "_abck", "bm_sz", "ak_bmsc", "bm_sv", "bm_s", "bm_so", "bm_sc", "bm_lso", "bm_mi", "sbsd", "sbsd_o", "sec_cpt", "pxcts", "reese84",
    "___utmvc", "aws-waf-token", "KP_UIDz", "KP_UIDz-ssn", "tkrm_alpekz_s1.3", "tkrm_alpekz_s1.3-ssn",
];
/// ...and these prefixes, each followed by at least one more byte.
const CLEARANCE_PREFIXES: [&str; 5] = ["_px", "incap_ses_", "visid_incap_", "nlbi_", "incap_sh_"];
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

/// How a web job's hops are authorized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    /// `web-relay-v1`: exactly the request the payload's headers make.
    Relay,
    /// `web-browser-v1`: the payload's headers plus the node's pinned
    /// User-Agent and, optionally, its clearance cookies.
    Browser,
}

impl Policy {
    pub fn name(self) -> &'static str {
        match self {
            Self::Relay => WEB_POLICY,
            Self::Browser => BROWSER_POLICY,
        }
    }
}

/// A validated web job.
#[derive(Debug, PartialEq, Eq)]
pub struct Job {
    pub url: String,
    pub max_redirects: usize,
    pub max_response_bytes: usize,
    pub headers: Vec<Header>,
    pub policy: Policy,
}

impl Job {
    /// What hop `index` at `url` may do with a redirect.
    pub fn rule(&self, url: &str, index: usize) -> HopRule {
        HopRule { url: url.to_owned(), can_follow: index < self.max_redirects }
    }

    /// The request bytes for one hop: the node's headers are required
    /// under `web-browser-v1` and refused otherwise.
    pub fn hop_request(&self, url: &str, node: Option<&NodeHeaders>) -> Result<Vec<u8>> {
        match (self.policy, node) {
            (Policy::Relay, None) => Ok(request(url, &self.headers)),
            (Policy::Browser, Some(node)) => {
                node.check()?;
                let raw = request_with_node(url, &self.headers, &node.user_agent, node.cookie.as_deref());
                if raw.len() > crate::relay::MAX_REQUEST {
                    bail!("hop request exceeds {} bytes", crate::relay::MAX_REQUEST);
                }
                Ok(raw)
            }
            (Policy::Relay, Some(_)) => bail!("node headers are only for {BROWSER_POLICY} jobs"),
            (Policy::Browser, None) => bail!("{BROWSER_POLICY} jobs need the node's headers"),
        }
    }
}

/// Deserializes a field that may be absent but never `null`.
pub(crate) fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(deserializer: D) -> Result<Option<T>, D::Error> {
    T::deserialize(deserializer).map(Some)
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
    #[serde(default, deserialize_with = "present")]
    node_headers: Option<Vec<String>>,
}

/// Validates a `web.fetch` payload as the coordinator registers it and the
/// node receives it: every field present, nothing else, integers only.
pub fn validate_job(payload: &Value) -> Result<Job> {
    let p = Payload::deserialize(payload).context("invalid web job")?;
    let policy = [Policy::Relay, Policy::Browser].into_iter().find(|policy| policy.name() == p.proof_policy);
    let (Some(policy), PAYLOAD_TYPE, "relay") = (policy, p.kind.as_str(), p.proof_mode.as_str()) else {
        bail!("web jobs must be {PAYLOAD_TYPE} under relay proof policy {WEB_POLICY} or {BROWSER_POLICY}");
    };
    if canonical_url(&p.url).ok().as_deref() != Some(p.url.as_str()) {
        bail!("web job URL must be a canonical public https URL");
    }
    if p.max_redirects > MAX_REDIRECTS as u64 {
        bail!("web job limits are out of range");
    }
    if p.max_response_bytes != PAGE_MAX as u64 {
        bail!("web jobs must set max_response_bytes to the page ceiling, {PAGE_MAX}");
    }
    if policy == Policy::Browser {
        let headers: Vec<(&str, &str)> = p.headers.iter().map(|h| (h.name.as_str(), h.value.as_str())).collect();
        if headers != BROWSER_HEADERS {
            bail!("{BROWSER_POLICY} job headers must be exactly the default accept and accept-language, in that order");
        }
        if p.node_headers.as_deref().is_none_or(|names| names != NODE_HEADERS) {
            bail!("{BROWSER_POLICY} jobs must name node_headers user-agent and cookie, in that order");
        }
        if p.max_redirects != MAX_REDIRECTS as u64 {
            bail!("{BROWSER_POLICY} jobs must use the default limits");
        }
    } else if p.node_headers.is_some() {
        bail!("{WEB_POLICY} jobs take no node_headers");
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
    Ok(Job { url: p.url, max_redirects: p.max_redirects as usize, max_response_bytes: p.max_response_bytes as usize, headers: p.headers, policy })
}

/// The request line and Host header for a hop.
fn request_head(url: &str) -> String {
    let host = url_host(url);
    let rest = &url["https://".len() + host.len()..];
    let target = if rest.is_empty() { "/" } else { rest };
    format!("GET {target} HTTP/1.1\r\nHost: {host}\r\n")
}

/// The payload's header lines, in wire spelling.
fn header_lines(headers: &[Header]) -> String {
    headers
        .iter()
        .map(|header| {
            let name = HEADERS.iter().find(|(lower, _)| *lower == header.name).map_or(header.name.as_str(), |(_, wire)| wire);
            format!("{name}: {}\r\n", header.value)
        })
        .collect()
}

const REQUEST_TAIL: &str = "Accept-Encoding: gzip, deflate, br\r\nConnection: close\r\n\r\n";

/// The exact request bytes for one hop. Both sides build them with this
/// function, and the verifier authorizes nothing else.
pub fn request(url: &str, headers: &[Header]) -> Vec<u8> {
    format!("{}{}{REQUEST_TAIL}", request_head(url), header_lines(headers)).into_bytes()
}

/// The exact request bytes for one hop of a `web-browser-v1` job: the
/// node's User-Agent right after Host, and its Cookie, when it sends one,
/// between the payload headers and Accept-Encoding.
pub fn request_with_node(url: &str, headers: &[Header], user_agent: &str, cookie: Option<&str>) -> Vec<u8> {
    let cookie = cookie.map(|c| format!("Cookie: {c}\r\n")).unwrap_or_default();
    format!("{}User-Agent: {user_agent}\r\n{}{cookie}{REQUEST_TAIL}", request_head(url), header_lines(headers)).into_bytes()
}

/// The User-Agent the node's browser and its re-fetch send on `platform`
/// (`darwin`, `windows` or `linux`) for a Chrome `major`.
pub fn user_agent(platform: &str, major: u32) -> Option<String> {
    let (_, os) = UA_PLATFORMS.iter().find(|(name, _)| *name == platform)?;
    Some(format!("{UA_PREFIX}{os}{UA_ENGINE}{major}{UA_SUFFIX}"))
}

/// The Chrome major of a string `user_agent` builds for some platform,
/// whatever the major.
fn user_agent_major(value: &str) -> Option<u32> {
    let rest = value.strip_prefix(UA_PREFIX)?;
    UA_PLATFORMS.iter().find_map(|(_, os)| {
        let digits = rest.strip_prefix(os)?.strip_prefix(UA_ENGINE)?.strip_suffix(UA_SUFFIX)?;
        let canonical = (1..=4).contains(&digits.len()) && digits.bytes().all(|b| b.is_ascii_digit()) && !digits.starts_with('0');
        canonical.then(|| digits.parse().ok()).flatten()
    })
}

/// Whether the verifier accepts `value` as a node's User-Agent now: exactly
/// `user_agent` for a supported platform and a pinned major.
pub fn pinned_user_agent(value: &str) -> bool {
    UA_PLATFORMS.iter().any(|(platform, _)| (MIN_BROWSER_MAJOR..=MAX_BROWSER_MAJOR).any(|major| user_agent(platform, major).as_deref() == Some(value)))
}

fn tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

fn cookie_octet(b: u8) -> bool {
    matches!(b, 0x21 | 0x23..=0x2b | 0x2d..=0x3a | 0x3c..=0x5b | 0x5d..=0x7e)
}

/// A cookie name: 1-256 RFC 9110 token characters.
pub fn cookie_name(name: &str) -> bool {
    (1..=MAX_COOKIE_NAME).contains(&name.len()) && name.bytes().all(tchar)
}

/// Whether `cookie` is a Cookie header value the node may send:
/// `name=value` pairs joined by `"; "`, 1-50 of them in 1-4096 bytes, each
/// value bare or double-quoted cookie-octets. Names may repeat.
pub fn valid_cookie(cookie: &str) -> bool {
    let pair = |pair: &str| {
        pair.split_once('=').is_some_and(|(name, value)| {
            let bare = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')).unwrap_or(value);
            cookie_name(name) && bare.bytes().all(cookie_octet)
        })
    };
    (1..=MAX_COOKIE).contains(&cookie.len()) && cookie.split("; ").count() <= MAX_COOKIE_PAIRS && cookie.split("; ").all(pair)
}

/// Whether `name` is an anti-bot clearance cookie a re-fetch may carry.
/// Case matters; a prefix alone is not a name.
pub fn clearance_cookie(name: &str) -> bool {
    CLEARANCE_COOKIES.contains(&name) || CLEARANCE_PREFIXES.iter().any(|prefix| name.len() > prefix.len() && name.starts_with(prefix))
}

/// The names of a valid cookie's pairs, in header order.
pub fn cookie_names(cookie: &str) -> Vec<&str> {
    cookie.split("; ").map(|pair| pair.split_once('=').map_or(pair, |(name, _)| name)).collect()
}

/// Whether a receipt's cookie names could have come from an allowed Cookie
/// header: at most 50 allowlisted names that fit in one. The shortest such
/// header is the names with empty values, `a=; b=`.
pub fn allowed_cookie_names(names: &[String]) -> bool {
    names.len() <= MAX_COOKIE_PAIRS && names.iter().all(|name| cookie_name(name) && clearance_cookie(name)) && names.join("=; ").len() < MAX_COOKIE
}

/// Whether `value` has the shape of a browser User-Agent for any major. A
/// receipt keeps the one its hop was authorized with, which may predate a
/// pin bump.
pub fn browser_user_agent(value: &str) -> bool {
    user_agent_major(value).is_some()
}

/// The headers a node chose for one hop of a `web-browser-v1` job. They are
/// public request bytes, but the cookie is the node's: it is never printed.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeHeaders {
    pub user_agent: String,
    #[serde(default, deserialize_with = "present")]
    pub cookie: Option<String>,
}

impl fmt::Debug for NodeHeaders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NodeHeaders").field("user_agent", &self.user_agent).field("cookie_names", &self.cookie.as_deref().map(cookie_names)).finish()
    }
}

impl NodeHeaders {
    /// Refuses anything but a pinned User-Agent and a well-formed Cookie of
    /// clearance cookies only. Errors never quote either value.
    pub fn check(&self) -> Result<()> {
        if !pinned_user_agent(&self.user_agent) {
            bail!("node user agent is not a pinned browser user agent");
        }
        if let Some(cookie) = &self.cookie {
            if !valid_cookie(cookie) {
                bail!("node cookie is not a valid Cookie header value");
            }
            if !cookie_names(cookie).into_iter().all(clearance_cookie) {
                bail!("node cookie carries a name outside the clearance allowlist");
            }
        }
        Ok(())
    }

    /// The cookie names in header order: empty without a cookie.
    pub fn cookie_names(&self) -> Vec<String> {
        self.cookie.as_deref().map(cookie_names).unwrap_or_default().into_iter().map(str::to_owned).collect()
    }

    /// SHA-256 of the cookie value bytes, in hex, when there is one.
    pub fn cookie_sha256(&self) -> Option<String> {
        self.cookie.as_deref().map(|cookie| Sha256::digest(cookie.as_bytes()).iter().map(|b| format!("{b:02x}")).collect())
    }
}

/// Authorizes the public request bytes of one hop of `job` at `url`, with
/// nothing hidden. A `web-relay-v1` hop must be exactly `request`. A
/// `web-browser-v1` hop must have the node's User-Agent as its third line
/// and may have one Cookie line right before Accept-Encoding; both must
/// pass `NodeHeaders::check`, and then the bytes must be exactly
/// `request_with_node` for them. Returns the node's headers for a browser hop.
pub fn authorize(job: &Job, url: &str, public: &[u8]) -> Result<Option<NodeHeaders>> {
    let node = match job.policy {
        Policy::Relay => None,
        Policy::Browser => {
            let line = |rest: &[u8]| -> Result<(String, usize)> {
                let end = find(rest, b"\r\n").context("request line is not terminated")?;
                Ok((String::from_utf8(rest[..end].to_vec()).context("request header is not UTF-8")?, end + 2))
            };
            let rest = public.strip_prefix(format!("{}User-Agent: ", request_head(url)).as_bytes()).context("request must name the hop and then the node's User-Agent")?;
            let (user_agent, used) = line(rest)?;
            let rest = rest[used..].strip_prefix(header_lines(&job.headers).as_bytes()).context("request headers are not the job's")?;
            let cookie = match rest.strip_prefix(b"Cookie: ") {
                Some(rest) => Some(line(rest)?.0),
                None => None,
            };
            let node = NodeHeaders { user_agent, cookie };
            node.check()?;
            Some(node)
        }
    };
    if public != job.hop_request(url, node.as_ref())? {
        bail!("request is not the hop's canonical request");
    }
    Ok(node)
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
    /// The entity is over the job's page ceiling, or the hop took more
    /// decrypted bytes than that ceiling allows (`max_wire`).
    TooLarge,
    /// A malformed head or body framing.
    Invalid,
    /// The server closed before the response was complete.
    Closed,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLarge => "response exceeds the page ceiling",
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

/// What a hop's final response may do next: the URL its `Location`
/// resolves against, and whether a followable redirect may be followed (the
/// hop is below the job's `max_redirects`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HopRule {
    pub url: String,
    pub can_follow: bool,
}

/// One complete response as the verifier decrypted it. The entity itself is
/// not here: it was handed out as it arrived (`Framer::take_entity`).
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    /// The final (non-1xx) status line and header lines, through the blank line.
    pub head: Vec<u8>,
    /// Entity bytes: transfer-decoded, still content-encoded.
    pub body_bytes: usize,
    /// SHA-256 of the entity.
    pub body_sha256: [u8; 32],
    pub framing: Framing,
    /// Decrypted bytes up to completion, interim heads and chunk framing included.
    pub received: usize,
    /// SHA-256 of those bytes.
    pub response_sha256: [u8; 32],
    /// The canonical next URL of a redirect's `Location`, set even on the
    /// last allowed hop.
    pub location: Option<String>,
    /// Why a redirect's `Location` could not be followed.
    pub location_refused: Option<&'static str>,
    /// Whether the verifier follows `location`. Its entity was hashed and
    /// counted but never handed out; every other response's was.
    pub followable: bool,
}

/// What a hop had taken when it ended, complete or not.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// Decrypted bytes, heads and framing included.
    pub received: usize,
    /// Entity bytes.
    pub entity: usize,
    /// The final head's Content-Length, if it had one.
    pub declared: Option<u64>,
}

/// Frames an HTTP/1.x response as its bytes arrive. Each byte is examined
/// once: the head search resumes where it stopped, and the body is parsed
/// as a stream. The entity is counted and hashed here and, unless the
/// response is a followable redirect, handed out in pieces through
/// `take_entity`, so a page is never held whole. Followability is decided
/// once, when the final head is parsed.
pub struct Framer {
    max_entity: usize,
    max_wire: usize,
    received: usize,
    entity: usize,
    declared: Option<u64>,
    /// The entity passed `max_entity`; the step that did it has been counted.
    over: bool,
    hasher: Sha256,
    body_hasher: Sha256,
    state: State,
    head: Vec<u8>,
    /// Bytes of earlier interim heads.
    interim: usize,
    line: Vec<u8>,
    trailers: usize,
    status: u16,
    framing: Framing,
    rule: Option<HopRule>,
    location: Option<String>,
    location_refused: Option<&'static str>,
    followable: bool,
    /// Entity bytes not yet taken.
    out: Vec<u8>,
}

impl Framer {
    /// A framer for a response that is never followed: its entity is always
    /// handed out and no `Location` is resolved.
    pub fn new(max_entity: usize) -> Self {
        Self {
            max_entity,
            max_wire: max_wire(max_entity),
            received: 0,
            entity: 0,
            declared: None,
            over: false,
            hasher: Sha256::new(),
            body_hasher: Sha256::new(),
            state: State::Head,
            head: Vec::new(),
            interim: 0,
            line: Vec::new(),
            trailers: 0,
            status: 0,
            framing: Framing::None,
            rule: None,
            location: None,
            location_refused: None,
            followable: false,
            out: Vec::new(),
        }
    }

    /// A framer for one hop under `rule`.
    pub fn for_hop(max_entity: usize, rule: HopRule) -> Self {
        Self { rule: Some(rule), ..Self::new(max_entity) }
    }

    pub fn complete(&self) -> bool {
        self.state == State::Done
    }

    /// Whether the final head is parsed and the entity is to be kept: every
    /// final response but a followable redirect.
    pub fn stores_body(&self) -> bool {
        self.status != 0 && !self.followable
    }

    /// Entity bytes framed since the last call (always empty for a
    /// followable redirect).
    pub fn take_entity(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.out)
    }

    pub fn counts(&self) -> Counts {
        Counts { received: self.received, entity: self.entity, declared: self.declared }
    }

    /// Takes decrypted bytes and returns whether the response is complete.
    /// Bytes after the end of the response are not part of it. A failure
    /// leaves `counts` at what was taken, the byte that broke a limit
    /// included.
    pub fn push(&mut self, mut data: &[u8]) -> Result<bool, FrameError> {
        while !data.is_empty() && self.state != State::Done {
            // Never take more than one byte past the wire limit.
            let room = (self.max_wire + 1).saturating_sub(self.received);
            let used = self.step(&data[..data.len().min(room)])?;
            self.received += used;
            self.hasher.update(&data[..used]);
            if self.over || self.received > self.max_wire {
                return Err(FrameError::TooLarge);
            }
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
            body_bytes: self.entity,
            body_sha256: std::mem::take(&mut self.body_hasher).finalize().into(),
            framing: self.framing,
            received: self.received,
            response_sha256: std::mem::take(&mut self.hasher).finalize().into(),
            location: self.location.take(),
            location_refused: self.location_refused,
            followable: self.followable,
        }
    }

    /// Takes entity bytes, at most one past the ceiling, and returns how
    /// many it took.
    fn entity(&mut self, data: &[u8], remaining: usize) -> usize {
        let take = remaining.min(data.len()).min(self.max_entity + 1 - self.entity);
        let bytes = &data[..take];
        self.entity += take;
        if self.entity > self.max_entity {
            self.over = true;
            return take;
        }
        self.body_hasher.update(bytes);
        if !self.followable {
            self.out.extend_from_slice(bytes);
        }
        take
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
                let take = self.entity(data, remaining);
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
                let take = self.entity(data, remaining);
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
            State::Close => self.entity(data, usize::MAX),
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
    /// head after an interim response. The final head also decides, once,
    /// whether the response is a followable redirect.
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
        // A redirect's Location: every value equal, UTF-8, and resolving to
        // a canonical public https URL. It is followed only below the job's
        // redirect limit; the last allowed hop is final either way.
        if let (Some(rule), true, Some(first)) = (&self.rule, REDIRECTS.contains(&status), locations.first()) {
            let resolved = if locations.iter().any(|l| l != first) {
                Err(UrlError::Invalid)
            } else {
                std::str::from_utf8(first).map_err(|_| UrlError::Invalid).and_then(|location| resolve_location(&rule.url, location))
            };
            match resolved {
                Ok(next) => self.location = Some(next),
                Err(refused) => self.location_refused = Some(refused.code()),
            }
            self.followable = self.location.is_some() && rule.can_follow;
        }
        (self.framing, self.state) = if matches!(status, 204 | 304) {
            (Framing::None, State::Done)
        } else if transfer_encoding {
            if codings.last().is_some_and(|c| c == b"chunked") { (Framing::Chunked, State::ChunkSize) } else { (Framing::Close, State::Close) }
        } else if let Some(first) = lengths.first() {
            if lengths.iter().any(|l| l != first) || first.is_empty() || first.len() > 19 || !first.iter().all(u8::is_ascii_digit) {
                return Err(FrameError::Invalid);
            }
            let length = std::str::from_utf8(first).ok().and_then(|s| s.parse::<u64>().ok()).ok_or(FrameError::Invalid)?;
            self.declared = Some(length);
            // Refused at the head, before any body byte is relayed.
            if length > self.max_entity as u64 {
                return Err(FrameError::TooLarge);
            }
            (Framing::ContentLength, if length == 0 { State::Done } else { State::Length(length as usize) })
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

/// Browser-policy values from the contract (B.2, B.3), shared by the tests.
#[cfg(test)]
pub(crate) mod fixtures {
    use super::{request, request_with_node};
    use serde_json::{Value, json};

    pub const DARWIN_UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36";
    pub const WINDOWS_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36";
    pub const LINUX_UA: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36";
    pub const CLEARANCE: &str = "cf_clearance=abc.DEF-123_456; __cf_bm=x1y2";
    pub const CLEARANCE_SHA256: &str = "22c210c1e1510c5c642a8782afa10ebc1eee8d8bb91a7d1dedcec522a446aca7";

    /// The B.2 `web_payload` for `url`.
    pub fn browser_payload(url: &str) -> Value {
        json!({"type":"web.fetch","proof_mode":"relay","proof_policy":"web-browser-v1","url":url,"max_redirects":5,"max_response_bytes":67108864,
            "headers":[{"name":"accept","value":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},{"name":"accept-language","value":"en-US,en;q=0.9"}],
            "node_headers":["user-agent","cookie"]})
    }

    /// The contract's `browser_authorize` refusals, plus neighbours.
    pub(crate) fn browser_refusals() -> Vec<(String, Vec<u8>)> {
        let url = "https://example.com/";
        let headers = crate::webpolicy::validate_job(&browser_payload(url)).unwrap().headers;
        let canonical = String::from_utf8(request_with_node(url, &headers, DARWIN_UA, Some(CLEARANCE))).unwrap();
        let cookie_line = format!("Cookie: {CLEARANCE}\r\n");
        let without = canonical.replace(&cookie_line, "");
        vec![
            ("cookie before accept", without.replacen("Accept: ", &format!("{cookie_line}Accept: "), 1).into_bytes()),
            ("missing user agent", request(url, &headers)),
            ("two cookie lines", canonical.replacen(&cookie_line, &format!("{cookie_line}{cookie_line}"), 1).into_bytes()),
            ("header inside the user agent", request_with_node(url, &headers, &DARWIN_UA.replacen(") ", ")\r\nX-Injected: 1\r\n", 1), None)),
            ("header after the user agent", request_with_node(url, &headers, &format!("{DARWIN_UA}\r\nX-Injected: 1"), None)),
            ("lowercase cookie", canonical.replace("Cookie: ", "cookie: ").into_bytes()),
            ("non-pinned user agent", request_with_node(url, &headers, &DARWIN_UA.replace("Chrome/155", "Chrome/154"), None)),
            ("session cookie", request_with_node(url, &headers, DARWIN_UA, Some("session=x"))),
            ("session among clearance", request_with_node(url, &headers, DARWIN_UA, Some("cf_clearance=a; session=x"))),
            ("cookie grammar", request_with_node(url, &headers, DARWIN_UA, Some("cf_clearance=a;__cf_bm=b"))),
            ("empty cookie", request_with_node(url, &headers, DARWIN_UA, Some(""))),
            ("lowercase user agent", without.replace("User-Agent: ", "user-agent: ").into_bytes()),
            ("user agent twice", without.replacen("Accept: ", &format!("User-Agent: {DARWIN_UA}\r\nAccept: "), 1).into_bytes()),
            ("cookie after accept-encoding", without.replace("Connection: close", &format!("{cookie_line}Connection: close")).into_bytes()),
            ("other header", without.replace("Accept-Encoding", "X-Other: 1\r\nAccept-Encoding").into_bytes()),
            ("padded user agent", request_with_node(url, &headers, &format!(" {DARWIN_UA}"), None)),
            ("other host", request_with_node("https://www.example.com/", &headers, DARWIN_UA, None)),
        ]
        .into_iter()
        .map(|(case, raw)| (case.to_owned(), raw))
        .chain(shared_refusals())
        .collect()
    }

    /// The `browser_authorize` refusals every implementation shares
    /// (`api/web-vectors.json`), all for `https://example.com/`.
    pub(crate) fn shared_refusals() -> Vec<(String, Vec<u8>)> {
        let vectors: Value = serde_json::from_str(include_str!("../../api/web-vectors.json")).unwrap();
        vectors["browser_authorize"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                assert_eq!((v["url"].as_str(), v["refused"].as_str()), (Some("https://example.com/"), Some("request_rejected")), "{v}");
                (v["case"].as_str().unwrap().to_owned(), v["request"].as_str().unwrap().as_bytes().to_vec())
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        fixtures::{CLEARANCE, CLEARANCE_SHA256, DARWIN_UA, LINUX_UA, WINDOWS_UA, browser_payload, browser_refusals, shared_refusals},
        *,
    };
    use serde_json::json;

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../../api/web-vectors.json")).unwrap()
    }

    fn browser_job() -> Job {
        validate_job(&browser_payload("https://example.com/")).unwrap()
    }

    fn node(user_agent: &str, cookie: Option<&str>) -> NodeHeaders {
        NodeHeaders { user_agent: user_agent.into(), cookie: cookie.map(Into::into) }
    }

    #[test]
    fn browser_request_bytes_match_the_contract() {
        let job = browser_job();
        let plain = request_with_node("https://example.com/", &job.headers, DARWIN_UA, None);
        let expected = format!(
            "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: {DARWIN_UA}\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.9\r\nAccept-Encoding: gzip, deflate, br\r\nConnection: close\r\n\r\n"
        );
        assert_eq!(plain, expected.as_bytes());
        assert_eq!(format!("{:x}", Sha256::digest(&plain)), "633dcef6749617f2c417104a95c41141971690764338087f7013b2255065c288");
        let with_cookie = request_with_node("https://example.com/", &job.headers, DARWIN_UA, Some(CLEARANCE));
        let expected = expected.replace("Accept-Encoding", &format!("Cookie: {CLEARANCE}\r\nAccept-Encoding"));
        assert_eq!(with_cookie, expected.as_bytes());
        assert_eq!(format!("{:x}", Sha256::digest(&with_cookie)), "c60f3dee15090ef6bd9b9b70695ed3f89884ae089850179e92a9be061e9160cb");
        assert_eq!(node(DARWIN_UA, Some(CLEARANCE)).cookie_sha256().as_deref(), Some(CLEARANCE_SHA256));
        assert_eq!(node(DARWIN_UA, None).cookie_sha256(), None);
        // The job builds the same bytes, and only with the node's headers.
        assert_eq!(job.hop_request("https://example.com/", Some(&node(DARWIN_UA, Some(CLEARANCE)))).unwrap(), with_cookie);
        assert!(job.hop_request("https://example.com/", None).is_err());
        assert!(job.hop_request("https://example.com/", Some(&node(DARWIN_UA, Some("session=x")))).is_err());
        let relay = validate_job(&payload()).unwrap();
        assert!(relay.hop_request("https://example.com/", Some(&node(DARWIN_UA, None))).is_err());
        assert_eq!(relay.hop_request("https://example.com/", None).unwrap(), request("https://example.com/", &relay.headers));
    }

    #[test]
    fn cookie_grammar_vectors() {
        let fifty = (0..50).map(|i| format!("_px{i}=v")).collect::<Vec<_>>().join("; ");
        let fits = format!("a={}", "b".repeat(MAX_COOKIE - 2));
        for valid in ["a=b", "a=", "q=\"x\"", "q=\"\"", CLEARANCE, "a=b; a=c", "a=x=y", fifty.as_str(), fits.as_str()] {
            assert!(valid_cookie(valid), "{valid} refused");
        }
        let fifty_one = format!("{fifty}; a=b");
        let long = format!("a={}", "b".repeat(4097));
        for invalid in ["a=b;c=d", "=b", "a b=c", "a=b c", "a=b,c", "a=b; ", "a=\u{7f}", "", "a", "a=\"x", "a=x\"", "a=\"", "a=b;  c=d", " a=b", "a=b\\c", "a=é", "a=b\r\nX: y", long.as_str(), fifty_one.as_str()] {
            assert!(!valid_cookie(invalid), "{invalid:?} accepted");
        }
        assert!(!valid_cookie(&format!("{}=v", "a".repeat(257))) && valid_cookie(&format!("{}=v", "a".repeat(256))));
        assert_eq!(cookie_names(CLEARANCE), ["cf_clearance", "__cf_bm"]);
        assert_eq!(cookie_names("a=b; a=c=d"), ["a", "a"]);
    }

    #[test]
    fn clearance_cookie_name_vectors() {
        for allowed in [
            "cf_clearance", "__cf_bm", "_cfuvid", "datadome", "_abck", "bm_sz", "ak_bmsc", "bm_sv", "pxcts", "reese84", "aws-waf-token", "_px3", "_pxhd", "incap_ses_123_456", "visid_incap_789", "nlbi_1",
            "bm_s", "bm_so", "bm_sc", "bm_lso", "bm_mi", "sbsd", "sbsd_o", "sec_cpt", "___utmvc", "KP_UIDz", "KP_UIDz-ssn", "tkrm_alpekz_s1.3", "tkrm_alpekz_s1.3-ssn", "incap_sh_2483049",
        ] {
            assert!(clearance_cookie(allowed), "{allowed} refused");
        }
        for refused in [
            "session", "sid", "CF_CLEARANCE", "cf_clearance2", "_px", "incap_ses_", "__Secure-session", "visid_incap_", "nlbi_", "", "xcf_clearance", "incap_sh_", "SBSD", "sbsd_x", "sec_cpt2",
            "kp_uidz", "KP_UID", "KP_UIDz-ssn2", "tkrm_alpekz", "tkrm_alpekz_s1.4", "__utmvc", "bm_", "bm_s2",
        ] {
            assert!(!clearance_cookie(refused), "{refused} accepted");
        }
        // Grammar and names are separate checks; a receipt's list needs both and must fit one header.
        let names = |list: &[&str]| list.iter().map(|n| n.to_string()).collect::<Vec<_>>();
        assert!(allowed_cookie_names(&names(&["cf_clearance", "__cf_bm"])) && allowed_cookie_names(&[]));
        assert!(!allowed_cookie_names(&names(&["cf_clearance", "session"])));
        assert!(!allowed_cookie_names(&names(&["_px a"])));
        assert!(!allowed_cookie_names(&vec!["_px1".to_string(); 51]));
        assert!(allowed_cookie_names(&vec![format!("_px{}", "a".repeat(253)); 13]) && !allowed_cookie_names(&vec![format!("_px{}", "a".repeat(253)); 16]));
    }

    #[test]
    fn user_agent_vectors() {
        assert_eq!(user_agent("darwin", 155).as_deref(), Some(DARWIN_UA));
        assert_eq!(user_agent("windows", 155).as_deref(), Some(WINDOWS_UA));
        assert_eq!(user_agent("linux", 155).as_deref(), Some(LINUX_UA));
        assert_eq!(user_agent("android", 155), None);
        for allowed in [DARWIN_UA, WINDOWS_UA, LINUX_UA] {
            assert!(pinned_user_agent(allowed) && browser_user_agent(allowed), "{allowed}");
        }
        let refused = [
            DARWIN_UA.replace("Chrome/155", "Chrome/154"),
            DARWIN_UA.replace("Chrome/155", "Chrome/156"),
            "Googlebot/2.1 (+http://www.google.com/bot.html)".into(),
            format!("{DARWIN_UA} "),
            "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Mobile Safari/537.36".into(),
            DARWIN_UA.replace("Chrome/155.0.0.0", "Chrome/155.0.8059.39"),
            DARWIN_UA.replace("Chrome/155", "Chrome/0155"),
            DARWIN_UA.replace("Chrome/155", "HeadlessChrome/155"),
            String::new(),
        ];
        for value in &refused {
            assert!(!pinned_user_agent(value), "{value} accepted");
        }
        // A receipt may keep a UA from before a pin bump; it must still have the browser's shape.
        assert!(browser_user_agent(&refused[0]) && browser_user_agent(&refused[1]));
        assert!(refused[2..].iter().all(|value| !browser_user_agent(value)));
    }

    #[test]
    fn browser_authorize_accepts_exactly_the_canonical_forms() {
        let job = browser_job();
        let url = "https://example.com/";
        for ua in [DARWIN_UA, WINDOWS_UA, LINUX_UA] {
            for cookie in [None, Some(CLEARANCE), Some("datadome=Ab~9_-.z"), Some("_pxhd=\"q\"; _px3=1; _px3=2")] {
                let raw = request_with_node(url, &job.headers, ua, cookie);
                assert_eq!(authorize(&job, url, &raw).unwrap(), Some(node(ua, cookie)), "{ua} {cookie:?}");
            }
        }
        // A later hop is authorized for its own URL only.
        let next = "https://www.example.com/next?q=1";
        let raw = request_with_node(next, &job.headers, DARWIN_UA, Some(CLEARANCE));
        assert!(authorize(&job, next, &raw).is_ok() && authorize(&job, url, &raw).is_err());
        // A relay job still takes exactly its request, and no node header.
        let relay = validate_job(&payload()).unwrap();
        assert_eq!(authorize(&relay, url, &request(url, &relay.headers)).unwrap(), None);
        let mut relay_with_cookie = request(url, &relay.headers);
        let at = find(&relay_with_cookie, b"Accept-Encoding").unwrap();
        relay_with_cookie.splice(at..at, format!("Cookie: {CLEARANCE}\r\n").into_bytes());
        assert!(authorize(&relay, url, &relay_with_cookie).is_err());
    }

    /// The browser vectors every implementation shares (`api/web-vectors.json`).
    #[test]
    fn shared_browser_vectors() {
        let vectors = vectors();
        assert_eq!(vectors["version"], 2);
        let defaults: Vec<Header> = serde_json::from_value(vectors["browser_default_headers"].clone()).unwrap();
        assert_eq!(defaults, browser_job().headers);
        let requests = vectors["browser_requests"].as_array().unwrap();
        assert!(requests.iter().any(|v| v.get("cookie").is_some()) && requests.iter().any(|v| v.get("cookie").is_none()));
        for v in requests {
            let (url, ua, cookie) = (v["url"].as_str().unwrap(), v["user_agent"].as_str().unwrap(), v["cookie"].as_str());
            let headers: Vec<Header> = serde_json::from_value(v["headers"].clone()).unwrap();
            let bytes = request_with_node(url, &headers, ua, cookie);
            assert_eq!(bytes, v["bytes"].as_str().unwrap().as_bytes());
            assert_eq!(format!("{:x}", Sha256::digest(&bytes)), v["sha256"].as_str().unwrap());
            assert_eq!(node(ua, cookie).cookie_sha256().as_deref(), v["cookie_sha256"].as_str());
            // These are exactly what the verifier authorizes.
            let job = validate_job(&browser_payload(url)).unwrap();
            assert_eq!(authorize(&job, url, &bytes).unwrap(), Some(node(ua, cookie)));
        }
        for valid in vectors["cookies"]["valid"].as_array().unwrap() {
            assert!(valid_cookie(valid.as_str().unwrap()), "{valid} refused");
        }
        for invalid in vectors["cookies"]["invalid"].as_array().unwrap() {
            assert!(!valid_cookie(invalid.as_str().unwrap()), "{invalid} accepted");
        }
        for allowed in vectors["cookie_names"]["allowed"].as_array().unwrap() {
            assert!(clearance_cookie(allowed.as_str().unwrap()), "{allowed} refused");
        }
        for refused in vectors["cookie_names"]["refused"].as_array().unwrap() {
            assert!(!clearance_cookie(refused.as_str().unwrap()), "{refused} accepted");
        }
        for allowed in vectors["user_agents"]["allowed"].as_array().unwrap() {
            assert!(pinned_user_agent(allowed.as_str().unwrap()), "{allowed} refused");
        }
        for refused in vectors["user_agents"]["refused"].as_array().unwrap() {
            assert!(!pinned_user_agent(refused.as_str().unwrap()), "{refused} accepted");
        }
        assert!(shared_refusals().len() >= 7);
    }

    #[test]
    fn browser_authorize_refuses_every_other_form() {
        let job = browser_job();
        for (case, raw) in browser_refusals() {
            let error = authorize(&job, "https://example.com/", &raw).expect_err(&case);
            // Refusals never quote what the node sent.
            let text = format!("{error:#}");
            assert!(!text.contains("abc.DEF") && !text.contains("session=") && !text.contains("Mozilla"), "{case}: {text}");
        }
    }

    #[test]
    fn validates_the_browser_payload_and_rejects_every_mutation() {
        let job = browser_job();
        assert_eq!((job.policy, job.max_redirects, job.max_response_bytes, job.headers.len()), (Policy::Browser, 5, PAGE_MAX, 2));
        assert_eq!((Policy::Browser.name(), Policy::Relay.name()), ("web-browser-v1", "web-relay-v1"));
        assert_eq!(validate_job(&payload()).unwrap().policy, Policy::Relay);
        // The coordinator registers it as these exact bytes (B.2's request_sha256).
        assert_eq!(format!("{:x}", Sha256::digest(serde_json::to_vec(&browser_payload("https://example.com/")).unwrap())), "964f55b17be3ad0fb55ae96c3a1cdd36883b9a2f4833da2946c1eeefcdd62ba7");
        let mutations: Vec<(&str, Box<dyn Fn(&mut Value)>)> = vec![
            ("user agent header", Box::new(|p| p["headers"].as_array_mut().unwrap().insert(0, json!({"name":"user-agent","value":DARWIN_UA})))),
            ("header order", Box::new(|p| p["headers"].as_array_mut().unwrap().swap(0, 1))),
            ("missing header", Box::new(|p| drop(p["headers"].as_array_mut().unwrap().pop()))),
            ("other accept", Box::new(|p| p["headers"][0]["value"] = "*/*".into())),
            ("cookie header", Box::new(|p| p["headers"].as_array_mut().unwrap().push(json!({"name":"cookie","value":"a=b"})))),
            ("no node headers", Box::new(|p| drop(p.as_object_mut().unwrap().remove("node_headers")))),
            ("null node headers", Box::new(|p| p["node_headers"] = Value::Null)),
            ("node header order", Box::new(|p| p["node_headers"] = json!(["cookie","user-agent"]))),
            ("node headers missing cookie", Box::new(|p| p["node_headers"] = json!(["user-agent"]))),
            ("node headers extra", Box::new(|p| p["node_headers"] = json!(["user-agent","cookie","accept"]))),
            ("node header case", Box::new(|p| p["node_headers"] = json!(["User-Agent","cookie"]))),
            ("fewer redirects", Box::new(|p| p["max_redirects"] = 4.into())),
            ("smaller pages", Box::new(|p| p["max_response_bytes"] = (1 << 20).into())),
            ("other policy", Box::new(|p| p["proof_policy"] = "web-browser-v2".into())),
            ("mpc", Box::new(|p| p["proof_mode"] = "mpc".into())),
            ("unknown field", Box::new(|p| p["mode"] = "browser".into())),
        ];
        for (name, mutate) in mutations {
            let mut p = browser_payload("https://example.com/");
            mutate(&mut p);
            assert!(validate_job(&p).is_err(), "{name} accepted");
        }
        // A relay job takes no node headers at all, not even null or empty.
        for node_headers in [json!(["user-agent","cookie"]), json!([]), Value::Null] {
            let mut p = payload();
            p["node_headers"] = node_headers.clone();
            assert!(validate_job(&p).is_err(), "relay with {node_headers}");
        }
    }

    #[test]
    fn node_headers_deserialize_strictly_and_never_print_the_cookie() {
        let parse = |v: Value| serde_json::from_value::<NodeHeaders>(v);
        assert_eq!(parse(json!({"user_agent":DARWIN_UA})).unwrap(), node(DARWIN_UA, None));
        assert_eq!(parse(json!({"user_agent":DARWIN_UA,"cookie":CLEARANCE})).unwrap(), node(DARWIN_UA, Some(CLEARANCE)));
        for bad in [json!({"user_agent":DARWIN_UA,"cookie":null}), json!({"cookie":CLEARANCE}), json!({"user_agent":DARWIN_UA,"other":1}), json!({"user_agent":null})] {
            assert!(parse(bad.clone()).is_err(), "{bad}");
        }
        let debug = format!("{:?}", node(DARWIN_UA, Some(CLEARANCE)));
        assert!(debug.contains("cf_clearance") && !debug.contains("abc.DEF") && !debug.contains("x1y2"), "{debug}");
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
        json!({"type":"web.fetch","proof_mode":"relay","proof_policy":"web-relay-v1","url":"https://example.com/","max_redirects":5,"max_response_bytes":67108864,"headers":vectors()["default_headers"]})
    }

    #[test]
    fn validates_the_contract_payload_and_rejects_every_mutation() {
        let job = validate_job(&payload()).unwrap();
        assert_eq!((job.url.as_str(), job.max_redirects, job.max_response_bytes, job.headers.len()), ("https://example.com/", 5, PAGE_MAX, 3));
        let mut minimal = payload();
        minimal["headers"] = json!([]);
        minimal["max_redirects"] = 0.into();
        assert!(validate_job(&minimal).is_ok());
        // The relay payload of the node contract (api/fixtures/lease-web.json) hashes to its request_sha256.
        assert_eq!(format!("{:x}", Sha256::digest(serde_json::to_vec(&payload()).unwrap())), "d4362de8c9e08295b9a777f758e8f9833a4257b30b689c391d609c0e4a7c610c");
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
            ("bytes", Box::new(|p| p["max_response_bytes"] = (PAGE_MAX + 1).into())),
            ("fewer bytes", Box::new(|p| p["max_response_bytes"] = (PAGE_MAX - 1).into())),
            ("ten MiB", Box::new(|p| p["max_response_bytes"] = (10u64 << 20).into())),
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

    /// Frames a whole response and returns it with its entity.
    fn frame(response: &[u8], max: usize) -> Result<(Response, Vec<u8>), FrameError> {
        let mut framer = Framer::new(max);
        if !framer.push(response)? {
            framer.close_notify()?;
        }
        let body = framer.take_entity();
        Ok((framer.finish(), body))
    }

    #[test]
    fn content_length_and_bodyless_responses() {
        let (r, body) = frame(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhelloEXTRA", 1 << 20).unwrap();
        assert_eq!((r.status, body.as_slice(), r.framing, r.received, r.body_bytes), (200, &b"hello"[..], Framing::ContentLength, 62, 5));
        assert_eq!(r.body_sha256, <[u8; 32]>::from(Sha256::digest(b"hello")));
        assert_eq!(r.head, b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n");
        assert_eq!(r.response_sha256, <[u8; 32]>::from(Sha256::digest(&b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello"[..])));
        for head in [&b"HTTP/1.1 204 No Content\r\nContent-Length: 10\r\n\r\n"[..], b"HTTP/1.0 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n", b"HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n"] {
            let mut framer = Framer::new(1 << 20);
            assert!(framer.push(head).unwrap());
            assert!(framer.take_entity().is_empty());
            assert_eq!(framer.finish().body_bytes, 0);
        }
        // Without a hop rule nothing is resolved or followed.
        let (r, _) = frame(b"HTTP/1.1 301 Moved\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n", 1 << 20).unwrap();
        assert_eq!((r.framing, r.location, r.followable), (Framing::ContentLength, None, false));
        // Conflicting lengths are refused, whether on one line or several.
        for head in [&b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n"[..], b"HTTP/1.1 200 OK\r\nContent-Length: 5, 6\r\n\r\n", b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n", b"HTTP/1.1 200 OK\r\nContent-Length: 0x5\r\n\r\n"] {
            assert_eq!(Framer::new(1 << 20).push(head).err(), Some(FrameError::Invalid));
        }
    }

    #[test]
    fn chunked_bodies_parse_at_every_split_without_rescanning() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n5;name=value\r\nhello\r\n7 ; x\r\n, world\r\n0\r\nX-Trailer: yes\r\nOther: 1\r\n\r\nNEXT";
        let (whole, whole_body) = frame(response, 1 << 20).unwrap();
        assert_eq!((whole_body.as_slice(), whole.framing, whole.received, whole.body_bytes), (&b"hello, world"[..], Framing::Chunked, response.len() - 4, 12));
        for split in 0..response.len() {
            let mut framer = Framer::new(1 << 20);
            let first = framer.push(&response[..split]).unwrap();
            assert!(!first || split >= response.len() - 4, "complete early at {split}");
            let mut body = framer.take_entity();
            assert!(framer.push(&response[split..]).unwrap(), "split at {split}");
            body.extend(framer.take_entity());
            let r = framer.finish();
            assert_eq!((body.as_slice(), r.received, r.response_sha256, r.body_sha256), (whole_body.as_slice(), whole.received, whole.response_sha256, whole.body_sha256));
        }
        // Byte by byte as well.
        let mut framer = Framer::new(1 << 20);
        let mut body = Vec::new();
        for byte in response {
            framer.push(std::slice::from_ref(byte)).unwrap();
            body.extend(framer.take_entity());
        }
        assert_eq!(body, b"hello, world");
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
        let (r, body) = frame(response, 1 << 20).unwrap();
        assert_eq!((r.status, body.as_slice()), (200, &b"ok"[..]));
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
            let body = framer.take_entity();
            let r = framer.finish();
            assert_eq!((body.as_slice(), r.framing, r.body_bytes), (&b"partial page"[..], Framing::Close, 12));
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
        // The ceiling is on entity bytes: heads and framing do not count.
        let body = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n";
        assert!(!Framer::new(100).push(body).unwrap());
        let mut framer = Framer::new(99);
        assert_eq!(framer.push(body).err(), Some(FrameError::TooLarge));
        assert_eq!(framer.counts(), Counts { received: body.len(), entity: 0, declared: Some(100) });
        let mut framer = Framer::new(31);
        framer.push(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap();
        assert_eq!(framer.push(b"20\r\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n").err(), Some(FrameError::TooLarge));
        assert_eq!((framer.counts().entity, framer.counts().declared), (32, None));
        let mut framer = Framer::new(39);
        framer.push(b"HTTP/1.0 200 OK\r\n\r\n").unwrap();
        assert_eq!(framer.push(&[b'a'; 50]).err(), Some(FrameError::TooLarge));
        // Counting stops at the first byte over the ceiling.
        assert_eq!(framer.counts(), Counts { received: 19 + 40, entity: 40, declared: None });
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
        let (r, body) = frame(b"HTTP/1.1 999 Request denied\r\nContent-Length: 3\r\n\r\n\xff\x00\xfe", 1 << 20).unwrap();
        assert_eq!((r.status, body.as_slice()), (999, &b"\xff\x00\xfe"[..]));
    }

    /// A response's entity streamed through a framer in `chunk`-byte
    /// pushes, discarding what it hands out; returns the response, how many
    /// entity bytes it handed out and their SHA-256.
    fn stream(framer: &mut Framer, parts: impl IntoIterator<Item = Vec<u8>>) -> Result<(usize, [u8; 32]), FrameError> {
        let (mut handed, mut hash) = (0, Sha256::new());
        for part in parts {
            for piece in part.chunks(16 << 10) {
                framer.push(piece)?;
                let out = framer.take_entity();
                handed += out.len();
                hash.update(&out);
            }
        }
        Ok((handed, hash.finalize().into()))
    }

    /// `PAGE_MAX + extra` entity bytes in chunks of `size`, as a chunked response.
    fn chunked_page(size: usize, extra: usize) -> impl Iterator<Item = Vec<u8>> {
        let total = PAGE_MAX + extra;
        let head = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        std::iter::once(head)
            .chain((0..total.div_ceil(size)).map(move |i| {
                let n = size.min(total - i * size);
                let mut chunk = format!("{n:x}\r\n").into_bytes();
                chunk.extend(std::iter::repeat_n(b'a' + (i % 26) as u8, n));
                chunk.extend(b"\r\n");
                chunk
            }))
            .chain(std::iter::once(b"0\r\n\r\n".to_vec()))
    }

    #[test]
    fn a_page_of_exactly_the_ceiling_passes_in_small_chunks_and_one_byte_more_does_not() {
        assert_eq!((PAGE_MAX, max_wire(PAGE_MAX)), (67_108_864, 68_222_976));
        for size in [1 << 10, 8 << 10] {
            let mut framer = Framer::new(PAGE_MAX);
            let (handed, hash) = stream(&mut framer, chunked_page(size, 0)).unwrap();
            assert!(framer.complete(), "{size}");
            let r = framer.finish();
            assert_eq!((handed, r.body_bytes, r.framing), (PAGE_MAX, PAGE_MAX, Framing::Chunked), "{size}");
            assert_eq!(hash, r.body_sha256);
            assert!(r.received > PAGE_MAX && r.received <= max_wire(PAGE_MAX), "{size}: {}", r.received);
        }
        let mut framer = Framer::new(PAGE_MAX);
        assert_eq!(stream(&mut framer, chunked_page(8 << 10, 1)).err(), Some(FrameError::TooLarge));
        let counts = framer.counts();
        assert_eq!((counts.entity, counts.declared), (PAGE_MAX + 1, None));
        assert!(counts.received > PAGE_MAX + 1);
        // Content-Length: exactly the ceiling streams; one more is refused at the head.
        let head = |n: usize| format!("HTTP/1.1 200 OK\r\nContent-Length: {n}\r\n\r\n").into_bytes();
        let mut framer = Framer::new(PAGE_MAX);
        let (handed, _) = stream(&mut framer, [head(PAGE_MAX), vec![b'x'; PAGE_MAX]]).unwrap();
        assert_eq!((handed, framer.complete()), (PAGE_MAX, true));
        let mut framer = Framer::new(PAGE_MAX);
        assert_eq!(framer.push(&head(PAGE_MAX + 1)).err(), Some(FrameError::TooLarge));
        assert_eq!(framer.counts(), Counts { received: head(PAGE_MAX + 1).len(), entity: 0, declared: Some(PAGE_MAX as u64 + 1) });
        // Close-delimited: counting stops one byte over.
        let mut framer = Framer::new(PAGE_MAX);
        let close = b"HTTP/1.0 200 OK\r\n\r\n".to_vec();
        assert_eq!(stream(&mut framer, [close.clone(), vec![b'y'; PAGE_MAX + 100]]).err(), Some(FrameError::TooLarge));
        assert_eq!(framer.counts(), Counts { received: close.len() + PAGE_MAX + 1, entity: PAGE_MAX + 1, declared: None });
        // Framing beyond max_wire is too large even when the entity is not:
        // one-byte chunks cost six wire bytes each.
        let mut framer = Framer::new(1 << 20);
        let tiny: Vec<Vec<u8>> = std::iter::once(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec()).chain(std::iter::repeat_n(b"1\r\na\r\n".to_vec(), 400_000)).collect();
        assert_eq!(stream(&mut framer, tiny).err(), Some(FrameError::TooLarge));
        assert!(framer.counts().entity < 1 << 20);
        assert_eq!(framer.counts().received, max_wire(1 << 20) + 1);
    }

    #[test]
    fn followability_is_decided_once_at_the_final_head() {
        let rule = |can_follow| HopRule { url: "https://example.com/a/b".into(), can_follow };
        let run = |response: &[u8], can_follow| {
            let mut framer = Framer::for_hop(1 << 20, rule(can_follow));
            assert!(framer.push(response).unwrap());
            let body = framer.take_entity();
            (framer.finish(), body)
        };
        // A followable redirect: its body is hashed and counted, never handed out.
        let (r, body) = run(b"HTTP/1.1 302 Found\r\nLocation: /next?x=1\r\nContent-Length: 5\r\n\r\nmoved", true);
        assert_eq!((r.location.as_deref(), r.location_refused, r.followable, body.len(), r.body_bytes), (Some("https://example.com/next?x=1"), None, true, 0, 5));
        assert_eq!(r.body_sha256, <[u8; 32]>::from(Sha256::digest(b"moved")));
        // The same redirect on the last allowed hop is final and keeps its body.
        let (r, body) = run(b"HTTP/1.1 302 Found\r\nLocation: /next?x=1\r\nContent-Length: 5\r\n\r\nmoved", false);
        assert_eq!((r.location.as_deref(), r.followable, body.as_slice()), (Some("https://example.com/next?x=1"), false, &b"moved"[..]));
        // A refused Location, and conflicting ones, are final with their reason and body.
        for (head, reason) in [
            (&b"HTTP/1.1 301 Moved\r\nLocation: http://example.com/\r\nContent-Length: 4\r\n\r\nbody"[..], "insecure"),
            (b"HTTP/1.1 307 Temporary\r\nLocation: /a\r\nLocation: /b\r\nContent-Length: 4\r\n\r\nbody", "invalid"),
            (b"HTTP/1.1 308 Permanent\r\nLocation: \xff\r\nContent-Length: 4\r\n\r\nbody", "invalid"),
            (b"HTTP/1.1 303 See Other\r\nLocation: https://x.com/\r\nContent-Length: 4\r\n\r\nbody", "x_host"),
        ] {
            let (r, body) = run(head, true);
            assert_eq!((r.location.as_deref(), r.location_refused, r.followable, body.as_slice()), (None, Some(reason), false, &b"body"[..]), "{reason}");
        }
        // Equal repeated Locations are one; a 3xx outside the five, or without a Location, is final.
        let (r, _) = run(b"HTTP/1.1 301 Moved\r\nLocation: /n\r\nLocation: /n\r\nContent-Length: 0\r\n\r\n", true);
        assert!(r.followable);
        for head in [&b"HTTP/1.1 300 Multiple\r\nLocation: /n\r\nContent-Length: 1\r\n\r\nx"[..], b"HTTP/1.1 302 Found\r\nContent-Length: 1\r\n\r\nx"] {
            let (r, body) = run(head, true);
            assert_eq!((r.location, r.location_refused, r.followable, body.as_slice()), (None, None, false, &b"x"[..]));
        }
        // An interim head's Location decides nothing.
        let (r, body) = run(b"HTTP/1.1 103 Early\r\nLocation: /n\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", true);
        assert_eq!((r.status, r.followable, r.location, body.as_slice()), (200, false, None, &b"ok"[..]));
    }
}
