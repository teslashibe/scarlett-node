//! What a verifier accepts for an X read: one GraphQL GET to x.com that is
//! exactly one of the reads the job pins, hiding only the session cookie
//! values and CSRF token, with X's response fully revealed.

use std::{fmt, io::Read, ops::Range};

use anyhow::{Context, Result, bail};
use serde::{
    Deserialize, Serialize,
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Value};

use crate::policy::find;

pub const HOST: &str = "x.com";
const GRAPHQL: &str = "/i/api/graphql/";
/// Cookies whose values the supplier may hide, with the longest value allowed.
/// Their names, the other cookies and the rest of the request stay revealed.
const SECRET_COOKIES: [(&str, usize); 3] = [("auth_token", 64), ("ct0", 160), ("kdt", 64)];
/// The CSRF header carries the ct0 value, so it may be hidden too.
const CSRF_HEADER: (&str, usize) = ("x-csrf-token", 160);
/// Headers that change how a server frames or routes a request. None of them
/// belongs on a GraphQL GET.
const FORBIDDEN_HEADERS: &[&str] = &[
    "content-length",
    "transfer-encoding",
    "te",
    "trailer",
    "expect",
    "upgrade",
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
    "x-original-url",
    "x-rewrite-url",
];
/// Read-only GraphQL operations x-go issues. Writes are POSTs and never allowed.
pub const READ_OPERATIONS: &[&str] = &[
    "Viewer",
    "UserByRestId",
    "UserByScreenName",
    "UserTweets",
    "TweetResultByRestId",
    "TweetDetail",
    "SearchTimeline",
    "Followers",
    "Following",
    "ListBySlug",
    "ListLatestTweetsTimeline",
    "ListMembers",
    "HomeTimeline",
    "HomeLatestTimeline",
];
const MAX_BODY: usize = 8 << 20;
const MAX_EXCHANGES: usize = 100;
const MAX_ATTEMPTS: usize = 200;

/// One read the job pays for, pinned exactly: the request must carry this
/// query ID, variables and features, and field toggles only if given.
/// `cursor_from: k` asks for the page after exchange k: the request's
/// variables are `variables` plus a `cursor` taken from the response the
/// verifier recorded for k.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    pub operation: String,
    pub query_id: String,
    pub variables: Value,
    pub features: Value,
    #[serde(default)]
    pub field_toggles: Option<Value>,
    #[serde(default)]
    pub cursor_from: Option<usize>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Job {
    #[serde(rename = "type")]
    kind: String,
    exchanges: Vec<Spec>,
    #[serde(default)]
    max_attempts: Option<usize>,
}

/// A proven X read as the verifier parsed it from the transcript.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Exchange {
    pub operation: String,
    pub query_id: String,
    pub variables: Value,
    pub features: Option<Value>,
    pub field_toggles: Option<Value>,
    pub http_status: u16,
    pub body: String,
}

/// An X job payload: `{"type":"x.read","exchanges":[Spec...],"max_attempts":n}`.
/// Returns the pinned exchanges and how many proofs the session allows.
pub fn validate_job(job: &Value) -> Result<(Vec<Spec>, usize)> {
    let job: Job = serde_json::from_value(job.clone()).context("invalid x.read job")?;
    if job.kind != "x.read" {
        bail!("job payload must be an x.read");
    }
    let n = job.exchanges.len();
    if !(1..=MAX_EXCHANGES).contains(&n) {
        bail!("x.read needs 1-{MAX_EXCHANGES} exchanges");
    }
    for (i, spec) in job.exchanges.iter().enumerate() {
        let at = |what: &str| format!("exchange {i}: {what}");
        if job.exchanges[..i].contains(spec) {
            bail!(at("duplicate requested read"));
        }
        if !READ_OPERATIONS.contains(&spec.operation.as_str()) {
            bail!(at("operation is not an allowed read"));
        }
        if !valid_query_id(&spec.query_id) {
            bail!(at("invalid query_id"));
        }
        for value in [Some(&spec.variables), Some(&spec.features), spec.field_toggles.as_ref()].into_iter().flatten() {
            if !value.is_object() {
                bail!(at("variables, features and field_toggles must be objects"));
            }
            if !integers_only(value) {
                bail!(at("numbers must be 64-bit integers"));
            }
        }
        if let Some(k) = spec.cursor_from {
            if k >= i {
                bail!(at("cursor_from must name an earlier exchange"));
            }
            if spec.variables.get("cursor").is_some() {
                bail!(at("variables must not carry a cursor when cursor_from is set"));
            }
            // The next page of the same read: only the cursor may differ.
            let source = &job.exchanges[k];
            let mut previous = source.variables.clone();
            previous.as_object_mut().map(|v| v.remove("cursor"));
            if source.operation != spec.operation || previous != spec.variables {
                bail!(at("cursor_from must name the same operation with the same variables"));
            }
        }
    }
    let max = job.max_attempts.unwrap_or((2 * n).min(MAX_ATTEMPTS));
    if !(n..=MAX_ATTEMPTS).contains(&max) {
        bail!("max_attempts must be between the number of exchanges and {MAX_ATTEMPTS}");
    }
    Ok((job.exchanges, max))
}

fn valid_query_id(q: &str) -> bool {
    (1..=64).contains(&q.len()) && q.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn integers_only(value: &Value) -> bool {
    match value {
        Value::Number(n) => n.is_i64() || n.is_u64(),
        Value::Array(items) => items.iter().all(integers_only),
        Value::Object(map) => map.values().all(integers_only),
        _ => true,
    }
}

/// Whether a proven read can fulfil an exchange, which takes HTTP 200 with a
/// non-empty `data` object, and the next-page cursors in its response.
pub fn outcome(e: &Exchange) -> (bool, Vec<String>) {
    if e.http_status != 200 {
        return (false, Vec::new());
    }
    let Ok(value) = serde_json::from_str::<Value>(&e.body) else { return (false, Vec::new()) };
    if !value.get("data").and_then(Value::as_object).is_some_and(|d| !d.is_empty()) {
        return (false, Vec::new());
    }
    (true, bottom_cursors(&value))
}

/// Which exchange of `job` a proven read fulfils or retries, given the
/// exchanges already fulfilled as `(index, proven request, response cursors)`. An
/// exchange is pending until a matching read fulfils it, and a paged exchange
/// only once its source is fulfilled.
pub fn assign(job: &[Spec], fulfilled: &[(usize, &Exchange, &[String])], got: &Exchange) -> Result<usize> {
    // A looping pagination cursor or repeated requested read must not turn the
    // same proven request into another unit of useful work. Response bytes are
    // not identity: distinct pages may legitimately have identical bodies.
    if fulfilled.iter().any(|(_, e, _)| {
        e.operation == got.operation && e.query_id == got.query_id && e.variables == got.variables
            && e.features == got.features && e.field_toggles == got.field_toggles
    }) {
        bail!("request already fulfilled");
    }
    let cursors_of = |i: usize| fulfilled.iter().find(|(k, _, _)| *k == i).map(|(_, _, c)| *c);
    for (i, spec) in job.iter().enumerate() {
        if cursors_of(i).is_some() {
            continue;
        }
        let cursors = match spec.cursor_from {
            Some(k) => match cursors_of(k) {
                Some(cursors) => Some(cursors),
                None => continue,
            },
            None => None,
        };
        if matches(spec, cursors, got) {
            return Ok(i);
        }
    }
    let mut shown = got.variables.to_string();
    if shown.len() > 300 {
        shown.truncate(shown.floor_char_boundary(300));
        shown.push('…');
    }
    bail!("{} {shown} matches no pending exchange", got.operation)
}

fn matches(spec: &Spec, cursors: Option<&[String]>, got: &Exchange) -> bool {
    if spec.operation != got.operation
        || spec.query_id != got.query_id
        || got.features.as_ref() != Some(&spec.features)
        || got.field_toggles != spec.field_toggles
    {
        return false;
    }
    let Some(cursors) = cursors else { return spec.variables == got.variables };
    let mut variables = got.variables.clone();
    let Some(cursor) = variables.as_object_mut().and_then(|v| v.remove("cursor")) else { return false };
    cursor.as_str().is_some_and(|c| cursors.iter().any(|known| known == c)) && variables == spec.variables
}

/// Values of X's `Bottom` timeline cursors in a response, where x-go finds
/// them: the content of an entry of a timeline instruction, typed as
/// `TimelineTimelineCursor`. Never text inside strings, and never cursors
/// nested in modules or conversation threads.
fn bottom_cursors(value: &Value) -> Vec<String> {
    fn walk(value: &Value, out: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                for instruction in map.get("instructions").and_then(Value::as_array).into_iter().flatten() {
                    let entries = instruction.get("entries").and_then(Value::as_array).into_iter().flatten();
                    for entry in entries.chain(instruction.get("entry")) {
                        let content = &entry["content"];
                        let typed = ["entryType", "__typename"].iter().any(|k| content[*k] == "TimelineTimelineCursor");
                        if typed
                            && content["cursorType"] == "Bottom"
                            && let Some(v) = content["value"].as_str().filter(|v| !v.is_empty())
                        {
                            out.push(v.to_owned());
                        }
                    }
                }
                map.values().for_each(|v| walk(v, out));
            }
            Value::Array(items) => items.iter().for_each(|v| walk(v, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(value, &mut out);
    out
}

pub fn check(server_name: &str, sent: &[u8], sent_hidden: &[Range<usize>], received: &[u8], received_hidden: &[Range<usize>]) -> Result<Exchange> {
    if server_name != HOST {
        bail!("proof is for {server_name}, not {HOST}");
    }
    if !received_hidden.is_empty() {
        bail!("part of X's response was hidden");
    }
    let head_end = find(sent, b"\r\n\r\n").context("no request header terminator")?;
    if sent.len() != head_end + 4 {
        bail!("request carries a body or a second request");
    }
    let secrets = secret_spans(sent, head_end)?;
    for hidden in sent_hidden {
        if !secrets.iter().any(|s| s.start <= hidden.start && hidden.end <= s.end) {
            bail!("supplier hid request bytes {hidden:?} outside the session cookie values and CSRF token");
        }
    }
    let request_line_end = find(sent, b"\r\n").context("no request line")?;
    let target = std::str::from_utf8(&sent[..request_line_end])
        .ok()
        .and_then(|l| l.strip_prefix("GET "))
        .and_then(|l| l.strip_suffix(" HTTP/1.1"))
        .context("request is not an HTTP/1.1 GET")?;
    let mut hosts = Vec::new();
    for (name, value) in header_lines(sent, request_line_end + 2, head_end, sent_hidden)? {
        if FORBIDDEN_HEADERS.contains(&name.as_str()) {
            bail!("request carries a {name} header");
        }
        if name == "host" {
            hosts.push(value);
        }
    }
    if hosts != [HOST.as_bytes()] {
        bail!("request must carry exactly one Host: x.com header");
    }
    let (path, query) = target.split_once('?').context("request has no query")?;
    let (query_id, operation) = path
        .strip_prefix(GRAPHQL)
        .and_then(|rest| rest.split_once('/'))
        .context("request is not an X GraphQL call")?;
    if !valid_query_id(query_id) {
        bail!("invalid query id");
    }
    if !READ_OPERATIONS.contains(&operation) {
        bail!("{operation} is not an allowed read");
    }
    let (variables, features, field_toggles) = query_params(query)?;
    let (http_status, body) = response_body(received)?;
    Ok(Exchange { operation: operation.to_owned(), query_id: query_id.to_owned(), variables, features, field_toggles, http_status, body })
}

/// The header lines between `start` and the blank line at `head_end`, as
/// lowercase names and values. Each must be a strict `name: value` line: no
/// folding, no whitespace before the colon, and no control or non-ASCII bytes
/// among the revealed value bytes, so no server can split or join lines
/// differently. Hidden bytes are skipped; they read as zeros.
fn header_lines<'a>(sent: &'a [u8], mut start: usize, head_end: usize, hidden: &[Range<usize>]) -> Result<Vec<(String, &'a [u8])>> {
    let is_hidden = |i: usize| hidden.iter().any(|r| r.contains(&i));
    let mut lines = Vec::new();
    while start < head_end {
        let line_end = start + find(&sent[start..head_end + 2], b"\r\n").context("bad header line")?;
        let line = &sent[start..line_end];
        let colon = line.iter().position(|&b| b == b':').context("header line without a colon")?;
        let name = &line[..colon];
        if name.is_empty() || !name.iter().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(b)) {
            bail!("malformed header name");
        }
        for (i, &b) in line.iter().enumerate().skip(colon + 1) {
            if !is_hidden(start + i) && !(b == b'\t' || (0x20..0x7f).contains(&b)) {
                bail!("header {} has a control or non-ASCII byte", String::from_utf8_lossy(name));
            }
        }
        let value = &line[colon + 1..];
        let trim = |v: &'a [u8]| {
            let v = &v[v.iter().take_while(|&&b| b == b' ' || b == b'\t').count()..];
            &v[..v.len() - v.iter().rev().take_while(|&&b| b == b' ' || b == b'\t').count()]
        };
        lines.push((String::from_utf8_lossy(name).to_ascii_lowercase(), trim(value)));
        start = line_end + 2;
    }
    Ok(lines)
}

/// Byte ranges the supplier may hide: the values of the secret cookies and of
/// the CSRF header, each within its length limit. On the supplier's side
/// these are exactly the values; on the verifier's, where hidden bytes read
/// as zeros, each value runs to the next revealed `; ` or the end of the line.
pub fn secret_spans(sent: &[u8], head_end: usize) -> Result<Vec<Range<usize>>> {
    let (mut spans, mut seen) = (Vec::new(), Vec::new());
    let mut once = |name: &str| {
        if seen.iter().any(|s| s == name) {
            bail!("more than one {name}");
        }
        seen.push(name.to_owned());
        Ok(())
    };
    let mut start = find(sent, b"\r\n").context("no request line")? + 2;
    while start < head_end {
        let line_end = start + find(&sent[start..head_end + 2], b"\r\n").context("bad header line")?;
        let line = &sent[start..line_end];
        if let Some(colon) = line.iter().position(|&b| b == b':') {
            let name = String::from_utf8_lossy(&line[..colon]).to_ascii_lowercase();
            let value = start + colon + 1 + line[colon + 1..].iter().take_while(|&&b| b == b' ').count();
            if name == CSRF_HEADER.0 {
                once(&name)?;
                if line_end - value > CSRF_HEADER.1 {
                    bail!("{name} is longer than {} bytes", CSRF_HEADER.1);
                }
                spans.push(value..line_end);
            } else if name == "cookie" {
                once(&name)?;
                let mut at = value;
                for pair in sent[value..line_end].split(|&b| b == b';') {
                    let lead = pair.iter().take_while(|&&b| b == b' ').count();
                    if let Some(eq) = pair.iter().position(|&b| b == b'=') {
                        let cookie = String::from_utf8_lossy(&pair[lead.min(eq)..eq]).into_owned();
                        if let Some((_, max)) = SECRET_COOKIES.iter().find(|(n, _)| *n == cookie) {
                            once(&cookie)?;
                            if pair.len() - eq - 1 > *max {
                                bail!("{cookie} cookie is longer than {max} bytes");
                            }
                            spans.push(at + eq + 1..at + pair.len());
                        }
                    }
                    at += pair.len() + 1;
                }
            }
        }
        start = line_end + 2;
    }
    Ok(spans)
}

/// The `variables`, `features` and `fieldToggles` of a GraphQL GET. The query
/// must be in the form Go's url.Values.Encode writes, with each parameter at
/// most once and JSON without duplicate keys or non-integer numbers, so the
/// verifier and X cannot read it differently.
fn query_params(query: &str) -> Result<(Value, Option<Value>, Option<Value>)> {
    if !query.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~%&=+".contains(&b)) {
        bail!("query has characters outside form encoding");
    }
    let mut params: [(&str, Option<Value>); 3] = [("variables", None), ("features", None), ("fieldToggles", None)];
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').context("query parameter without a value")?;
        let slot = params.iter_mut().find(|(name, _)| *name == key).with_context(|| format!("unexpected query parameter {key:?}"))?;
        if slot.1.is_some() {
            bail!("query parameter {key} appears twice");
        }
        let text = form_decode(value).with_context(|| format!("bad {key} encoding"))?;
        slot.1 = Some(strict_json(&text).with_context(|| format!("{key} is not strict JSON"))?);
    }
    let [(_, variables), (_, features), (_, field_toggles)] = params;
    let variables = variables.context("request has no variables")?;
    if !variables.is_object() {
        bail!("variables must be an object");
    }
    Ok((variables, features, field_toggles))
}

fn form_decode(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let (mut out, mut i) = (Vec::with_capacity(bytes.len()), 0);
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' => {
                let hex = bytes.get(i + 1..i + 3).and_then(|h| std::str::from_utf8(h).ok()).context("truncated escape")?;
                if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                    bail!("invalid escape %{hex}");
                }
                out.push(u8::from_str_radix(hex, 16)?);
                i += 2;
            }
            b => out.push(b),
        }
        i += 1;
    }
    Ok(String::from_utf8(out)?)
}

/// Parses JSON, rejecting duplicate object keys at any depth and numbers that
/// are not 64-bit integers, which parsers can disagree about.
fn strict_json(text: &str) -> Result<Value> {
    struct Strict;
    impl<'de> DeserializeSeed<'de> for Strict {
        type Value = Value;
        fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
            d.deserialize_any(self)
        }
    }
    impl<'de> Visitor<'de> for Strict {
        type Value = Value;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("JSON")
        }
        fn visit_unit<E>(self) -> Result<Value, E> {
            Ok(Value::Null)
        }
        fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
            Ok(v.into())
        }
        fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
            Ok(v.into())
        }
        fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
            Ok(v.into())
        }
        fn visit_f64<E: de::Error>(self, _: f64) -> Result<Value, E> {
            Err(E::custom("numbers must be 64-bit integers"))
        }
        fn visit_str<E>(self, v: &str) -> Result<Value, E> {
            Ok(v.into())
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
            let mut items = Vec::new();
            while let Some(item) = seq.next_element_seed(Strict)? {
                items.push(item);
            }
            Ok(Value::Array(items))
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
            let mut out = Map::new();
            while let Some(key) = map.next_key::<String>()? {
                if out.contains_key(&key) {
                    return Err(de::Error::custom(format!("duplicate key {key:?}")));
                }
                let value = map.next_value_seed(Strict)?;
                out.insert(key, value);
            }
            Ok(Value::Object(out))
        }
    }
    let mut de = serde_json::Deserializer::from_str(text);
    let value = Strict.deserialize(&mut de)?;
    de.end()?;
    Ok(value)
}

struct Head {
    status: u16,
    body_start: usize,
    chunked: bool,
    gzip: bool,
    length: Option<usize>,
}

fn parse_head(received: &[u8]) -> Result<Head> {
    let head_end = find(received, b"\r\n\r\n").context("no response header terminator")?;
    let head = std::str::from_utf8(&received[..head_end]).context("response header is not UTF-8")?;
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .and_then(|l| l.strip_prefix("HTTP/1.1 "))
        .and_then(|l| l.get(..3))
        .and_then(|s| s.parse().ok())
        .context("not an HTTP/1.1 response")?;
    let mut h = Head { status, body_start: head_end + 4, chunked: false, gzip: false, length: None };
    for line in lines {
        let Some((name, value)) = line.split_once(':') else { continue };
        let value = value.trim().to_ascii_lowercase();
        match name.trim().to_ascii_lowercase().as_str() {
            "transfer-encoding" => h.chunked = value == "chunked",
            "content-encoding" => match value.as_str() {
                "gzip" => h.gzip = true,
                "identity" => {}
                other => bail!("unsupported content encoding {other}"),
            },
            "content-length" => h.length = Some(value.parse::<usize>().context("bad content-length")?),
            _ => {}
        }
    }
    Ok(h)
}

/// Whether `received` already holds a whole response by its own framing. A
/// response without chunking or a length is never complete.
pub fn response_complete(received: &[u8]) -> bool {
    let Ok(h) = parse_head(received) else { return false };
    let rest = &received[h.body_start..];
    if h.chunked {
        dechunk(rest).is_ok()
    } else {
        h.length.is_some_and(|n| rest.len() >= n)
    }
}

/// Status and decoded body of a complete HTTP/1.1 response.
pub fn response_body(received: &[u8]) -> Result<(u16, String)> {
    let h = parse_head(received)?;
    let rest = &received[h.body_start..];
    let mut body = if h.chunked {
        dechunk(rest)?
    } else if let Some(n) = h.length {
        rest.get(..n).context("response body is truncated")?.to_vec()
    } else {
        // The prover ends the server stream itself, so an unframed body could be cut short.
        bail!("response has neither Content-Length nor chunked framing");
    };
    if h.gzip {
        let mut plain = Vec::new();
        flate2::read::GzDecoder::new(body.as_slice()).take(MAX_BODY as u64 + 1).read_to_end(&mut plain).context("bad gzip body")?;
        body = plain;
    }
    if body.len() > MAX_BODY {
        bail!("response body is too large");
    }
    Ok((h.status, String::from_utf8(body).context("response body is not UTF-8")?))
}

fn dechunk(mut data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = find(data, b"\r\n").context("truncated chunk size")?;
        let size_text = std::str::from_utf8(&data[..line_end])?.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16).context("bad chunk size")?;
        data = &data[line_end + 2..];
        if size == 0 {
            if !data.starts_with(b"\r\n") {
                bail!("truncated or trailer-bearing final chunk");
            }
            return Ok(out);
        }
        out.extend_from_slice(data.get(..size).context("truncated chunk")?);
        data = data.get(size + 2..).context("truncated chunk")?;
        if out.len() > MAX_BODY {
            bail!("response body is too large");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;
    use serde_json::json;

    const COOKIE: &str = "auth_token=SECRET; ct0=CSRF; twid=u%3D1";

    fn sent_with(line: &str, extra: &str) -> Vec<u8> {
        format!("{line}\r\nHost: x.com\r\nAuthorization: Bearer PUBLIC\r\nX-Csrf-Token: CSRF\r\nCookie: {COOKIE}\r\nConnection: close\r\n{extra}\r\n").into_bytes()
    }

    const FORM: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC.remove(b'-').remove(b'.').remove(b'_').remove(b'~');

    /// A GraphQL GET encoded the way Go's url.Values.Encode does.
    fn get(operation: &str, variables: &Value, features: Option<&Value>) -> Vec<u8> {
        let enc = |v: &Value| percent_encoding::utf8_percent_encode(&v.to_string(), FORM).to_string().replace("%20", "+");
        let mut query = String::new();
        if let Some(f) = features {
            query = format!("features={}&", enc(f));
        }
        query.push_str(&format!("variables={}", enc(variables)));
        sent_with(&format!("GET /i/api/graphql/qid_1/{operation}?{query} HTTP/1.1"), "")
    }

    /// The secret values as the prover hides them.
    fn hidden(sent: &[u8]) -> Vec<Range<usize>> {
        let text = String::from_utf8_lossy(sent);
        let at = |needle: &str, len: usize| {
            let start = text.find(needle).unwrap() + needle.len();
            start..start + len
        };
        vec![at("X-Csrf-Token: ", 4), at("auth_token=", 6), at("ct0=", 4)]
    }

    /// The verifier's view of `sent`: hidden bytes read as zeros.
    fn blank(sent: &[u8], hidden: &[Range<usize>]) -> Vec<u8> {
        let mut out = sent.to_vec();
        for r in hidden {
            out[r.clone()].fill(0);
        }
        out
    }

    fn gzip_response(body: &str) -> Vec<u8> {
        let mut z = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(body.as_bytes()).unwrap();
        let gz = z.finish().unwrap();
        let (a, b) = gz.split_at(gz.len() / 2);
        let mut r = b"HTTP/1.1 200 OK\r\ncontent-encoding: gzip\r\ntransfer-encoding: chunked\r\n\r\n".to_vec();
        for part in [a, b] {
            r.extend(format!("{:x}\r\n", part.len()).as_bytes());
            r.extend(part);
            r.extend(b"\r\n");
        }
        r.extend(b"0\r\n\r\n");
        r
    }

    fn features() -> Value {
        json!({"f": true})
    }

    fn exchange(operation: &str, variables: Value) -> Exchange {
        Exchange {
            operation: operation.into(),
            query_id: "qid_1".into(),
            variables,
            features: Some(features()),
            field_toggles: None,
            http_status: 200,
            body: r#"{"data":{"x":1}}"#.into(),
        }
    }

    fn spec(operation: &str, variables: Value) -> Value {
        json!({"operation": operation, "query_id": "qid_1", "variables": variables, "features": features()})
    }

    fn paged(operation: &str, variables: Value, from: usize) -> Value {
        let mut s = spec(operation, variables);
        s["cursor_from"] = json!(from);
        s
    }

    fn page(cursor: &str) -> String {
        json!({"data": {"search": {"timeline": {"instructions": [
            {"type": "TimelineAddEntries", "entries": [
                {"entryId": "tweet-1", "content": {"entryType": "TimelineTimelineItem", "itemContent": {"tweet_results": {"result": {"legacy": {"full_text":
                    "{\"entryType\":\"TimelineTimelineCursor\",\"cursorType\":\"Bottom\",\"value\":\"FROM_TEXT\"}"}}}}}},
                {"entryId": "module", "content": {"entryType": "TimelineTimelineModule", "items": [{"item": {"itemContent": {"instructions": []},
                    "content": {"entryType": "TimelineTimelineCursor", "cursorType": "Bottom", "value": "NESTED"}}}]}},
                {"entryId": "cursor-top", "content": {"entryType": "TimelineTimelineCursor", "__typename": "TimelineTimelineCursor", "cursorType": "Top", "value": "TOP"}},
                {"entryId": "cursor-bottom", "content": {"entryType": "TimelineTimelineCursor", "__typename": "TimelineTimelineCursor", "cursorType": "Bottom", "value": cursor}},
            ]},
        ]}}}})
        .to_string()
    }

    fn search(query: &str) -> Value {
        json!({"rawQuery": query, "count": 20, "querySource": "typed_query", "product": "Latest"})
    }

    fn job(exchanges: Vec<Value>) -> Vec<Spec> {
        validate_job(&json!({"type": "x.read", "exchanges": exchanges})).unwrap().0
    }

    /// `assign` against exchanges already fulfilled by these responses.
    fn assign_after(specs: &[Spec], done: &[(usize, &Exchange)], got: &Exchange) -> Result<usize> {
        let cursors: Vec<(usize, &Exchange, Vec<String>)> = done.iter().filter(|(_, e)| outcome(e).0).map(|(i, e)| (*i, *e, outcome(e).1)).collect();
        let fulfilled: Vec<(usize, &Exchange, &[String])> = cursors.iter().map(|(i, e, c)| (*i, *e, c.as_slice())).collect();
        assign(specs, &fulfilled, got)
    }

    #[test]
    fn accepts_a_read_hiding_only_the_session() {
        let variables = json!({"tweetId": "20", "withCommunity": false, "note": "a b&c=d+e%f/ü"});
        let sent = get("TweetResultByRestId", &variables, Some(&features()));
        let body = r#"{"data":{"tweetResult":{"result":{"rest_id":"20"}}}}"#;
        let got = check(HOST, &blank(&sent, &hidden(&sent)), &hidden(&sent), &gzip_response(body), &[]).unwrap();
        assert_eq!(got, Exchange { variables, body: body.into(), operation: "TweetResultByRestId".into(), ..exchange("", json!({})) });
        assert_eq!(secret_spans(&sent, sent.len() - 4).unwrap(), hidden(&sent));
    }

    #[test]
    fn rejects_cheats() {
        let sent = get("TweetResultByRestId", &json!({"tweetId": "20"}), None);
        let ok = hidden(&sent);
        let response = gzip_response("{}");
        let auth = String::from_utf8_lossy(&sent).find("PUBLIC").unwrap();
        let name = String::from_utf8_lossy(&sent).find("auth_token=").unwrap();
        let twid = String::from_utf8_lossy(&sent).find("u%3D1").unwrap();
        let cookie_end = String::from_utf8_lossy(&sent).find("\r\nConnection").unwrap();
        let post = sent_with("POST /i/api/graphql/lI07N6Otwv1PhnEgXILM7A/FavoriteTweet HTTP/1.1", "");
        let write_op = get("FavoriteTweet", &json!({}), None);
        let dm = sent_with("GET /i/api/1.1/dm/inbox_initial_state.json HTTP/1.1", "");
        let mut two = sent.clone();
        two.extend(get("TweetResultByRestId", &json!({"tweetId": "20"}), None));
        let line = "GET /i/api/graphql/q/TweetResultByRestId?variables=%7B%7D HTTP/1.1";
        let wrong_host = String::from_utf8_lossy(&sent).replace("Host: x.com", "Host: api.x.com").into_bytes();
        let long_csrf = String::from_utf8_lossy(&sent).replace("X-Csrf-Token: CSRF", &format!("X-Csrf-Token: {}", "c".repeat(161))).into_bytes();
        let long_token = String::from_utf8_lossy(&sent).replace("auth_token=SECRET", &format!("auth_token={}", "s".repeat(65))).into_bytes();
        let mut cases: Vec<(String, Vec<u8>, Vec<Range<usize>>)> = vec![
            ("hidden bearer".into(), sent.clone(), vec![auth..auth + 6]),
            ("hidden cookie name".into(), sent.clone(), vec![name..name + 10]),
            ("hidden other cookie".into(), sent.clone(), vec![twid..twid + 5]),
            ("hidden cookie separator".into(), sent.clone(), vec![name + 10..cookie_end]),
            ("POST write".into(), post.clone(), hidden(&post)),
            ("GET write operation".into(), write_op.clone(), hidden(&write_op)),
            ("REST DM read".into(), dm.clone(), hidden(&dm)),
            ("second request".into(), two, ok.clone()),
            ("wrong Host header".into(), wrong_host.clone(), hidden(&wrong_host)),
            ("overlong CSRF token".into(), long_csrf.clone(), vec![]),
            ("overlong auth_token".into(), long_token.clone(), vec![]),
        ];
        for (what, extra) in [
            ("duplicate cookie", "Cookie: other=1\r\n"),
            ("duplicate CSRF header", "X-Csrf-Token: x\r\n"),
            ("second Host header", "Host: api.x.com\r\n"),
            ("folded header", "X-A: b\r\n Host: api.x.com\r\n"),
            ("bare LF", "X-A: b\nHost: api.x.com\r\n"),
            ("bare CR", "X-A: b\rHost: api.x.com\r\n"),
            ("NUL in a revealed value", "X-A: b\0c\r\n"),
            ("non-ASCII value", "X-A: \u{e9}\r\n"),
            ("space before colon", "Host : api.x.com\r\n"),
            ("line without a colon", "garbage\r\n"),
            ("empty header name", ": v\r\n"),
            ("Content-Length", "Content-Length: 5\r\n"),
            ("Transfer-Encoding", "Transfer-Encoding: chunked\r\n"),
            ("method override", "X-HTTP-Method-Override: POST\r\n"),
            ("URL override", "X-Original-URL: /i/api/graphql/q/Viewer\r\n"),
        ] {
            let s = sent_with(line, extra);
            cases.push((what.into(), s.clone(), hidden(&s)));
        }
        for (name, sent, hidden) in cases {
            assert!(check(HOST, &blank(&sent, &hidden), &hidden, &response, &[]).is_err(), "{name} was accepted");
        }
        assert!(check("twitter.com", &blank(&sent, &ok), &ok, &response, &[]).is_err(), "wrong server was accepted");
        assert!(check(HOST, &blank(&sent, &ok), &ok, &response, &[0..4]).is_err(), "hidden response was accepted");
        // A second request hidden inside a secret value can't hide beyond that value's length limit.
        let smuggled = format!("{}\r\n\r\nGET /i/api/graphql/q/HomeTimeline?variables=%7B%7D HTTP/1.1\r\nHost: x.com", "a".repeat(40));
        let s = String::from_utf8_lossy(&sent).replace("auth_token=SECRET", &format!("auth_token={smuggled}")).into_bytes();
        let start = String::from_utf8_lossy(&s).find("auth_token=").unwrap() + 11;
        let h = vec![start..start + smuggled.len()];
        assert!(check(HOST, &blank(&s, &h), &h, &response, &[]).is_err(), "a smuggled request was hidden");
    }

    #[test]
    fn rejects_ambiguous_queries() {
        let response = gzip_response("{}");
        for query in [
            "",
            "features=%7B%7D",
            "variables=%7B%7D&variables=%7B%22tweetId%22%3A%2221%22%7D",
            "variables=%7B%7D&features=%7B%7D&features=%7B%7D",
            "variables=%7B%7D&extra=1",
            "variables=%7B%7D&Variables=%7B%7D",
            "variables=%7B%7D&",
            "variables",
            "variables=%7B%7D;features=%7B%7D",
            "variables=%7B%22a%22:1%7D",
            "variables=%7B%22a%22%3A1%7",
            "variables=%7B%22a%22%3A1%zz",
            "variables=%7B%22a%22%3A%22%FF%22%7D",
            "variables=%7B%22a%22%3A%22%C0%AF%22%7D",
            "variables=%7B%22a%22%3A1%2C%22a%22%3A2%7D",
            "variables=%7B%22a%22%3A1%2C%22%5Cu0061%22%3A2%7D",
            "variables=%7B%22a%22%3A%7B%22b%22%3A1%2C%22b%22%3A1%7D%7D",
            "variables=%7B%22count%22%3A20.0%7D",
            "variables=%7B%22count%22%3A2e1%7D",
            "variables=%7B%22count%22%3A-0%7D",
            "variables=%7B%22id%22%3A18446744073709551616%7D",
            "variables=%7B%22a%22%3A%22%5Cud800%22%7D",
            "variables=%7B%7D%7B%7D",
            "variables=%5B%5D",
        ] {
            let sent = sent_with(&format!("GET /i/api/graphql/q/SearchTimeline?{query} HTTP/1.1"), "");
            assert!(check(HOST, &blank(&sent, &hidden(&sent)), &hidden(&sent), &response, &[]).is_err(), "{query:?} was accepted");
        }
        for target in [
            "/i/api/graphql/q/SearchTimeline/x?variables=%7B%7D",
            "/i/api/graphql/q%2F/SearchTimeline?variables=%7B%7D",
            "/i/api/graphql//SearchTimeline?variables=%7B%7D",
            "/i/api/graphql/q/../SearchTimeline?variables=%7B%7D",
            "https://x.com/i/api/graphql/q/SearchTimeline?variables=%7B%7D",
            "/i/api/graphql/q/SearchTimeline?variables=%7B%7D HTTP/1.1",
        ] {
            let sent = sent_with(&format!("GET {target} HTTP/1.1"), "");
            assert!(check(HOST, &blank(&sent, &hidden(&sent)), &hidden(&sent), &response, &[]).is_err(), "{target} was accepted");
        }
    }

    #[test]
    fn validates_jobs() {
        let s = spec("SearchTimeline", search("bitcoin"));
        let (specs, max) = validate_job(&json!({"type": "x.read", "exchanges": [s, paged("SearchTimeline", search("bitcoin"), 0)]})).unwrap();
        assert_eq!((specs.len(), max, specs[1].cursor_from), (2, 4, Some(0)));
        let mut toggles = spec("Viewer", json!({"withCommunity": true}));
        toggles["field_toggles"] = json!({"t": false});
        assert_eq!(validate_job(&json!({"type": "x.read", "exchanges": [toggles], "max_attempts": 1})).unwrap().1, 1);
        let many: Vec<Value> = (0..100).map(|i| spec("SearchTimeline", search(&format!("synthetic-{i}")))).collect();
        assert_eq!(validate_job(&json!({"type": "x.read", "exchanges": many})).unwrap().1, 200);
        // A resumed first page may carry its own cursor; its next page drops it.
        let mut resumed = search("bitcoin");
        resumed["cursor"] = json!("C0");
        assert!(validate_job(&json!({"type": "x.read", "exchanges": [spec("SearchTimeline", resumed), paged("SearchTimeline", search("bitcoin"), 0)]})).is_ok());

        let too_many: Vec<Value> = (0..101).map(|i| spec("SearchTimeline", search(&format!("synthetic-{i}")))).collect();
        let with = |key: &str, value: Value| {
            let mut e = s.clone();
            e[key] = value;
            json!({"type": "x.read", "exchanges": [e]})
        };
        let without = |key: &str| {
            let mut e = s.clone();
            e.as_object_mut().unwrap().remove(key);
            json!({"type": "x.read", "exchanges": [e]})
        };
        for bad in [
            json!({"type": "x.read", "operations": ["Viewer"], "max_exchanges": 3}),
            json!({"type": "x.read", "exchanges": []}),
            json!({"type": "x.read", "exchanges": too_many}),
            json!({"type": "x.read", "exchanges": [s], "max_attempts": 0}),
            json!({"type": "x.read", "exchanges": [s], "max_attempts": 201}),
            json!({"type": "x.read", "exchanges": [s], "extra": 1}),
            json!({"type": "x.write", "exchanges": [s]}),
            json!({"type": "response.create", "model": "gpt-5.5"}),
            json!({"type": "x.read", "exchanges": [paged("SearchTimeline", search("bitcoin"), 0)]}),
            json!({"type": "x.read", "exchanges": [s, paged("SearchTimeline", search("bitcoin"), 1)]}),
            json!({"type": "x.read", "exchanges": [s, paged("UserTweets", search("bitcoin"), 0)]}),
            json!({"type": "x.read", "exchanges": [s, paged("SearchTimeline", search("ethereum"), 0)]}),
            json!({"type": "x.read", "exchanges": [s, paged("SearchTimeline", json!({"cursor": "X"}), 0)]}),
            with("operation", json!("FavoriteTweet")),
            with("query_id", json!("a/b")),
            with("query_id", json!("")),
            with("variables", json!("{}")),
            with("variables", json!({"count": 20.5})),
            with("features", json!({"f": 1.0})),
            with("features", json!([])),
            with("field_toggles", json!(true)),
            with("variabels", json!({})),
            without("query_id"),
            without("features"),
            without("variables"),
        ] {
            assert!(validate_job(&bad).is_err(), "{bad} was accepted");
        }
    }

    #[test]
    fn pins_the_request() {
        let specs = job(vec![spec("SearchTimeline", search("bitcoin")), spec("UserTweets", json!({"userId": "12", "count": 20}))]);
        let honest = exchange("SearchTimeline", search("bitcoin"));
        assert_eq!(assign_after(&specs, &[], &honest).unwrap(), 0);
        // Order does not matter; each exchange is matched on its own terms.
        assert_eq!(assign_after(&specs, &[], &exchange("UserTweets", json!({"userId": "12", "count": 20}))).unwrap(), 1);

        let mut added = search("bitcoin");
        added["extra"] = json!(1);
        let mut removed = search("bitcoin");
        removed.as_object_mut().unwrap().remove("product");
        let mut cursor = search("bitcoin");
        cursor["cursor"] = json!("C");
        let cheats = [
            ("swapped search term", Exchange { variables: search("ethereum"), ..honest.clone() }),
            ("changed count", Exchange { variables: json!({"rawQuery": "bitcoin", "count": 5, "querySource": "typed_query", "product": "Latest"}), ..honest.clone() }),
            ("added variable", Exchange { variables: added, ..honest.clone() }),
            ("removed variable", Exchange { variables: removed, ..honest.clone() }),
            ("uninvited cursor", Exchange { variables: cursor, ..honest.clone() }),
            ("changed feature", Exchange { features: Some(json!({"f": false})), ..honest.clone() }),
            ("extra feature", Exchange { features: Some(json!({"f": true, "g": true})), ..honest.clone() }),
            ("missing features", Exchange { features: None, ..honest.clone() }),
            ("unpinned field toggles", Exchange { field_toggles: Some(json!({})), ..honest.clone() }),
            ("other query id", Exchange { query_id: "qid_2".into(), ..honest.clone() }),
            ("other operation", Exchange { operation: "HomeTimeline".into(), ..honest.clone() }),
            ("other user", exchange("UserTweets", json!({"userId": "13", "count": 20}))),
            ("string count", exchange("UserTweets", json!({"userId": "12", "count": "20"}))),
        ];
        for (name, got) in cheats {
            assert!(assign_after(&specs, &[], &got).is_err(), "{name} was accepted");
        }
        let mut toggled = spec("Viewer", json!({}));
        toggled["field_toggles"] = json!({"t": true});
        let toggled = job(vec![toggled]);
        let viewer = exchange("Viewer", json!({}));
        assert!(assign_after(&toggled, &[], &viewer).is_err(), "missing field toggles were accepted");
        assert_eq!(assign_after(&toggled, &[], &Exchange { field_toggles: Some(json!({"t": true})), ..viewer }).unwrap(), 0);
    }

    #[test]
    fn fulfils_once_with_data_and_retries_otherwise() {
        let specs = job(vec![spec("SearchTimeline", search("bitcoin"))]);
        let ok = exchange("SearchTimeline", search("bitcoin"));
        for (name, status, body) in [
            ("429", 429, r#"{"data":{"x":1}}"#),
            ("200 with only errors", 200, r#"{"errors":[{"message":"Rate limit exceeded"}]}"#),
            ("200 with null data", 200, r#"{"data":null}"#),
            ("200 with empty data", 200, r#"{"data":{}}"#),
            ("200 not JSON", 200, "<html>"),
        ] {
            let failed = Exchange { http_status: status, body: body.into(), ..ok.clone() };
            assert!(!outcome(&failed).0, "{name} fulfilled an exchange");
            assert_eq!(assign_after(&specs, &[(0, &failed)], &ok).unwrap(), 0, "a retry after {name} must still count");
        }
        assert!(outcome(&Exchange { body: r#"{"data":{"x":1},"errors":[{"message":"partial"}]}"#.into(), ..ok.clone() }).0, "partial data must fulfil");
        assert!(assign_after(&specs, &[(0, &ok)], &ok).is_err(), "a duplicate of a fulfilled exchange was accepted");
        // A second request for the same page cannot earn another fulfilled unit.
        let twice = json!({"type":"x.read","exchanges":[spec("Viewer", json!({})),spec("Viewer", json!({}))]});
        assert!(validate_job(&twice).is_err());
    }

    #[test]
    fn chains_pages_by_recorded_cursors() {
        let specs = job(vec![
            spec("SearchTimeline", search("bitcoin")),
            paged("SearchTimeline", search("bitcoin"), 0),
            paged("SearchTimeline", search("bitcoin"), 1),
            spec("SearchTimeline", search("ethereum")),
        ]);
        let with_cursor = |q: &str, c: &str| {
            let mut v = search(q);
            v["cursor"] = json!(c);
            v
        };
        let answered = |variables: Value, body: String| Exchange { body, ..exchange("SearchTimeline", variables) };
        let page_2 = answered(with_cursor("bitcoin", "C1"), page("C2"));
        assert!(assign_after(&specs, &[], &page_2).is_err(), "page 2 before page 1 was accepted");
        let p1 = answered(search("bitcoin"), page("C1"));
        let eth = answered(search("ethereum"), page("E1"));
        let failed = Exchange { http_status: 429, ..answered(search("bitcoin"), page("C_FAILED")) };
        let errors = answered(search("bitcoin"), r#"{"errors":[{"message":"x"}],"instructions":[{"entries":[{"content":{"entryType":"TimelineTimelineCursor","cursorType":"Bottom","value":"C_ERRORS"}}]}]}"#.into());
        let done = [(3, &eth), (0, &failed), (0, &errors), (0, &p1)];
        assert_eq!(assign_after(&specs, &done, &page_2).unwrap(), 1);
        for (name, cursor) in [
            ("forged cursor", "FORGED"),
            ("cursor from tweet text", "FROM_TEXT"),
            ("cursor nested in a module", "NESTED"),
            ("Top cursor", "TOP"),
            ("cursor from a different exchange", "E1"),
            ("cursor from a failed attempt", "C_FAILED"),
            ("cursor from an errors-only response", "C_ERRORS"),
        ] {
            assert!(assign_after(&specs, &done, &exchange("SearchTimeline", with_cursor("bitcoin", cursor))).is_err(), "{name} was accepted");
        }
        let mut numeric = search("bitcoin");
        numeric["cursor"] = json!(1);
        assert!(assign_after(&specs, &done, &exchange("SearchTimeline", numeric)).is_err(), "non-string cursor was accepted");
        assert!(assign_after(&specs, &done, &exchange("SearchTimeline", with_cursor("ethereum", "C1"))).is_err(), "page 2 of another query was accepted");
        // Page 3 follows page 2's recorded cursor.
        let done = [(0, &p1), (1, &page_2)];
        assert_eq!(assign_after(&specs, &done, &exchange("SearchTimeline", with_cursor("bitcoin", "C2"))).unwrap(), 2);
        assert!(assign_after(&specs, &done, &exchange("SearchTimeline", with_cursor("bitcoin", "C1"))).is_err(), "page 2 again was accepted");
    }

    #[test]
    fn looping_cursor_cannot_fulfil_another_page() {
        let specs = job(vec![
            spec("SearchTimeline", search("bitcoin")),
            paged("SearchTimeline", search("bitcoin"), 0),
            paged("SearchTimeline", search("bitcoin"), 1),
        ]);
        let first = Exchange { body: page("C1"), ..exchange("SearchTimeline", search("bitcoin")) };
        let mut variables = search("bitcoin");
        variables["cursor"] = json!("C1");
        let second = Exchange { body: first.body.clone(), ..exchange("SearchTimeline", variables) };
        // Different request cursors are distinct work even if response bytes match.
        assert_eq!(assign_after(&specs, &[(0, &first)], &second).unwrap(), 1);
        let failed = Exchange { http_status: 429, ..second.clone() };
        assert_eq!(assign_after(&specs, &[(0, &first), (1, &failed)], &second).unwrap(), 1);
        let done = [(0, &first), (1, &second)];
        assert!(assign_after(&specs, &done, &second).is_err());
        // A new response body cannot make the repeated request a new page.
        assert!(assign_after(&specs, &done, &Exchange { body: page("C2"), ..second.clone() }).is_err());
    }

    #[test]
    fn finds_bottom_cursors_only_in_timeline_entries() {
        let cursors = |body: &str| outcome(&Exchange { body: body.into(), ..exchange("SearchTimeline", json!({})) }).1;
        assert_eq!(cursors(&page("C1")), ["C1"]);
        let replaced = json!({"data": {"t": {"instructions": [{"type": "TimelineReplaceEntry", "entry": {"content": {"__typename": "TimelineTimelineCursor", "cursorType": "Bottom", "value": "R"}}}]}}});
        assert_eq!(cursors(&replaced.to_string()), ["R"]);
        let loose = json!({"data": {"content": {"entryType": "TimelineTimelineCursor", "cursorType": "Bottom", "value": "LOOSE"},
            "t": {"instructions": [{"entries": [{"content": {"cursorType": "Bottom", "value": "UNTYPED"}}, {"content": {"entryType": "TimelineTimelineCursor", "cursorType": "Bottom", "value": ""}}]}]}}});
        assert!(cursors(&loose.to_string()).is_empty());
    }

    #[test]
    fn decodes_plain_content_length_bodies() {
        let r = b"HTTP/1.1 403 Forbidden\r\ncontent-length: 2\r\n\r\n{}".to_vec();
        assert_eq!(response_body(&r).unwrap(), (403, "{}".into()));
        assert!(response_body(b"HTTP/1.1 200 OK\r\n\r\n{}").is_err());
    }

    #[test]
    fn detects_complete_responses_by_framing() {
        let chunked = gzip_response("{}");
        assert!(response_complete(&chunked));
        assert!(!response_complete(&chunked[..chunked.len() - 3]));
        let sized = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\n{}";
        assert!(response_complete(sized) && !response_complete(&sized[..sized.len() - 1]));
        assert!(!response_complete(b"HTTP/1.1 200 OK\r\n\r\n{}"));
    }
}
