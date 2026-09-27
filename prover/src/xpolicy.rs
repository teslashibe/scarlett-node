//! What a verifier accepts for an X read: one GraphQL GET to x.com for an
//! allowed read operation, hiding only the session cookie and CSRF token, with
//! X's response fully revealed.

use std::{io::Read, ops::Range};

use anyhow::{Context, Result, bail};
use serde::Serialize;
use serde_json::Value;

use crate::policy::find;

pub const HOST: &str = "x.com";
const GRAPHQL: &str = "/i/api/graphql/";
/// Request headers whose values the supplier may hide.
const SECRET_HEADERS: [&str; 2] = ["cookie", "x-csrf-token"];
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

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Exchange {
    pub operation: String,
    pub variables: Value,
    pub http_status: u16,
    pub body: String,
}

/// An X job payload: `{"type":"x.read","operations":[...],"max_exchanges":n}`.
pub fn validate_job(job: &Value) -> Result<(Vec<String>, usize)> {
    if job["type"] != "x.read" {
        bail!("job payload must be an x.read");
    }
    let ops: Vec<String> = job["operations"]
        .as_array()
        .context("x.read needs operations")?
        .iter()
        .map(|v| v.as_str().filter(|op| READ_OPERATIONS.contains(op)).map(str::to_owned).context("operation is not an allowed read"))
        .collect::<Result<_>>()?;
    if ops.is_empty() {
        bail!("x.read needs at least one operation");
    }
    let max = job["max_exchanges"].as_u64().filter(|n| (1..=100).contains(n)).context("max_exchanges must be 1-100")?;
    Ok((ops, max as usize))
}

pub fn check(
    server_name: &str,
    sent: &[u8],
    sent_hidden: &[Range<usize>],
    received: &[u8],
    received_hidden: &[Range<usize>],
    operations: &[String],
) -> Result<Exchange> {
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
    let secrets = secret_values(sent, head_end)?;
    for hidden in sent_hidden {
        if !secrets.iter().any(|s| s.start <= hidden.start && hidden.end <= s.end) {
            bail!("supplier hid request bytes {hidden:?} outside the session cookie and CSRF token");
        }
    }
    let head = std::str::from_utf8(&sent[..head_end]).context("request header is not UTF-8")?;
    let mut lines = head.split("\r\n");
    let target = lines
        .next()
        .and_then(|l| l.strip_prefix("GET "))
        .and_then(|l| l.strip_suffix(" HTTP/1.1"))
        .context("request is not an HTTP/1.1 GET")?;
    if !lines.any(|l| l.eq_ignore_ascii_case("host: x.com")) {
        bail!("request is not addressed to x.com");
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let (query_id, operation) = path
        .strip_prefix(GRAPHQL)
        .and_then(|rest| rest.split_once('/'))
        .context("request is not an X GraphQL call")?;
    if query_id.is_empty() || !query_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
        bail!("invalid query id");
    }
    if !operations.iter().any(|op| op == operation) {
        bail!("operation {operation} is not allowed for this job");
    }
    let variables = query_param(query, "variables")
        .map(|v| serde_json::from_str(&v).context("variables are not JSON"))
        .transpose()?
        .unwrap_or(Value::Null);
    let (http_status, body) = response_body(received)?;
    Ok(Exchange { operation: operation.to_owned(), variables, http_status, body })
}

/// Byte ranges of the values of the headers the supplier may hide.
fn secret_values(sent: &[u8], head_end: usize) -> Result<Vec<Range<usize>>> {
    let (mut ranges, mut start, mut seen) = (Vec::new(), 0, Vec::new());
    while start < head_end {
        let line_end = start + find(&sent[start..head_end + 2], b"\r\n").context("bad header line")?;
        let line = &sent[start..line_end];
        if let Some(colon) = line.iter().position(|&b| b == b':') {
            let name = String::from_utf8_lossy(&line[..colon]).trim().to_ascii_lowercase();
            if SECRET_HEADERS.contains(&name.as_str()) {
                if seen.contains(&name) {
                    bail!("more than one {name} header");
                }
                let value = start + colon + 1 + line[colon + 1..].iter().take_while(|&&b| b == b' ').count();
                ranges.push(value..line_end);
                seen.push(name);
            }
        }
        start = line_end + 2;
    }
    Ok(ranges)
}

fn query_param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == name).then(|| percent_encoding::percent_decode_str(&value.replace('+', " ")).decode_utf8_lossy().into_owned())
    })
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

    const COOKIE: &str = "auth_token=SECRET; ct0=CSRF";

    fn ops() -> Vec<String> {
        vec!["TweetResultByRestId".into()]
    }

    fn sent_with(line: &str, extra: &str) -> Vec<u8> {
        format!("{line}\r\nHost: x.com\r\nAuthorization: Bearer PUBLIC\r\nX-Csrf-Token: CSRF\r\nCookie: {COOKIE}\r\nConnection: close\r\n{extra}\r\n").into_bytes()
    }

    fn tweet_get() -> Vec<u8> {
        sent_with("GET /i/api/graphql/fHLDP3qFEjnTqhWBVvsREg/TweetResultByRestId?variables=%7B%22tweetId%22%3A%2220%22%7D&features=%7B%7D HTTP/1.1", "")
    }

    fn hidden(sent: &[u8]) -> Vec<Range<usize>> {
        let text = String::from_utf8_lossy(sent);
        let csrf = text.find("X-Csrf-Token: ").unwrap() + 14;
        let cookie = text.find("Cookie: ").unwrap() + 8;
        vec![csrf..csrf + 4, cookie..cookie + COOKIE.len()]
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

    #[test]
    fn accepts_a_read_hiding_only_the_session() {
        let sent = tweet_get();
        let body = r#"{"data":{"tweetResult":{"result":{"rest_id":"20"}}}}"#;
        let got = check(HOST, &sent, &hidden(&sent), &gzip_response(body), &[], &ops()).unwrap();
        assert_eq!(
            got,
            Exchange { operation: "TweetResultByRestId".into(), variables: json!({"tweetId": "20"}), http_status: 200, body: body.into() }
        );
    }

    #[test]
    fn rejects_cheats() {
        let sent = tweet_get();
        let ok = hidden(&sent);
        let response = gzip_response("{}");
        let auth = String::from_utf8_lossy(&sent).find("PUBLIC").unwrap();
        let post = sent_with("POST /i/api/graphql/lI07N6Otwv1PhnEgXILM7A/FavoriteTweet HTTP/1.1", "");
        let other_op = sent_with("GET /i/api/graphql/abc/UserTweets?variables=%7B%7D HTTP/1.1", "");
        let dm = sent_with("GET /i/api/1.1/dm/inbox_initial_state.json HTTP/1.1", "");
        let mut two = sent.clone();
        two.extend(tweet_get());
        let two_cookies = sent_with("GET /i/api/graphql/q/TweetResultByRestId HTTP/1.1", "Cookie: other\r\n");
        let wrong_host = String::from_utf8_lossy(&sent).replace("Host: x.com", "Host: api.x.com").into_bytes();
        let cases: Vec<(&str, Result<Exchange>)> = vec![
            ("wrong server", check("twitter.com", &sent, &ok, &response, &[], &ops())),
            ("hidden response", check(HOST, &sent, &ok, &response, &[0..4], &ops())),
            ("hidden bearer", check(HOST, &sent, &[auth..auth + 6], &response, &[], &ops())),
            ("write", check(HOST, &post, &hidden(&post), &response, &[], &["FavoriteTweet".into()])),
            ("operation not in job", check(HOST, &other_op, &hidden(&other_op), &response, &[], &ops())),
            ("REST DM read", check(HOST, &dm, &hidden(&dm), &response, &[], &ops())),
            ("second request", check(HOST, &two, &ok, &response, &[], &ops())),
            ("duplicate cookie", check(HOST, &two_cookies, &[], &response, &[], &ops())),
            ("wrong Host header", check(HOST, &wrong_host, &hidden(&wrong_host), &response, &[], &ops())),
        ];
        for (name, result) in cases {
            assert!(result.is_err(), "{name} was accepted");
        }
    }

    #[test]
    fn validates_jobs() {
        assert!(validate_job(&json!({"type": "x.read", "operations": ["TweetResultByRestId"], "max_exchanges": 3})).is_ok());
        for job in [
            json!({"type": "x.read", "operations": ["FavoriteTweet"], "max_exchanges": 3}),
            json!({"type": "x.read", "operations": [], "max_exchanges": 3}),
            json!({"type": "x.read", "operations": ["Viewer"], "max_exchanges": 0}),
            json!({"type": "response.create", "model": "gpt-5.5"}),
        ] {
            assert!(validate_job(&job).is_err(), "{job} was accepted");
        }
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
