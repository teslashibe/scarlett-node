//! What a verifier accepts: a transcript proven to come from chatgpt.com whose
//! request is exactly the assigned job and whose response is fully revealed.

use std::ops::Range;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const HOST: &str = "chatgpt.com";
pub const PATH: &str = "/backend-api/codex/responses";
/// The supplier may hide only this header's credential value.
const AUTH_PREFIX: &[u8] = b"authorization: Bearer ";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verified {
    pub model: String,
    pub output: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

/// A job payload must be a Codex `response.create` naming a model.
pub fn validate_job(job: &Value) -> Result<&str> {
    if job["type"] != "response.create" {
        bail!("job payload must be a response.create");
    }
    job["model"].as_str().filter(|m| !m.is_empty()).context("job payload must name a model")
}

pub fn check(
    server_name: &str,
    sent: &[u8],
    sent_hidden: &[Range<usize>],
    received: &[u8],
    received_hidden: &[Range<usize>],
    job: &Value,
) -> Result<Verified> {
    let job_model = validate_job(job)?;
    if server_name != HOST {
        bail!("proof is for {server_name}, not {HOST}");
    }
    if !received_hidden.is_empty() {
        bail!("part of OpenAI's response was hidden");
    }
    let token = login_token_range(sent)?;
    for hidden in sent_hidden {
        if !token.as_ref().is_some_and(|t| t.start <= hidden.start && hidden.end <= t.end) {
            bail!("supplier hid request bytes {hidden:?} outside the login token");
        }
    }
    if !sent.starts_with(format!("GET {PATH} HTTP/1.1\r\n").as_bytes()) {
        bail!("request was not the Codex responses WebSocket");
    }
    if !received.starts_with(b"HTTP/1.1 101") {
        bail!("OpenAI did not accept the WebSocket");
    }

    let creates: Vec<Value> = json_messages(sent)?.into_iter().filter(|v| v["type"] == "response.create").collect();
    match creates.as_slice() {
        [only] if only == job => {}
        [_] => bail!("request does not match the job"),
        other => bail!("expected one request, found {}", other.len()),
    }

    let events = json_messages(received)?;
    let completed: Vec<&Value> = events.iter().filter(|v| v["type"] == "response.completed").collect();
    let [completed] = completed.as_slice() else {
        bail!("expected one completed response, found {}", completed.len());
    };
    let response = &completed["response"];
    let model = response["model"].as_str().context("completed response has no model")?;
    if model != job_model {
        bail!("OpenAI reported model {model}, job asked for {job_model}");
    }
    let usage = &response["usage"];
    let (Some(input_tokens), Some(output_tokens)) = (usage["input_tokens"].as_u64(), usage["output_tokens"].as_u64()) else {
        bail!("completed response has no token usage");
    };
    let output = events
        .iter()
        .filter(|v| v["type"] == "response.output_text.delta")
        .filter_map(|v| v["delta"].as_str())
        .collect();
    Ok(Verified { model: model.to_owned(), output, input_tokens, output_tokens })
}

/// Byte range of the bearer credential in the request header, if present.
fn login_token_range(sent: &[u8]) -> Result<Option<Range<usize>>> {
    let end = find(sent, b"\r\n\r\n").context("no request header terminator")?;
    let (mut found, mut start) = (None, 0);
    while start < end {
        let line_end = start + find(&sent[start..end + 2], b"\r\n").context("bad header line")?;
        let line = &sent[start..line_end];
        if line.len() > AUTH_PREFIX.len() && line[..AUTH_PREFIX.len()].eq_ignore_ascii_case(AUTH_PREFIX) {
            if found.is_some() {
                bail!("more than one authorization header");
            }
            found = Some(start + AUTH_PREFIX.len()..line_end);
        }
        start = line_end + 2;
    }
    Ok(found)
}

pub fn find(data: &[u8], needle: &[u8]) -> Option<usize> {
    data.windows(needle.len()).position(|w| w == needle)
}

/// JSON values of the WebSocket text messages after the HTTP upgrade.
pub fn json_messages(data: &[u8]) -> Result<Vec<Value>> {
    let body = &data[find(data, b"\r\n\r\n").context("no HTTP header terminator")? + 4..];
    let (mut i, mut messages, mut partial) = (0, Vec::new(), Vec::new());
    while i + 2 <= body.len() {
        let (fin, opcode, masked) = (body[i] & 0x80 != 0, body[i] & 0x0f, body[i + 1] & 0x80 != 0);
        let mut len = (body[i + 1] & 0x7f) as usize;
        i += 2;
        if len == 126 {
            let Some(b) = body.get(i..i + 2) else { break };
            len = u16::from_be_bytes([b[0], b[1]]) as usize;
            i += 2;
        } else if len == 127 {
            let Some(b) = body.get(i..i + 8) else { break };
            len = u64::from_be_bytes(b.try_into()?) as usize;
            i += 8;
        }
        let mask = if masked {
            let Some(m) = body.get(i..i + 4) else { break };
            i += 4;
            Some([m[0], m[1], m[2], m[3]])
        } else {
            None
        };
        let Some(payload) = body.get(i..i.saturating_add(len)) else { break };
        i += len;
        if opcode == 0x1 || opcode == 0x0 {
            partial.extend(payload.iter().enumerate().map(|(j, b)| mask.map_or(*b, |m| b ^ m[j % 4])));
            if fin {
                if let Ok(value) = serde_json::from_slice(&std::mem::take(&mut partial)) {
                    messages.push(value);
                }
            }
        }
    }
    Ok(messages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const TOKEN: &str = "SECRET.TOKEN.VALUE";

    fn job() -> Value {
        json!({"type": "response.create", "model": "gpt-5.5", "input": "hi"})
    }

    fn frame(payload: &[u8], mask: Option<[u8; 4]>, fin: bool, opcode: u8) -> Vec<u8> {
        let mut f = vec![(if fin { 0x80 } else { 0 }) | opcode];
        let bit = if mask.is_some() { 0x80 } else { 0 };
        if payload.len() < 126 {
            f.push(bit | payload.len() as u8);
        } else {
            f.push(bit | 126);
            f.extend((payload.len() as u16).to_be_bytes());
        }
        match mask {
            Some(m) => {
                f.extend(m);
                f.extend(payload.iter().enumerate().map(|(i, b)| b ^ m[i % 4]));
            }
            None => f.extend(payload),
        }
        f
    }

    fn sent_with(body: &Value) -> Vec<u8> {
        let mut s = format!(
            "GET {PATH} HTTP/1.1\r\nhost: chatgpt.com\r\nauthorization: Bearer {TOKEN}\r\nchatgpt-account-id: acct\r\n\r\n"
        )
        .into_bytes();
        s.extend(frame(body.to_string().as_bytes(), Some([1, 2, 3, 4]), true, 1));
        s
    }

    fn received_with(model: &str) -> Vec<u8> {
        let mut r = b"HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\n\r\n".to_vec();
        r.extend(frame(json!({"type": "response.output_text.delta", "delta": "hello"}).to_string().as_bytes(), None, true, 1));
        let done = json!({"type": "response.completed", "response": {"model": model, "usage": {"input_tokens": 12, "output_tokens": 3}}});
        r.extend(frame(done.to_string().as_bytes(), None, true, 1));
        r
    }

    fn token_range(sent: &[u8]) -> Range<usize> {
        let at = find(sent, TOKEN.as_bytes()).unwrap();
        at..at + TOKEN.len()
    }

    #[test]
    fn accepts_honest_transcript_hiding_only_the_token() {
        let sent = sent_with(&job());
        let got = check(HOST, &sent, &[token_range(&sent)], &received_with("gpt-5.5"), &[], &job()).unwrap();
        assert_eq!(got, Verified { model: "gpt-5.5".into(), output: "hello".into(), input_tokens: 12, output_tokens: 3 });
    }

    #[test]
    fn rejects_cheats() {
        let sent = sent_with(&job());
        let ok_hidden = [token_range(&sent)];
        let received = received_with("gpt-5.5");
        let acct = find(&sent, b"acct").unwrap();
        let mut cheap = job();
        cheap["model"] = json!("gpt-5.6-terra");
        let cases: Vec<(&str, Result<Verified>)> = vec![
            ("wrong server", check("api.openai.com", &sent, &ok_hidden, &received, &[], &job())),
            ("hidden response", check(HOST, &sent, &ok_hidden, &received, &[3..9], &job())),
            ("hidden account id", check(HOST, &sent, &[acct..acct + 4], &received, &[], &job())),
            ("different request", check(HOST, &sent_with(&cheap), &[token_range(&sent_with(&cheap))], &received, &[], &job())),
            ("different model reported", check(HOST, &sent, &ok_hidden, &received_with("gpt-5.6-terra"), &[], &job())),
        ];
        for (name, result) in cases {
            assert!(result.is_err(), "{name} was accepted");
        }
    }

    #[test]
    fn rejects_two_requests_and_missing_usage() {
        let mut sent = sent_with(&job());
        sent.extend(frame(job().to_string().as_bytes(), Some([9, 9, 9, 9]), true, 1));
        assert!(check(HOST, &sent, &[token_range(&sent)], &received_with("gpt-5.5"), &[], &job()).is_err());

        let sent = sent_with(&job());
        let mut received = b"HTTP/1.1 101 Switching Protocols\r\n\r\n".to_vec();
        received.extend(frame(br#"{"type":"response.completed","response":{"model":"gpt-5.5"}}"#, None, true, 1));
        assert!(check(HOST, &sent, &[token_range(&sent)], &received, &[], &job()).is_err());
    }

    #[test]
    fn reassembles_fragmented_and_extended_frames() {
        let long = json!({"type": "x", "pad": "a".repeat(300)}).to_string();
        let (a, b) = long.as_bytes().split_at(100);
        let mut data = b"HTTP/1.1 101 OK\r\n\r\n".to_vec();
        data.extend(frame(a, None, false, 1));
        data.extend(frame(b, None, true, 0));
        data.extend(frame(b"ping", None, true, 9));
        let messages = json_messages(&data).unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["pad"].as_str().unwrap().len(), 300);
    }
}
