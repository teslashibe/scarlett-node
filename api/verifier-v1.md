# Verifier API v2 for web jobs (large pages)

This is the contract between the Scarlett verifier (`scarlett-prover verifier`),
the app that registers and reads web jobs, and the node's `scarlett-prover
relay-web`. It covers what the large-pages release (verifier with node 0.1.13)
changed for `web.fetch` jobs. Codex and X sessions, receipts and limits are
unchanged. Fixtures are in `api/fixtures/verifier/`; the prover tests read them,
so a change here that the code does not make fails the build.

Pre-launch rule: these shapes replace the old ones directly. There is no
compatibility mode. Release order is app, then verifier, then node.

## 1. The page ceiling

| Name | Value | Meaning |
|---|---|---|
| `PAGE_MAX` | 67,108,864 B (64 MiB) | A web payload's `max_response_bytes`, which must equal it under `web-relay-v1` and `web-browser-v1`. It caps the final hop's **entity** bytes: de-chunked, still content-encoded. |
| `max_wire` | 68,222,976 B = `PAGE_MAX` + `MAX_HEAD` (65,536) + `PAGE_MAX`/64 | Every decrypted byte of one hop up to completion: heads (interim heads too), chunk framing, trailers and the entity. Derived, never on the wire. Chunks of 1 KiB or larger always fit. |
| `web_json_bound(r)` | (r + 1) × 98,798 + 65,536; **658,324** B at r = 5 | The most a web receipt's JSON can hold. 98,798 = base64(`MAX_HEAD`) + 2 × `MAX_URL` + `MAX_COOKIE` + 3 × `MAX_COOKIE_PAIRS` + 3 KiB. |
| `web_reservation` | `web_json_bound(5)` + `PAGE_MAX` = **67,767,188** B | What an unresolved web receipt is charged. Never clamped by `max_record_bytes`. |

A Content-Length above `PAGE_MAX` is refused at the head, before any body byte
is relayed. An entity that passes `PAGE_MAX` by one byte, or a hop that passes
`max_wire`, is refused as `page_too_large`.

## 2. Environment

New variables, validated at startup (the verifier refuses to start otherwise):

| Variable | Default | Range | Rule |
|---|---|---|---|
| `SCARLETT_VERIFIER_MAX_WEB_BYTES` | 201,326,592 | 67,767,188 to 1,099,511,627,776 | `MAX_WEB_BYTES + MAX_RECORD_BYTES <= MAX_TOTAL_BYTES`, so one full X or Codex receipt always fits beside the web pool |
| `SCARLETT_VERIFIER_WEB_CONCURRENCY` | 48 | 1 to 240 | `WEB_CONCURRENCY <= CONCURRENCY - 16`, so X and Codex always keep 16 session slots |

Unchanged: `SCARLETT_VERIFIER_MAX_RECORDS` (1024), `SCARLETT_VERIFIER_MAX_RECORD_BYTES`
(67,108,864, at most that), `SCARLETT_VERIFIER_MAX_TOTAL_BYTES` (268,435,456),
`SCARLETT_VERIFIER_CONCURRENCY` (64). The defaults (256 MiB total, 64 MiB record,
192 MiB web) hold two web reservations, enough for fixtures. Production: total
34,359,738,368 (32 GiB), web 25,769,803,776 (24 GiB, 380 web reservations), an
8 GiB X/Codex floor, web concurrency 48.

## 3. Store accounting

Files in `SCARLETT_VERIFIER_STATE_DIR` (0700): `<name>.json` receipts, and for a
web job whose final hop was verified, `<name>.body`, the entity bytes (0600).
`<name>` is the hex SHA-256 of `<job_id>\n<attempt>`. A body is written as
`<name>.body.partial`, fsynced, renamed and the directory fsynced before the
receipt that says `body_stored: true` is committed.

- A receipt is charged `max(reservation, JSON size)` while unresolved and its JSON
  size once resolved; a stored, unreleased body is charged its size on top.
  `storage.reserved_bytes` is the sum of these charges, and a registration fits
  while it plus the new reservation stays within `max_total_bytes`.
- The **web pool** is the part of those charges that belongs to web receipts
  (their charges and their bodies). A web registration also needs the pool plus
  `web_reservation` to stay within `max_web_bytes`. X and Codex registrations
  check the total only, and the pool rule above means web can never use the
  last X/Codex receipt's room.
- `GET /v1/capacity`'s `storage.can_register` keeps its meaning: one more
  worst-case X or Codex receipt fits.

At startup the verifier:

- deletes every `.body.partial` and every `.body` that no receipt holds as
  stored and unreleased (a crash after the rename and before the receipt
  commit, or after a release and before the unlink);
- refuses to start when a receipt says a body is stored and unreleased but its
  `.body` is missing, not a private regular file, or not `body_bytes` long
  (the bytes are not re-hashed; the app checks the SHA-256 on every read);
- refuses to start on any receipt whose hops hold `body_base64` (a receipt from
  before this release). There is no conversion: pause web and let old web
  receipts age out first (`deploy-verifier.py` checks this).

## 4. Registration: `POST /v1/sessions`

Unchanged request shape (`register-web.json`). A web payload is refused with
`400` unless `max_response_bytes` is 67,108,864. Capacity refusals are `503`:
`{"error":"verifier session capacity reached"}` (records or total) or
`{"error":"verifier web capacity reached"}` (the web pool). The registration
JSON and the `201 {"token":"…","durable":true}` answer are unchanged.

## 5. Receipt: `GET /v1/sessions/{job_id}/{attempt}`

A web receipt (`status: "web_read"`) changes as follows (fixtures
`session-web-complete.json`, `session-web-released.json`,
`session-web-rejected.json`):

- Each hop drops `body_base64` and has `body_stored` (boolean), true exactly on
  the final hop of a complete chain. `body_bytes` (entity bytes, at most
  `PAGE_MAX`) and `body_sha256` stay on every hop: a followable redirect's body
  is hashed and counted but not kept. `received_bytes` is at most `max_wire`.
  A hop has 21 fields under `web-relay-v1`, plus the three node fields under
  `web-browser-v1`.
- `body_released_at_ms` (integer or `null`): when the body file was released by
  `DELETE …/body`. Set only on a complete receipt.
- `rejection` (object or `null`): present exactly when `rejections` is not
  empty, with the same reason:
  `{"reason":"page_too_large","received_bytes":67174401,"entity_bytes":67108865,"declared_bytes":null}`.
  `received_bytes` and `entity_bytes` are what the failed hop had taken when it
  ended (0 when unknown, as for `execution_uncertain` after a restart);
  `declared_bytes` is the final head's Content-Length, else `null`. The counts
  are lower bounds of the page's size.
- `rejections` keeps its shape (at most one reason string). The reasons are
  `tls_failed`, `request_rejected`, `page_too_large` (was `response_too_large`),
  `response_invalid`, `server_closed`, `session_timeout`, `execution_uncertain`
  and `proof_rejected`.

Followability is decided once, when the final head arrives: a 301, 302, 303,
307 or 308 whose `Location` headers are all equal, UTF-8 and resolve to a
canonical public https URL is followable unless the hop is the last allowed
one (`index == max_redirects`). A followable redirect's body is discarded;
every other final response, including a refused or conflicting `Location` and
a redirect on the last allowed hop, is stored. `location` and
`location_refused` keep their meaning.

## 6. Body: `GET` and `DELETE /v1/sessions/{job_id}/{attempt}/body`

Key auth as for every route. The verifier never holds its session lock across
body I/O.

```
GET /v1/sessions/{job_id}/{attempt}/body
Authorization: Bearer <SCARLETT_VERIFIER_KEY>
Range: bytes=0-1048575                       (optional; one range: a-b or a-)

200 OK                                       (no Range)
Content-Type: application/octet-stream
Content-Length: 20
Accept-Ranges: bytes
X-Body-SHA256: f79a78801899fadb98daab6170721698cda95a2b79a35693b5bee908a15f55d1
X-Body-Bytes: 20

206 Partial Content                          (Range)
Content-Range: bytes 0-9/20
Content-Length: 10
(plus the headers above)
```

| Status | Body | When |
|---|---|---|
| 404 | `{"error":"unknown session"}` | no such receipt |
| 404 | `{"error":"no body"}` | the receipt has no stored body: not web, not complete, rejected, or its final hop was never stored |
| 410 | `{"error":"body released"}` | released by `DELETE`, or the receipt was purged (10 minutes after expiry) while this verifier process ran |
| 416 | `{"error":"invalid range"}` and `Content-Range: bytes */N` | a Range that is malformed, has more than one range, or starts at or past N |
| 401, 503 | as on every route | |

`X-Body-SHA256` and `X-Body-Bytes` equal the final hop's `body_sha256` and
`body_bytes`. The app hashes what it reads and treats any difference as a
receipt error. `fixtures/verifier/body-1.bin` is the body of
`session-web-complete.json`.

```
DELETE /v1/sessions/{job_id}/{attempt}/body
→ 204                     released now, released before, or purged while running
→ 404 {"error":"no body"} the receipt never stored a body
→ 404 {"error":"unknown session"}
```

`DELETE` commits `body_released_at_ms` in the receipt first and then unlinks
the file, so a crash in between leaves an orphan file that the next start
deletes. The app calls it after its verified-state commit or a terminal
failure. Purge removes a receipt and its body file 10 minutes after expiry
whether or not it was released.

## 7. Capacity: `GET /v1/capacity`

`capacity.json`. Unchanged fields keep their meaning. New:

- `storage.limits.max_web_bytes` and `limits.max_web_bytes`;
- `storage.body_files`, `storage.body_bytes`: stored, unreleased body files;
- `web`: `can_register` (a web registration fits the pool and the total),
  `reserved_bytes` (web receipt charges without bodies), `body_files`,
  `body_bytes`, `max_bytes` (`max_web_bytes`), `concurrency`
  (`SCARLETT_VERIFIER_WEB_CONCURRENCY`), `active_sessions` (web sessions holding
  a slot now) and `busy_refusals` (sessions turned away as `verifier_busy` since
  start). Pool use is `reserved_bytes + body_bytes`.

Without a state directory (`durable: false`, tests only) `storage` stays `null`
and `web` reports zero bytes.

## 8. Relay sessions (verifier and `relay-web`)

### 8.1 Web session slots
After the token line identifies a web job whose next hop may run, the session
takes one of `SCARLETT_VERIFIER_WEB_CONCURRENCY` web slots. When none is free
the verifier sends one `FAILED` frame `{"reason":"verifier_busy"}`
(`relay-failed-busy.json`) and closes. Nothing is spent: the token, the
session count and the receipt are unchanged, and the connection slot is
released at once. X and Codex sessions never take a web slot.

### 8.2 Hop timing
All limits end the hop as `session_timeout` and are enforced inside the
session, so a sealed request is always opened for the node first:

- the hop runs at most `min(280 s, session limit, receipt expiry - now)`;
- **time to first byte** 60 s, from the sealed request's release (MATERIAL) to
  the first decrypted response byte;
- **idle** 20 s: after the first response byte, 20 s with no bytes from the
  target;
- **throughput floor**: from 30 s after the first response byte, fewer than
  1,966,080 bytes (64 KiB/s) from the target over the trailing 30 s. A trickle
  origin fails within about 35 s of its first byte; a page that finishes within
  30 s is never affected.

The log line names the limit (`hop_limit`, `ttfb_timeout`, `idle_timeout`,
`throughput_floor`); the receipt says `session_timeout`.

### 8.3 FAILED frame
New frame kind **26** (`FAILED`), verifier to node, JSON of at most 256 bytes:
`{"reason":"<reason>"}` with a reason from section 5 or `verifier_busy`. A web
hop that fails after the token was accepted gets one `FAILED` after the
rejection is committed (and after `OPENING`, when a request was sealed), then
the connection closes. A node that receives `FAILED` before `OPENING` for a
request it sent reports relay misuse, as for any session that ends that way.

`relay-web` maps the reason to its stderr class
(`SCARLETT_WEB_ERROR=<class>`): `verifier_busy` → `verifier_busy` (the node
repeats the hop within its budget), `page_too_large` → `page_too_large`, any
other → `fetch_failed`. The full class set is `connect_failed`,
`proxy_failed`, `fetch_failed`, `page_too_large` and `verifier_busy`.

### 8.4 `relay-web` input
`timeout_ms` is 1000 to 280000. The node passes
`min(280 s, lease deadline - 10 s - now)`.

## 9. Logs
`verifier: job <id> proved web hop <n> (HTTP <status>, <entity bytes> bytes, <ms> ms)`;
failures `verifier: job <id> web hop <n> failed: <reason>` with the timing
limit in parentheses for `session_timeout`; `verifier: job <id> web session
refused: verifier_busy`. Never the URL, host or page content.
