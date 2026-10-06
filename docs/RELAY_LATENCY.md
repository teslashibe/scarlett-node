# Relay latency profiling

Run the bounded unpaid relay profile from `prover/` on macOS or Linux:

```sh
cargo test --locked benchmark_synthetic_relay_latency -- --ignored --nocapture
```

It measures six fresh relay sessions in each mode against a private TLS server
on loopback. Each session creates fresh provider TLS and oblivious-transfer
state, checks the authorized request, verifies the returned bytes, and checks
the record opening. One mode has no added control-link delay; the other delays
each complete control frame by 25 ms in each direction. It contacts no provider
or production verifier and prints only finite phase names and numeric timings.

The fixture excludes the production control connection's TCP/TLS setup,
coordinator acceptance/reporting, journal fsync and real provider response
time. Its delay per frame is a comparison tool, not a WAN throughput model.
Median and maximum use six samples; they do not establish a production tail
latency or scrape capacity. Certificate fixture setup is outside the timer.

Local `relay_authorization`, `x_tls_ready` and `ot_ready` spans start together.
Authorization includes the wait for TLS, OT, policy checks and request material.
Their nested timings overlap and must not be added. A node's `helper_wall` also
includes process startup/shutdown and is measured on a different clock from the
helper's spans. Compare cohorts with the same operation, page count and proof
mode when assessing a production change.

Each production relay read opens X TCP first, then authenticates verifier
control TLS and presents the one-use token. Overlapping those connections can
save at most the shorter setup duration, but a slow X connection would age the
verifier's ten-second token deadline. Preserve this ordering until a measured
benefit justifies a design that maintains that deadline. Fresh TLS, OT and
request authorization are required for every read.
