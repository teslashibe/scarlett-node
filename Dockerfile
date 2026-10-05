FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
COPY third_party/x-go ./third_party/x-go
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /scarlett-node . && \
    mkdir /codex && cp "$(go list -m -f '{{.Dir}}' github.com/teslashibe/open-agent-api)"/codex_profile.json "$(go list -m -f '{{.Dir}}' github.com/teslashibe/open-agent-api)"/codex_scaffold.json /codex/

FROM rust:1.95-bookworm AS prover-builder
WORKDIR /src/prover
COPY prover/ ./
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates gosu && \
    rm -rf /var/lib/apt/lists/* && useradd -m -u 10001 node && mkdir -m 755 /run/scarlett-browser
COPY --from=builder /scarlett-node /usr/local/bin/scarlett-node
COPY --from=prover-builder /src/prover/target/release/scarlett-prover /usr/local/bin/scarlett-prover
COPY --from=builder /codex/ /usr/local/share/scarlett-node/
ENV HOME=/home/node \
    SCARLETT_CODEX_PROFILE=/usr/local/share/scarlett-node/codex_profile.json \
    SCARLETT_CODEX_SCAFFOLD=/usr/local/share/scarlett-node/codex_scaffold.json
COPY packaging/node-container-entrypoint.sh /usr/local/bin/node-container-entrypoint.sh
ENTRYPOINT ["/bin/sh", "/usr/local/bin/node-container-entrypoint.sh"]
