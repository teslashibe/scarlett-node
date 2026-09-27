FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /scarlett-node . && \
    mkdir /codex && cp "$(go list -m -f '{{.Dir}}' github.com/teslashibe/open-agent-api)"/codex_profile.json "$(go list -m -f '{{.Dir}}' github.com/teslashibe/open-agent-api)"/codex_scaffold.json /codex/

FROM alpine:3.22
RUN adduser -D -u 10001 node
USER node
COPY --from=builder /scarlett-node /usr/local/bin/scarlett-node
COPY --from=builder /codex/ /usr/local/share/scarlett-node/
ENV SCARLETT_CODEX_PROFILE=/usr/local/share/scarlett-node/codex_profile.json \
    SCARLETT_CODEX_SCAFFOLD=/usr/local/share/scarlett-node/codex_scaffold.json
ENTRYPOINT ["scarlett-node"]
