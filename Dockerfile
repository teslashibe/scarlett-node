FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -o /scarlett-node .

FROM alpine:3.22
RUN adduser -D -u 10001 node
USER node
COPY --from=builder /scarlett-node /usr/local/bin/scarlett-node
ENTRYPOINT ["scarlett-node"]
