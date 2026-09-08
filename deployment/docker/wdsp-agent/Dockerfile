FROM golang:1.25.6-alpine AS builder

ARG VERSION=2.3.0

WORKDIR /src
COPY wdsp-agent/go.mod wdsp-agent/go.sum ./
RUN go mod download
COPY wdsp-agent/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/wdsp-agent ./cmd/agent

# Multi-arch index digest, shared with the WDSP E2E image.
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

COPY --from=builder /out/wdsp-agent /usr/local/bin/wdsp-agent
RUN mkdir -p /etc/wdsp-agent /var/lib/wdsp-agent \
    && chmod 0755 /usr/local/bin/wdsp-agent

ENTRYPOINT ["/usr/local/bin/wdsp-agent", "run"]
