# Multi-arch index digest, locked identically to docs/DEPENDENCIES.md.
FROM golang:1.25-alpine@sha256:56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587 AS builder

ARG VERSION=2.3.0

WORKDIR /src
COPY wdsp-agent/go.mod wdsp-agent/go.sum ./
RUN go mod download
COPY wdsp-agent/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/wdsp-agent ./cmd/agent

# Multi-arch index digest, shared with the WDSP E2E image.
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

RUN addgroup -g 1000 -S wdsp \
    && adduser -u 1000 -S -G wdsp -H -s /sbin/nologin wdsp \
    && mkdir -p /etc/wdsp-agent /var/lib/wdsp-agent \
    && chown -R 1000:1000 /etc/wdsp-agent /var/lib/wdsp-agent

COPY --from=builder /out/wdsp-agent /usr/local/bin/wdsp-agent
RUN chmod 0755 /usr/local/bin/wdsp-agent

USER 1000:1000

ENTRYPOINT ["/usr/local/bin/wdsp-agent", "run"]
