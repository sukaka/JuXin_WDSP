ARG GOLANG_IMAGE_DIGEST=sha256:56961d79ea8129efddcc0b8643fd8a5416b4e6228cfd477e3fd61deb2672c587
ARG ALPINE_IMAGE_DIGEST=sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

FROM --platform=$BUILDPLATFORM golang:1.25-alpine${GOLANG_IMAGE_DIGEST:+@$GOLANG_IMAGE_DIGEST} AS builder
ARG TARGETOS
ARG TARGETARCH
ARG GOPROXY=https://goproxy.cn,direct
ENV GOPROXY=${GOPROXY}
WORKDIR /src
COPY go.mod go.sum ./
COPY dynamic_security/ ./dynamic_security/
COPY pcapevidence/ ./pcapevidence/
COPY pcapcapture/ ./pcapcapture/
COPY mirrorcap/ ./mirrorcap/
COPY modules/jiuzhang_guard/go.mod ./modules/jiuzhang_guard/go.mod
COPY modules/jiuzhang_guard/apievents/ ./modules/jiuzhang_guard/apievents/
COPY cmd/pcapd/ ./cmd/pcapd/
RUN go mod download
RUN CGO_ENABLED=0 GOAMD64=v1 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/jiuzhang-pcapd ./cmd/pcapd

FROM alpine:3.24${ALPINE_IMAGE_DIGEST:+@$ALPINE_IMAGE_DIGEST}
RUN addgroup -g 1000 -S pcap && adduser -u 1000 -S -G pcap -H -h /var/lib/jiuzhang pcap \
    && mkdir -p /var/lib/jiuzhang/pcap-hot /etc/jiuzhang \
    && chown -R pcap:pcap /var/lib/jiuzhang
COPY --from=builder /out/jiuzhang-pcapd /usr/local/bin/jiuzhang-pcapd
USER 0:0
ENTRYPOINT ["/usr/local/bin/jiuzhang-pcapd"]
HEALTHCHECK --interval=15s --timeout=3s --retries=3 CMD ["kill", "-0", "1"]
