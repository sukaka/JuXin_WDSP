package com.jiuzhang.apisecurity;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

public final class EventStore implements AutoCloseable {
    private static final int MAX_EVENTS_IN_MEMORY = 5000;
    private final Path path;
    private final FileChannel channel;
    private final String salt;
    private final ArrayDeque<Models.ApiEvent> recent = new ArrayDeque<>();
    private final Map<String, Asset> assets = new LinkedHashMap<>();
    private final AtomicLong total = new AtomicLong();
    private final AtomicLong blocked = new AtomicLong();
    private final AtomicLong rateLimited = new AtomicLong();
    private final AtomicLong masked = new AtomicLong();
    private final AtomicLong writeErrors = new AtomicLong();

    public EventStore(Path path, String salt) throws IOException {
        this.path = path;
        this.salt = salt;
        var parent = path.toAbsolutePath().getParent();
        if (parent != null) Files.createDirectories(parent);
        if (Files.notExists(path)) {
            Files.createFile(path);
            setOwnerOnly(path);
        }
        channel = FileChannel.open(path, StandardOpenOption.WRITE, StandardOpenOption.APPEND);
    }

    private void setOwnerOnly(Path target) throws IOException {
        try {
            Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException ignored) {
            // Non-POSIX filesystems apply their own inherited ACLs.
        }
    }

    public synchronized void record(Models.RequestContext context) {
        var event = new Models.ApiEvent(
            UUID.randomUUID().toString(),
            context.requestId().toString(),
            Instant.now(),
            context.endpointKey(),
            context.method(),
            context.normalizedPath(),
            Fingerprints.hmac(salt, "ip:" + context.clientAddress()),
            context.identity().fingerprint(),
            context.classification().protocol().name(),
            context.responseStatus(),
            context.elapsedMillis(),
            context.finalAction(),
            context.riskScore(),
            context.riskLevel(),
            context.findings()
        );
        try {
            write(event);
            total.incrementAndGet();
            switch (event.action()) {
                case BLOCK -> blocked.incrementAndGet();
                case RATE_LIMIT -> rateLimited.incrementAndGet();
                case MASK_RESPONSE -> masked.incrementAndGet();
                default -> { }
            }
            recent.addLast(event);
            if (recent.size() > MAX_EVENTS_IN_MEMORY) recent.removeFirst();
            assets.computeIfAbsent(event.endpoint(), key -> new Asset(key)).record(event);
        } catch (IOException error) {
            writeErrors.incrementAndGet();
            throw new IllegalStateException("cannot persist API security event", error);
        }
    }

    private void write(Models.ApiEvent event) throws IOException {
        var encoded = Json.stringify(eventJson(event)) + "\n";
        var buffer = ByteBuffer.wrap(encoded.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        while (buffer.hasRemaining()) channel.write(buffer);
        channel.force(false);
    }

    private Map<String, Object> eventJson(Models.ApiEvent event) {
        var result = new LinkedHashMap<String, Object>();
        result.put("event_id", event.eventId());
        result.put("request_id", event.requestId());
        result.put("timestamp", event.timestamp().toString());
        result.put("endpoint", event.endpoint());
        result.put("method", event.method());
        result.put("path", event.path());
        result.put("source_fingerprint", event.client());
        result.put("identity_fingerprint", event.identityFingerprint());
        result.put("protocol", event.protocol());
        result.put("response_status", event.responseStatus());
        result.put("latency_ms", event.latencyMillis());
        result.put("action", event.action().name());
        result.put("risk_score", event.riskScore());
        result.put("risk_level", event.riskLevel().name());
        result.put("findings", event.findings().stream().map(this::findingJson).toList());
        return result;
    }

    private Map<String, Object> findingJson(Models.Finding finding) {
        var result = new LinkedHashMap<String, Object>();
        result.put("rule_id", finding.ruleId());
        result.put("detector", finding.detector());
        result.put("severity", finding.severity().name());
        result.put("score", finding.score());
        result.put("proposed_action", finding.proposedAction().name());
        result.put("evidence", finding.evidence());
        return result;
    }

    public synchronized List<Models.ApiEvent> events(
        String endpoint,
        Models.Action action,
        int limit
    ) {
        if (limit < 1 || limit > 200) throw new IllegalArgumentException("event limit must be 1..200");
        return recent.stream()
            .filter(event -> endpoint == null || event.endpoint().equals(endpoint))
            .filter(event -> action == null || event.action() == action)
            .sorted(Comparator.comparing(Models.ApiEvent::timestamp).reversed())
            .limit(limit)
            .toList();
    }

    public synchronized List<Map<String, Object>> assetList() {
        return assets.values().stream().map(Asset::toJson).toList();
    }

    public Map<String, Object> metrics() {
        var result = new LinkedHashMap<String, Object>();
        result.put("events", total.get());
        result.put("blocked", blocked.get());
        result.put("rate_limited", rateLimited.get());
        result.put("masked", masked.get());
        result.put("event_write_errors", writeErrors.get());
        result.put("recent_event_capacity", MAX_EVENTS_IN_MEMORY);
        synchronized (this) {
            result.put("discovered_endpoints", assets.size());
        }
        return result;
    }

    public Path path() {
        return path;
    }

    @Override
    public void close() throws IOException {
        channel.close();
    }

    private static final class Asset {
        private final String endpoint;
        private final Instant firstSeen;
        private Instant lastSeen;
        private long requests;
        private long findings;
        private String protocol = Models.Protocol.UNKNOWN.name();

        private Asset(String endpoint) {
            this.endpoint = endpoint;
            this.firstSeen = Instant.now();
        }

        private void record(Models.ApiEvent event) {
            requests++;
            lastSeen = event.timestamp();
            findings += event.findings().size();
            protocol = event.protocol();
        }

        private Map<String, Object> toJson() {
            var result = new LinkedHashMap<String, Object>();
            result.put("endpoint", endpoint);
            result.put("first_seen", firstSeen.toString());
            result.put("last_seen", lastSeen.toString());
            result.put("requests", requests);
            result.put("findings", findings);
            result.put("protocol", protocol);
            result.put("discovery", "RUNTIME");
            return result;
        }
    }
}
