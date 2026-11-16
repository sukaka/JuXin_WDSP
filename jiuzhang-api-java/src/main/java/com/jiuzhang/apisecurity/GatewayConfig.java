package com.jiuzhang.apisecurity;

import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;

public record GatewayConfig(
    InetSocketAddress listen,
    InetSocketAddress adminListen,
    URI upstream,
    Duration requestTimeout,
    Models.ProtectionMode mode,
    int maxBodyBytes,
    int maxResponseBytes,
    Path eventsPath,
    long rateLimit,
    Duration rateWindow,
    int trackedClients,
    Set<String> responseMaskFields,
    Path schemaLocation,
    String identitySalt
) {
    private static final Set<String> ALLOWED_KEYS = Set.of(
        "server.listen", "server.admin_listen", "server.upstream", "server.request_timeout",
        "protection.mode", "protection.max_body_bytes", "protection.max_response_bytes",
        "protection.events_path", "protection.rate_limit", "protection.rate_window",
        "protection.tracked_clients", "protection.response_mask_fields", "schemas.location"
    );

    public GatewayConfig {
        if (listen.getPort() != 0 && listen.equals(adminListen)) {
            throw new IllegalArgumentException("proxy and admin listeners must differ");
        }
        if (!adminListen.getAddress().isLoopbackAddress()) {
            throw new IllegalArgumentException("the unauthenticated admin listener must be loopback");
        }
        if (!Set.of("http", "https").contains(upstream.getScheme())) {
            throw new IllegalArgumentException("upstream must use HTTP or HTTPS");
        }
        if (upstream.getHost() == null || upstream.getUserInfo() != null
            || upstream.getRawQuery() != null || upstream.getRawFragment() != null) {
            throw new IllegalArgumentException("upstream contains forbidden URL components");
        }
        if (requestTimeout.isZero() || requestTimeout.isNegative()
            || requestTimeout.compareTo(Duration.ofMinutes(5)) > 0) {
            throw new IllegalArgumentException("request timeout must be between 1ms and 5m");
        }
        if (maxBodyBytes < 1024 || maxBodyBytes > 100 * 1024 * 1024) {
            throw new IllegalArgumentException("request body limit must be between 1KiB and 100MiB");
        }
        if (maxResponseBytes < 1024 || maxResponseBytes > 100 * 1024 * 1024) {
            throw new IllegalArgumentException("response body limit must be between 1KiB and 100MiB");
        }
        if (rateLimit <= 0 || trackedClients <= 0 || rateWindow.isZero() || rateWindow.isNegative()) {
            throw new IllegalArgumentException("rate limit values must be positive");
        }
        if (identitySalt == null || identitySalt.getBytes(StandardCharsets.UTF_8).length < 32) {
            throw new IllegalArgumentException("identity salt must contain at least 32 UTF-8 bytes");
        }
        responseMaskFields = Set.copyOf(responseMaskFields);
        for (String field : responseMaskFields) {
            if (field.isBlank() || field.length() > 128 || field.contains("..")) {
                throw new IllegalArgumentException("invalid response mask field");
            }
        }
    }

    public static GatewayConfig load(Path path, String identitySalt) throws IOException {
        var properties = new Properties();
        try (var reader = new InputStreamReader(
            Files.newInputStream(path), StandardCharsets.UTF_8
        )) {
            properties.load(reader);
        }
        for (Object key : properties.keySet()) {
            if (!ALLOWED_KEYS.contains(String.valueOf(key))) {
                throw new IllegalArgumentException("unknown configuration key: " + key);
            }
        }
        var base = path.toAbsolutePath().getParent();
        return new GatewayConfig(
            address(required(properties, "server.listen")),
            address(required(properties, "server.admin_listen")),
            URI.create(required(properties, "server.upstream")),
            Duration.parse(required(properties, "server.request_timeout")),
            mode(required(properties, "protection.mode")),
            integer(properties, "protection.max_body_bytes", 1_048_576),
            integer(properties, "protection.max_response_bytes", 2_097_152),
            base.resolve(properties.getProperty(
                "protection.events_path", "var/api-security-events.jsonl"
            )).normalize(),
            longValue(properties, "protection.rate_limit", 120),
            Duration.parse(properties.getProperty("protection.rate_window", "PT1M")),
            integer(properties, "protection.tracked_clients", 10_000),
            fields(properties.getProperty("protection.response_mask_fields", "")),
            base.resolve(properties.getProperty("schemas.location", "schemas.example.json")).normalize(),
            identitySalt
        );
    }

    public static Builder builder() {
        return new Builder();
    }

    private static String required(Properties properties, String key) {
        var value = properties.getProperty(key);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("missing configuration key: " + key);
        }
        return value.strip();
    }

    private static int integer(Properties properties, String key, int fallback) {
        var value = properties.getProperty(key);
        return value == null ? fallback : Integer.parseInt(value);
    }

    private static long longValue(Properties properties, String key, long fallback) {
        var value = properties.getProperty(key);
        return value == null ? fallback : Long.parseLong(value);
    }

    private static Models.ProtectionMode mode(String value) {
        try {
            return Models.ProtectionMode.valueOf(value.strip().toUpperCase());
        } catch (IllegalArgumentException error) {
            throw new IllegalArgumentException("unknown protection mode: " + value);
        }
    }

    private static InetSocketAddress address(String value) {
        try {
            var uri = new URI("tcp://" + value);
            if (uri.getHost() == null || uri.getPort() < 1 || uri.getPort() > 65535) {
                throw new IllegalArgumentException("invalid socket address: " + value);
            }
            var address = new InetSocketAddress(uri.getHost(), uri.getPort());
            if (address.isUnresolved()) {
                throw new IllegalArgumentException("listener address cannot be resolved: " + value);
            }
            return address;
        } catch (java.net.URISyntaxException error) {
            throw new IllegalArgumentException("invalid socket address: " + value, error);
        }
    }

    private static Set<String> fields(String value) {
        var result = new LinkedHashSet<String>();
        for (String field : value.split(",")) {
            if (!field.isBlank()) result.add(field.strip());
        }
        return result;
    }

    public static final class Builder {
        private InetSocketAddress listen = new InetSocketAddress("127.0.0.1", 0);
        private InetSocketAddress adminListen = new InetSocketAddress("127.0.0.1", 19091);
        private URI upstream = URI.create("http://127.0.0.1:3000");
        private Duration requestTimeout = Duration.ofSeconds(15);
        private Models.ProtectionMode mode = Models.ProtectionMode.OBSERVE;
        private int maxBodyBytes = 1_048_576;
        private int maxResponseBytes = 2_097_152;
        private Path eventsPath = Path.of("build/test-events.jsonl");
        private long rateLimit = 120;
        private Duration rateWindow = Duration.ofMinutes(1);
        private int trackedClients = 10_000;
        private Set<String> responseMaskFields = Set.of();
        private Path schemaLocation = Path.of("schemas.example.json");
        private String identitySalt = "unit-test-only-identity-salt-32-bytes-minimum";

        public Builder listen(InetSocketAddress value) { listen = value; return this; }
        public Builder adminListen(InetSocketAddress value) { adminListen = value; return this; }
        public Builder upstream(URI value) { upstream = value; return this; }
        public Builder requestTimeout(Duration value) { requestTimeout = value; return this; }
        public Builder mode(Models.ProtectionMode value) { mode = value; return this; }
        public Builder maxBodyBytes(int value) { maxBodyBytes = value; return this; }
        public Builder maxResponseBytes(int value) { maxResponseBytes = value; return this; }
        public Builder eventsPath(Path value) { eventsPath = value; return this; }
        public Builder rateLimit(long value) { rateLimit = value; return this; }
        public Builder rateWindow(Duration value) { rateWindow = value; return this; }
        public Builder trackedClients(int value) { trackedClients = value; return this; }
        public Builder responseMaskFields(Set<String> value) { responseMaskFields = value; return this; }
        public Builder schemaLocation(Path value) { schemaLocation = value; return this; }
        public Builder identitySalt(String value) { identitySalt = value; return this; }

        public GatewayConfig build() {
            return new GatewayConfig(
                listen, adminListen, upstream, requestTimeout, mode, maxBodyBytes,
                maxResponseBytes, eventsPath, rateLimit, rateWindow, trackedClients,
                responseMaskFields, schemaLocation, identitySalt
            );
        }
    }
}
