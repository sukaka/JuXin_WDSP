package com.jiuzhang.apisecurity;

import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.file.Files;
import java.time.Duration;
import java.util.Map;
import java.util.Set;

final class CoreTests {
    private CoreTests() {
    }

    static void run() {
        TestSupport.test("config builder validation", CoreTests::configurationValidation);
        TestSupport.test("config file loading and unknown keys", CoreTests::configurationFile);
        TestSupport.test("protocol classification", CoreTests::classification);
        TestSupport.test("path normalization and object extraction", CoreTests::normalization);
        TestSupport.test("invalid paths and percent encoding", CoreTests::invalidPaths);
    }

    private static void configurationValidation() {
        var valid = GatewayConfig.builder().build();
        TestSupport.equal(Models.ProtectionMode.OBSERVE, valid.mode(), "safe default mode");
        TestSupport.rejects(IllegalArgumentException.class, () -> GatewayConfig.builder()
            .upstream(URI.create("file:///tmp/origin")).build());
        TestSupport.rejects(IllegalArgumentException.class, () -> GatewayConfig.builder()
            .identitySalt("short").build());
        TestSupport.rejects(IllegalArgumentException.class, () -> GatewayConfig.builder()
            .adminListen(new InetSocketAddress("0.0.0.0", 19091)).build());
        TestSupport.rejects(IllegalArgumentException.class, () -> GatewayConfig.builder()
            .listen(new InetSocketAddress("127.0.0.1", 18090))
            .adminListen(new InetSocketAddress("127.0.0.1", 18090)).build());
        TestSupport.rejects(IllegalArgumentException.class, () -> GatewayConfig.builder()
            .requestTimeout(Duration.ZERO).build());
    }

    private static void configurationFile() throws Exception {
        var directory = Files.createTempDirectory("api-config-test");
        try {
            var config = directory.resolve("application.properties");
            Files.writeString(config, """
                server.listen=127.0.0.1:18090
                server.admin_listen=127.0.0.1:19091
                server.upstream=http://127.0.0.1:3000
                server.request_timeout=PT10S
                protection.mode=protect
                protection.events_path=var/events.jsonl
                schemas.location=models.json
                """);
            var loaded = GatewayConfig.load(
                config, "configuration-test-salt-with-at-least-32-bytes"
            );
            TestSupport.equal(Models.ProtectionMode.PROTECT, loaded.mode(), "loaded mode");
            TestSupport.equal(directory.resolve("var/events.jsonl").toAbsolutePath().normalize(),
                loaded.eventsPath(), "relative event path");
            Files.writeString(config, "unsupported.value=true\n");
            TestSupport.rejects(IllegalArgumentException.class, () -> GatewayConfig.load(
                config, "configuration-test-salt-with-at-least-32-bytes"
            ));
        } finally {
            deleteTree(directory);
        }
    }

    private static void classification() {
        var classifier = new ApiClassifier();
        TestSupport.equal(Models.Protocol.REST_JSON,
            classifier.classify(context("POST", "/login", "application/json", "{}")).protocol(),
            "JSON API");
        TestSupport.equal(Models.Protocol.GRAPHQL,
            classifier.classify(context("POST", "/graphql", "application/json", "{\"query\":\"q\"}"))
                .protocol(), "GraphQL API");
        TestSupport.equal(Models.Protocol.REST_FORM,
            classifier.classify(context("POST", "/login", "application/x-www-form-urlencoded", "a=1"))
                .protocol(), "form API");
        TestSupport.check(!classifier.classify(context("GET", "/", "text/html", "")).api(),
            "HTML is not an API");
    }

    private static void normalization() {
        var normalizer = new PathNormalizer();
        var result = normalizer.normalize("/users/10001/550e8400-e29b-41d4-a716-446655440000");
        TestSupport.equal("/users/{id}/{uuid}", result.normalizedPath(), "normalized objects");
        TestSupport.equal(2, result.objects().size(), "object count");
        TestSupport.equal("10001", result.objects().get(0).rawValue(), "raw object stays internal");
        TestSupport.equal("/plus/+", normalizer.normalize("/plus/+").normalizedPath(), "plus is path data");
    }

    private static void invalidPaths() {
        var normalizer = new PathNormalizer();
        TestSupport.rejects(IllegalArgumentException.class, () -> normalizer.normalize("relative"));
        TestSupport.rejects(IllegalArgumentException.class, () -> normalizer.normalize("/bad%zz"));
        TestSupport.rejects(IllegalArgumentException.class, () -> normalizer.normalize("/" + "a".repeat(1100)));
    }

    private static Models.RequestContext context(
        String method,
        String path,
        String contentType,
        String body
    ) {
        return new Models.RequestContext(
            java.util.UUID.randomUUID(), method, URI.create(path), "127.0.0.1",
            Map.of("content-type", java.util.List.of(contentType)),
            body.getBytes(java.nio.charset.StandardCharsets.UTF_8)
        );
    }

    private static void deleteTree(java.nio.file.Path directory) throws Exception {
        try (var paths = Files.walk(directory)) {
            for (var path : paths.sorted(java.util.Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        }
    }
}
