package com.jiuzhang.apisecurity;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;

final class GatewayIntegrationTest {
    private GatewayIntegrationTest() {
    }

    static void run() {
        TestSupport.test("gateway normal proxy and runtime discovery", GatewayIntegrationTest::normalProxy);
        TestSupport.test("gateway sensitive query and schema blocking", GatewayIntegrationTest::blocking);
        TestSupport.test("gateway response masking and metrics", GatewayIntegrationTest::masking);
        TestSupport.test("gateway observe mode forwards sensitive request", GatewayIntegrationTest::observeMode);
        TestSupport.test("gateway rate limit and learning candidate", GatewayIntegrationTest::rateAndLearning);
        TestSupport.test("gateway request body limit", GatewayIntegrationTest::bodyLimit);
    }

    private static void normalProxy() throws Exception {
        try (var stack = new TestStack(Models.ProtectionMode.PROTECT, 120, Set.of())) {
            var response = stack.request("GET", "/api/items/123", Map.of(), "");
            TestSupport.equal(200, response.statusCode(), "normal request status");
            TestSupport.equal(1L, stack.originHits.get(), "origin received request");
            TestSupport.check(response.headers().firstValue("x-request-id").isPresent(), "response request ID");
            TestSupport.equal(response.headers().firstValue("x-request-id").orElseThrow(),
                stack.lastRequestId.get(), "request ID reaches origin");

            await(() -> stack.admin("/apis").contains("GET /api/items/{id}"));
            TestSupport.check(stack.admin("/apis").contains("RUNTIME"), "runtime discovery source");
            TestSupport.check(stack.admin("/health").contains("\"status\":\"ok\""), "admin health");
        }
    }

    private static void blocking() throws Exception {
        try (var stack = new TestStack(Models.ProtectionMode.PROTECT, 120, Set.of())) {
            var sensitive = stack.request("GET", "/api/items/123?token=secret-value", Map.of(), "");
            TestSupport.equal(403, sensitive.statusCode(), "sensitive query blocked");
            TestSupport.equal(0L, stack.originHits.get(), "blocked request never reaches origin");

            var malformed = stack.request("POST", "/api/items",
                Map.of("content-type", "application/json"), "{broken");
            TestSupport.equal(403, malformed.statusCode(), "malformed JSON blocked");
            TestSupport.equal(0L, stack.originHits.get(), "malformed request never reaches origin");

            var missingField = stack.request("POST", "/login",
                Map.of("content-type", "application/json"), "{\"password\":\"valid-password\"}");
            TestSupport.equal(403, missingField.statusCode(), "required schema field enforced");
            TestSupport.equal(0L, stack.originHits.get(), "schema violation never reaches origin");
            var eventLog = Files.readString(stack.eventsPath);
            TestSupport.check(!eventLog.contains("secret-value"), "raw query value not persisted");
            TestSupport.check(eventLog.contains("sensitive.in_query"), "sensitive finding persisted");
        }
    }

    private static void masking() throws Exception {
        try (var stack = new TestStack(
            Models.ProtectionMode.PROTECT, 120, Set.of("password", "token")
        )) {
            var response = stack.request("POST", "/login",
                Map.of("content-type", "application/json"),
                "{\"username\":\"alice\",\"password\":\"valid-password\"}");
            TestSupport.equal(200, response.statusCode(), "valid login forwarded");
            TestSupport.check(!response.body().contains("valid-password"), "password masked in response");
            TestSupport.check(!response.body().contains("origin-token"), "token masked in response");
            TestSupport.check(response.body().contains("\"username\":\"alice\""),
                "non-sensitive response field retained");
            await(() -> stack.admin("/metrics").contains("\"masked\":1"));
            TestSupport.check(stack.admin("/metrics").contains("\"event_write_errors\":0"),
                "events persisted without errors");
        }
    }

    private static void observeMode() throws Exception {
        try (var stack = new TestStack(Models.ProtectionMode.OBSERVE, 120, Set.of())) {
            var response = stack.request("GET", "/api/items/123?token=secret-value", Map.of(), "");
            TestSupport.equal(200, response.statusCode(), "observe mode forwards");
            TestSupport.equal(1L, stack.originHits.get(), "observed request reaches origin");
            await(() -> stack.admin("/events").contains("\"action\":\"OBSERVE\""));
            var eventLog = Files.readString(stack.eventsPath);
            TestSupport.check(eventLog.contains("\"action\":\"OBSERVE\""), "observed action persisted");
            TestSupport.check(!eventLog.contains("secret-value"), "observe log still redacts values");
        }
    }

    private static void rateAndLearning() throws Exception {
        try (var stack = new TestStack(Models.ProtectionMode.PROTECT, 2, Set.of())) {
            TestSupport.equal(200, stack.request("GET", "/api/list", Map.of(), "").statusCode(),
                "first rate window request");
            TestSupport.equal(200, stack.request("GET", "/api/list", Map.of(), "").statusCode(),
                "second rate window request");
            var limited = stack.request("GET", "/api/list", Map.of(), "");
            TestSupport.equal(429, limited.statusCode(), "third request rate limited");
            TestSupport.equal(2L, stack.originHits.get(), "only two requests reach origin");
            await(() -> stack.admin("/learning").contains("GET /api/list"));
            var learning = stack.admin("/learning");
            TestSupport.check(learning.contains("\"sample_count\":2"), "two clean samples learned");
            TestSupport.check(learning.contains("CANDIDATE_ONLY"), "learning remains candidate");
            TestSupport.check(stack.admin("/metrics").contains("\"rate_limited\":1"),
                "rate limit metric");
        }
    }

    private static void bodyLimit() throws Exception {
        try (var stack = new TestStack(Models.ProtectionMode.PROTECT, 120, Set.of())) {
            var response = stack.request("POST", "/api/items",
                Map.of("content-type", "application/json"), "{\"text\":\"" + "x".repeat(1100) + "\"}");
            TestSupport.equal(413, response.statusCode(), "oversized request rejected");
            TestSupport.equal(0L, stack.originHits.get(), "oversized request never reaches origin");
        }
    }

    private static void await(Condition condition) throws Exception {
        for (int attempt = 0; attempt < 100; attempt++) {
            if (condition.evaluate()) return;
            Thread.sleep(20);
        }
        throw new AssertionError("condition was not met before timeout");
    }

    @FunctionalInterface
    private interface Condition {
        boolean evaluate() throws Exception;
    }

    private static final class TestStack implements AutoCloseable {
        private final Path directory;
        private final Path eventsPath;
        private final HttpServer origin;
        private final ApiGateway gateway;
        private final AdminServer admin;
        private final HttpClient client = HttpClient.newHttpClient();
        private final AtomicLong originHits = new AtomicLong();
        private final java.util.concurrent.atomic.AtomicReference<String> lastRequestId =
            new java.util.concurrent.atomic.AtomicReference<>("");

        private TestStack(
            Models.ProtectionMode mode,
            long rateLimit,
            Set<String> maskFields
        ) throws Exception {
            directory = Files.createTempDirectory("api-gateway-integration");
            eventsPath = directory.resolve("events.jsonl");
            origin = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 32);
            origin.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
            origin.createContext("/", this::origin);
            origin.start();

            var schemaPath = directory.resolve("models.json");
            Files.writeString(schemaPath, """
                {"models":{"POST /login":{"fields":{
                  "body:username":{"type":"STRING","required":true,"max_length":64},
                  "body:password":{"type":"STRING","required":true,"max_length":128}
                }}}}
                """);
            var authzPath = directory.resolve("authz.json");
            Files.writeString(authzPath, "{}");
            var config = GatewayConfig.builder()
                .listen(new InetSocketAddress("127.0.0.1", 0))
                .adminListen(new InetSocketAddress("127.0.0.1", 0))
                .upstream(URI.create("http://127.0.0.1:" + origin.getAddress().getPort()))
                .mode(mode)
                .rateLimit(rateLimit)
                .eventsPath(eventsPath)
                .schemaLocation(schemaPath)
                .responseMaskFields(maskFields)
                .maxBodyBytes(1024)
                .identitySalt("integration-test-salt-with-at-least-32-bytes")
                .build();
            var registry = SchemaRegistry.load(schemaPath);
            var policy = AuthorizationPolicy.load(authzPath, config.identitySalt());
            gateway = new ApiGateway(config, registry, policy, null);
            admin = new AdminServer(config, gateway.events(), registry, policy, gateway.behavior());
            gateway.start();
            admin.start();
        }

        private HttpResponse<String> request(
            String method,
            String path,
            Map<String, String> headers,
            String body
        ) throws Exception {
            var builder = HttpRequest.newBuilder(URI.create(base() + path))
                .timeout(Duration.ofSeconds(10))
                .method(method, HttpRequest.BodyPublishers.ofString(body));
            headers.forEach(builder::header);
            return client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        }

        private String admin(String path) throws Exception {
            var request = HttpRequest.newBuilder(URI.create(adminBase() + path)).GET().build();
            return client.send(request, HttpResponse.BodyHandlers.ofString()).body();
        }

        private String base() {
            return "http://127.0.0.1:" + gateway.address().getPort();
        }

        private String adminBase() {
            return "http://127.0.0.1:" + admin.address().getPort();
        }

        private void origin(HttpExchange exchange) throws IOException {
            try (exchange) {
                originHits.incrementAndGet();
                lastRequestId.set(exchange.getRequestHeaders().getFirst("X-Request-ID"));
                var received = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                Map<String, Object> response;
                if (exchange.getRequestURI().getPath().equals("/login")) {
                    response = Map.of(
                        "username", "alice", "password", "valid-password", "token", "origin-token"
                    );
                } else {
                    response = Map.of(
                        "method", exchange.getRequestMethod(), "received", received, "items", List.of()
                    );
                }
                var bytes = Json.stringify(response).getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, bytes.length);
                exchange.getResponseBody().write(bytes);
            }
        }

        @Override
        public void close() throws IOException {
            admin.stop();
            gateway.stop();
            origin.stop(0);
            try (var paths = Files.walk(directory)) {
                for (var path : paths.sorted(Comparator.reverseOrder()).toList()) {
                    Files.deleteIfExists(path);
                }
            }
        }
    }
}
