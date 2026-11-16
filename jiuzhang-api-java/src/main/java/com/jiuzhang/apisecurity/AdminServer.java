package com.jiuzhang.apisecurity;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;

public final class AdminServer {
    private final HttpServer server;
    private final EventStore events;
    private final SchemaRegistry schemas;
    private final AuthorizationPolicy authorization;
    private final BehaviorTracker behavior;
    private final Instant startedAt;

    public AdminServer(
        GatewayConfig config,
        EventStore events,
        SchemaRegistry schemas,
        AuthorizationPolicy authorization,
        BehaviorTracker behavior
    ) throws IOException {
        this.events = events;
        this.schemas = schemas;
        this.authorization = authorization;
        this.behavior = behavior;
        this.startedAt = Instant.now();
        server = HttpServer.create(config.adminListen(), 64);
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        server.createContext("/health", exchange -> handle(exchange, this::health));
        server.createContext("/metrics", exchange -> handle(exchange, this::metrics));
        server.createContext("/apis", exchange -> handle(exchange, this::apis));
        server.createContext("/events", exchange -> handle(exchange, this::events));
        server.createContext("/learning", exchange -> handle(exchange, this::learning));
        server.createContext("/policies", exchange -> handle(exchange, this::policies));
    }

    public void start() {
        server.start();
    }

    public java.net.InetSocketAddress address() {
        return server.getAddress();
    }

    public void stop() {
        server.stop(0);
    }

    private Map<String, Object> health(HttpExchange exchange) {
        return Map.of(
            "status", "ok",
            "version", "0.1.0",
            "started_at", startedAt.toString()
        );
    }

    private Map<String, Object> metrics(HttpExchange exchange) {
        var result = new LinkedHashMap<>(events.metrics());
        result.put("rate_windows", behavior.trackedWindows());
        result.put("object_windows", behavior.trackedObjectWindows());
        return result;
    }

    private Map<String, Object> apis(HttpExchange exchange) {
        return Map.of("items", events.assetList());
    }

    private Map<String, Object> events(HttpExchange exchange) {
        var query = exchange.getRequestURI().getRawQuery();
        var parameters = query(query);
        var endpoint = parameters.get("endpoint");
        var action = parameters.containsKey("action")
            ? Models.Action.valueOf(parameters.get("action").toUpperCase()) : null;
        var limit = parameters.containsKey("limit") ? Integer.parseInt(parameters.get("limit")) : 50;
        return Map.of("items", events.events(endpoint, action, limit).stream().map(this::eventJson).toList());
    }

    private Map<String, Object> learning(HttpExchange exchange) {
        var endpoint = query(exchange.getRequestURI().getRawQuery()).get("endpoint");
        if (endpoint != null) return schemas.candidate(endpoint);
        return Map.of("items", schemas.candidates());
    }

    private Map<String, Object> policies(HttpExchange exchange) {
        return Map.of(
            "formal_endpoints", schemas.formalEndpoints(),
            "role_baselines", authorization.roleBaselineCount(),
            "ownership_relations", authorization.ownershipCount()
        );
    }

    private Map<String, Object> eventJson(Models.ApiEvent event) {
        var result = new LinkedHashMap<String, Object>();
        result.put("event_id", event.eventId());
        result.put("request_id", event.requestId());
        result.put("timestamp", event.timestamp().toString());
        result.put("endpoint", event.endpoint());
        result.put("path", event.path());
        result.put("source_fingerprint", event.client());
        result.put("protocol", event.protocol());
        result.put("status", event.responseStatus());
        result.put("latency_ms", event.latencyMillis());
        result.put("action", event.action().name());
        result.put("risk_score", event.riskScore());
        result.put("risk_level", event.riskLevel().name());
        result.put("finding_count", event.findings().size());
        return result;
    }

    private Map<String, String> query(String query) {
        if (query == null || query.isBlank()) return Map.of();
        var result = new LinkedHashMap<String, String>();
        for (String pair : query.split("&")) {
            var parts = pair.split("=", 2);
            if (parts.length == 2) {
                result.put(
                    java.net.URLDecoder.decode(parts[0], StandardCharsets.UTF_8),
                    java.net.URLDecoder.decode(parts[1], StandardCharsets.UTF_8)
                );
            }
        }
        return result;
    }

    private void handle(
        HttpExchange exchange,
        Handler handler
    ) throws IOException {
        try (exchange) {
            if (!exchange.getRequestMethod().equals("GET")) {
                send(exchange, 405, Map.of("error", "method not allowed"));
                return;
            }
            try {
                send(exchange, 200, handler.get(exchange));
            } catch (IllegalArgumentException error) {
                send(exchange, 400, Map.of("error", "invalid query"));
            } catch (RuntimeException error) {
                System.getLogger(AdminServer.class.getName()).log(
                    System.Logger.Level.ERROR, "admin request failed", error
                );
                send(exchange, 500, Map.of("error", "internal error"));
            }
        }
    }

    private void send(HttpExchange exchange, int status, Map<String, Object> body)
        throws IOException {
        var bytes = Json.stringify(body).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
    }

    @FunctionalInterface
    private interface Handler {
        Map<String, Object> get(HttpExchange exchange);
    }
}
