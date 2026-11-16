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
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class ApiGateway {
    private static final Set<String> HOP_HEADERS = Set.of(
        "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
        "te", "trailer", "transfer-encoding", "upgrade", "proxy-connection"
    );

    private final GatewayConfig config;
    private final SchemaRegistry schemas;
    private final AuthorizationPolicy authorization;
    private final ApiClassifier classifier = new ApiClassifier();
    private final PathNormalizer normalizer = new PathNormalizer();
    private final PayloadParser payloadParser = new PayloadParser();
    private final IdentityExtractor identities;
    private final SensitiveDataDetector sensitive = new SensitiveDataDetector();
    private final DecisionEngine decisions = new DecisionEngine();
    private final BehaviorTracker behavior;
    private final ResponseGuard responses;
    private final EventStore events;
    private final HttpClient client;
    private final HttpServer server;
    private final ExecutorService executor;

    public ApiGateway(
        GatewayConfig config,
        SchemaRegistry schemas,
        AuthorizationPolicy authorization,
        String jwtHmacSecret
    ) throws IOException {
        this.config = config;
        this.schemas = schemas;
        this.authorization = authorization;
        identities = new IdentityExtractor(config.identitySalt(), jwtHmacSecret);
        behavior = new BehaviorTracker(
            config.rateLimit(), config.rateWindow(), config.trackedClients(), config.identitySalt()
        );
        responses = new ResponseGuard(config.responseMaskFields(), sensitive);
        events = new EventStore(config.eventsPath(), config.identitySalt());
        client = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(config.requestTimeout())
            .build();
        executor = Executors.newVirtualThreadPerTaskExecutor();
        server = HttpServer.create(config.listen(), 128);
        server.setExecutor(executor);
        server.createContext("/", this::handle);
    }

    public void start() {
        server.start();
    }

    public InetSocketAddress address() {
        return server.getAddress();
    }

    public EventStore events() {
        return events;
    }

    public BehaviorTracker behavior() {
        return behavior;
    }

    public void stop() {
        server.stop(0);
        executor.shutdown();
        try {
            events.close();
        } catch (IOException error) {
            System.getLogger(ApiGateway.class.getName()).log(
                System.Logger.Level.ERROR, "failed to close event store", error
            );
        }
    }

    private void handle(HttpExchange exchange) throws IOException {
        var context = new Models.RequestContext(
            UUID.randomUUID(),
            exchange.getRequestMethod(),
            exchange.getRequestURI(),
            exchange.getRemoteAddress().getAddress().getHostAddress(),
            exchange.getRequestHeaders(),
            new byte[0]
        );
        try (exchange) {
            var body = exchange.getRequestBody().readNBytes(config.maxBodyBytes() + 1);
            if (body.length > config.maxBodyBytes()) {
                context.add(Models.Finding.of(
                    "protocol.body_too_large", "protocol",
                    Models.Severity.HIGH, 40, Models.Action.BLOCK
                ));
                context.finalAction(Models.Action.BLOCK);
                sendJson(exchange, context, 413, "request body too large");
                recordSafely(context);
                return;
            }
            context = new Models.RequestContext(
                context.requestId(), context.method(), context.requestUri(), context.clientAddress(),
                context.headers(), body
            );

            PathNormalizer.Result path;
            try {
                path = normalizer.normalize(context.requestUri().getRawPath());
            } catch (IllegalArgumentException error) {
                context.add(Models.Finding.of(
                    "protocol.invalid_path", "protocol",
                    Models.Severity.HIGH, 40, Models.Action.BLOCK
                ));
                context.finalAction(Models.Action.BLOCK);
                sendJson(exchange, context, 400, "invalid request path");
                recordSafely(context);
                return;
            }
            context.normalizedPath(path.normalizedPath());
            context.classification(classifier.classify(context));
            if (!context.classification().api()) {
                forward(exchange, context, null);
                return;
            }

            var identity = identities.extract(context);
            context.identity(identity.identity());
            context.addAll(identity.findings());
            var rate = behavior.acquire(context);
            if (rate != null) context.add(rate);
            var earlyDecision = decisions.request(config.mode(), context.findings());
            if (earlyDecision == Models.Action.RATE_LIMIT) {
                context.finalAction(earlyDecision);
                sendJson(exchange, context, 429, "too many requests");
                recordSafely(context);
                return;
            }

            try {
                context.parameters(payloadParser.parse(context, path));
            } catch (IllegalArgumentException error) {
                context.add(Models.Finding.of(
                    "protocol.malformed_payload", "protocol",
                    Models.Severity.HIGH, 40, Models.Action.BLOCK
                ));
            }
            context.addAll(sensitive.inspect(context.parameters()));
            context.addAll(schemas.validate(context.endpointKey(), context.parameters()));
            context.addAll(authorization.evaluate(context, path));
            var enumeration = behavior.observeObjects(context, path);
            if (enumeration != null) context.add(enumeration);

            var decision = decisions.request(config.mode(), context.findings());
            context.finalAction(decision);
            if (decision == Models.Action.BLOCK) {
                sendJson(exchange, context, 403, "request blocked by API security policy");
                recordSafely(context);
                return;
            }
            if (decision == Models.Action.RATE_LIMIT) {
                sendJson(exchange, context, 429, "too many requests");
                recordSafely(context);
                return;
            }
            forward(exchange, context, path);
        } catch (IOException error) {
            System.getLogger(ApiGateway.class.getName()).log(
                System.Logger.Level.WARNING, "client connection failed", error
            );
        } catch (RuntimeException error) {
            System.getLogger(ApiGateway.class.getName()).log(
                System.Logger.Level.ERROR, "request processing failed", error
            );
            context.finalAction(Models.Action.OBSERVE);
            sendJson(exchange, context, 500, "internal gateway error");
            recordSafely(context);
        }
    }

    private void forward(
        HttpExchange exchange,
        Models.RequestContext context,
        PathNormalizer.Result path
    ) {
        try {
            var upstream = sendUpstream(context);
            if (upstream.body().length > config.maxResponseBytes()) {
                context.add(Models.Finding.of(
                    "upstream.response_too_large", "api_response",
                    Models.Severity.HIGH, 20, Models.Action.OBSERVE
                ));
                context.finalAction(Models.Action.OBSERVE);
                sendJson(exchange, context, 502, "upstream response exceeds the inspection limit");
                recordSafely(context);
                return;
            }

            var responseBody = upstream.body();
            var encoding = firstHeader(upstream, "content-encoding");
            var shouldInspect = context.classification().api()
                && (encoding.isBlank() || encoding.equalsIgnoreCase("identity"));
            var plan = shouldInspect
                ? responses.plan(upstream.statusCode(), firstHeader(upstream, "content-type"), responseBody)
                : null;
            if (plan != null) context.addAll(plan.findings());
            var action = decisions.response(
                config.mode(), context.findings(), plan != null && plan.hasTransformations()
            );
            context.finalAction(action);
            if (action == Models.Action.MASK_RESPONSE) {
                try {
                    responseBody = responses.apply(plan);
                    context.add(Models.Finding.of(
                        "response.mask_applied", "api_response",
                        Models.Severity.INFO, 0, Models.Action.OBSERVE
                    ));
                } catch (RuntimeException error) {
                    context.add(Models.Finding.of(
                        "response.mask_failed", "api_response",
                        Models.Severity.HIGH, 20, Models.Action.OBSERVE
                    ));
                    context.finalAction(Models.Action.OBSERVE);
                }
            }
            sendUpstream(exchange, context, upstream, responseBody, responseBody != upstream.body());
            if (path != null && upstream.statusCode() < 400 && context.findings().isEmpty()) {
                schemas.observe(context.endpointKey(), context.parameters());
            }
            recordSafely(context);
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            context.finalAction(Models.Action.OBSERVE);
            sendJson(exchange, context, 504, "upstream request interrupted");
            recordSafely(context);
        } catch (IOException | IllegalArgumentException error) {
            context.add(Models.Finding.of(
                "upstream.unavailable", "api_response",
                Models.Severity.HIGH, 10, Models.Action.OBSERVE
            ));
            context.finalAction(Models.Action.OBSERVE);
            sendJson(exchange, context, 502, "upstream unavailable");
            recordSafely(context);
        }
    }

    private HttpResponse<byte[]> sendUpstream(Models.RequestContext context)
        throws IOException, InterruptedException {
        var suffix = context.requestUri().toASCIIString();
        var base = config.upstream().toString();
        while (base.endsWith("/")) base = base.substring(0, base.length() - 1);
        var target = URI.create(base + suffix);
        var builder = HttpRequest.newBuilder(target)
            .timeout(config.requestTimeout())
            .method(
                context.method(),
                HttpRequest.BodyPublishers.ofByteArray(context.body())
            );
        context.headers().forEach((name, values) -> {
            if (HOP_HEADERS.contains(name.toLowerCase())
                || name.equalsIgnoreCase("host") || name.equalsIgnoreCase("content-length")
                || name.equalsIgnoreCase("expect")) return;
            for (String value : values) builder.header(name, value);
        });
        builder.header("X-Request-ID", context.requestId().toString());
        builder.header("X-Forwarded-For", context.clientAddress());
        builder.header("X-Forwarded-Proto", "http");
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofByteArray());
    }

    private void sendUpstream(
        HttpExchange exchange,
        Models.RequestContext context,
        HttpResponse<byte[]> upstream,
        byte[] body,
        boolean transformed
    ) throws IOException {
        upstream.headers().map().forEach((name, values) -> {
            var lower = name.toLowerCase();
            if (HOP_HEADERS.contains(lower) || lower.equals("content-length")) return;
            if (transformed && Set.of("etag", "content-md5", "content-encoding").contains(lower)) {
                return;
            }
            for (String value : values) exchange.getResponseHeaders().add(name, value);
        });
        exchange.getResponseHeaders().set("X-Request-ID", context.requestId().toString());
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        context.responseStatus(upstream.statusCode());
        sendBody(exchange, upstream.statusCode(), body, context.method().equals("HEAD"));
    }

    private void sendJson(
        HttpExchange exchange,
        Models.RequestContext context,
        int status,
        String message
    ) {
        try {
            var body = Json.stringify(Map.of(
                "error", message,
                "request_id", context.requestId().toString()
            )).getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
            exchange.getResponseHeaders().set("Cache-Control", "no-store");
            exchange.getResponseHeaders().set("X-Request-ID", context.requestId().toString());
            exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
            context.responseStatus(status);
            sendBody(exchange, status, body, context.method().equals("HEAD"));
        } catch (IOException error) {
            System.getLogger(ApiGateway.class.getName()).log(
                System.Logger.Level.WARNING, "failed to send local response", error
            );
        }
    }

    private void sendBody(HttpExchange exchange, int status, byte[] body, boolean head)
        throws IOException {
        if (head || status == 204 || status == 304) {
            exchange.sendResponseHeaders(status, -1);
            return;
        }
        exchange.sendResponseHeaders(status, body.length);
        exchange.getResponseBody().write(body);
    }

    private String firstHeader(HttpResponse<byte[]> response, String name) {
        return response.headers().firstValue(name).orElse("");
    }

    private void recordSafely(Models.RequestContext context) {
        if (!context.classification().api()) return;
        try {
            events.record(context);
        } catch (RuntimeException error) {
            System.getLogger(ApiGateway.class.getName()).log(
                System.Logger.Level.ERROR, "failed to persist API security event", error
            );
        }
    }
}
