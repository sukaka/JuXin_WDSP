package com.jiuzhang.apisecurity;

import java.util.Locale;

public final class ApiClassifier {
    public Models.Classification classify(Models.RequestContext context) {
        var contentType = context.header("content-type").toLowerCase(Locale.ROOT);
        var accept = context.header("accept").toLowerCase(Locale.ROOT);
        var path = context.requestUri().getRawPath().toLowerCase(Locale.ROOT);
        var body = new String(context.body(), java.nio.charset.StandardCharsets.UTF_8);

        if (contentType.startsWith("application/grpc")) {
            return new Models.Classification(Models.Protocol.GRPC, true, 0.99, "gRPC media type");
        }
        if (contentType.startsWith("application/graphql")
            || path.endsWith("/graphql") && body.contains("\"query\"")) {
            return new Models.Classification(Models.Protocol.GRAPHQL, true, 0.97, "GraphQL request");
        }
        if (contentType.startsWith("application/soap+xml")
            || contentType.startsWith("text/xml") && !context.header("soapaction").isBlank()) {
            return new Models.Classification(Models.Protocol.XML_SOAP, true, 0.97, "SOAP envelope");
        }
        if (accept.contains("text/event-stream")) {
            return new Models.Classification(Models.Protocol.EVENT_STREAM, true, 0.85, "SSE negotiation");
        }
        if (isJson(contentType)) {
            return new Models.Classification(Models.Protocol.REST_JSON, true, 0.96, "JSON media type");
        }
        if (contentType.startsWith("application/x-www-form-urlencoded")) {
            return new Models.Classification(Models.Protocol.REST_FORM, true, 0.94, "form media type");
        }
        if (contentType.startsWith("text/html") || contentType.startsWith("image/")) {
            return new Models.Classification(Models.Protocol.UNKNOWN, false, 0.05, "non-API media type");
        }
        if (path.startsWith("/api/") || path.matches(".*/v[0-9]+/.*")) {
            return new Models.Classification(Models.Protocol.REST_JSON, true, 0.75, "API path convention");
        }
        if (!context.header("authorization").isBlank() || !context.header("x-api-key").isBlank()) {
            return new Models.Classification(Models.Protocol.REST_JSON, true, 0.65, "API credential");
        }
        if (path.matches("/[^/]+/[0-9]+")) {
            return new Models.Classification(Models.Protocol.REST_JSON, true, 0.45, "object path convention");
        }
        return new Models.Classification(Models.Protocol.UNKNOWN, false, 0.1, "insufficient API evidence");
    }

    private boolean isJson(String contentType) {
        return contentType.startsWith("application/json")
            || contentType.startsWith("application/ld+json")
            || contentType.matches("^application/[a-z0-9._-]+\\+json(?:;.*)?$");
    }
}
