package com.jiuzhang.apisecurity;

import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public final class Models {
    private Models() {
    }

    public enum ProtectionMode { OFF, OBSERVE, PROTECT }
    public enum Action { ALLOW, OBSERVE, BLOCK, RATE_LIMIT, MASK_RESPONSE }
    public enum Severity { INFO, LOW, MEDIUM, HIGH, CRITICAL }
    public enum ValueType { STRING, NUMBER, BOOLEAN, NULL, ARRAY, OBJECT }
    public enum Protocol {
        REST_JSON, REST_FORM, GRAPHQL, XML_SOAP, GRPC, EVENT_STREAM, UNKNOWN
    }
    public enum ParameterLocation { PATH, QUERY, HEADER, BODY }

    public record Classification(
        Protocol protocol,
        boolean api,
        double confidence,
        String reason
    ) {
        public Classification {
            if (confidence < 0 || confidence > 1 || Double.isNaN(confidence)) {
                throw new IllegalArgumentException("confidence must be between zero and one");
            }
        }
    }

    public record Parameter(
        ParameterLocation location,
        String path,
        Object value,
        ValueType type
    ) {
        public Parameter {
            if (path == null || path.isBlank()) {
                throw new IllegalArgumentException("parameter path cannot be blank");
            }
        }
    }

    public record Identity(
        String credentialKind,
        String fingerprint,
        boolean verified,
        String subject,
        String role
    ) {
        public static Identity anonymous() {
            return new Identity("anonymous", "", false, "", "");
        }

        public boolean isAnonymous() {
            return fingerprint == null || fingerprint.isBlank();
        }
    }

    public record Finding(
        String ruleId,
        String detector,
        Severity severity,
        int score,
        Action proposedAction,
        Map<String, String> evidence
    ) {
        public Finding {
            if (ruleId == null || ruleId.isBlank()) {
                throw new IllegalArgumentException("finding rule ID is required");
            }
            evidence = Collections.unmodifiableMap(new LinkedHashMap<>(evidence));
        }

        public static Finding of(
            String ruleId,
            String detector,
            Severity severity,
            int score,
            Action action
        ) {
            return new Finding(ruleId, detector, severity, score, action, Map.of());
        }

        public Finding withEvidence(String key, String value) {
            var updated = new LinkedHashMap<>(evidence);
            updated.put(key, value);
            return new Finding(ruleId, detector, severity, score, proposedAction, updated);
        }
    }

    public static final class RequestContext {
        private final UUID requestId;
        private final Instant startedAt;
        private final String method;
        private final URI requestUri;
        private final String clientAddress;
        private final Map<String, List<String>> headers;
        private final byte[] body;
        private final List<Finding> findings = new ArrayList<>();
        private Classification classification = new Classification(
            Protocol.UNKNOWN, false, 0, "not classified"
        );
        private Identity identity = Identity.anonymous();
        private List<Parameter> parameters = List.of();
        private String normalizedPath = "/";
        private int responseStatus;
        private Action finalAction = Action.ALLOW;

        public RequestContext(
            UUID requestId,
            String method,
            URI requestUri,
            String clientAddress,
            Map<String, List<String>> headers,
            byte[] body
        ) {
            this.requestId = requestId;
            this.startedAt = Instant.now();
            this.method = method;
            this.requestUri = requestUri;
            this.clientAddress = clientAddress;
            this.headers = Collections.unmodifiableMap(new LinkedHashMap<>(headers));
            this.body = body.clone();
        }

        public UUID requestId() { return requestId; }
        public Instant startedAt() { return startedAt; }
        public String method() { return method; }
        public URI requestUri() { return requestUri; }
        public String clientAddress() { return clientAddress; }
        public Map<String, List<String>> headers() { return headers; }
        public byte[] body() { return body.clone(); }
        public Classification classification() { return classification; }
        public Identity identity() { return identity; }
        public List<Parameter> parameters() { return parameters; }
        public String normalizedPath() { return normalizedPath; }
        public int responseStatus() { return responseStatus; }
        public Action finalAction() { return finalAction; }
        public long elapsedMillis() { return Instant.now().toEpochMilli() - startedAt.toEpochMilli(); }

        public void classification(Classification value) { classification = value; }
        public void identity(Identity value) { identity = value; }
        public void parameters(List<Parameter> value) { parameters = List.copyOf(value); }
        public void normalizedPath(String value) { normalizedPath = value; }
        public void responseStatus(int value) { responseStatus = value; }
        public void finalAction(Action value) { finalAction = value; }

        public String endpointKey() {
            return method + " " + normalizedPath;
        }

        public void add(Finding finding) {
            findings.add(finding);
        }

        public void addAll(List<Finding> additions) {
            findings.addAll(additions);
        }

        public List<Finding> findings() {
            return Collections.unmodifiableList(findings);
        }

        public int riskScore() {
            return findings.stream().mapToInt(Finding::score).sum();
        }

        public Severity riskLevel() {
            int score = riskScore();
            if (score >= 80) return Severity.CRITICAL;
            if (score >= 50) return Severity.HIGH;
            if (score >= 25) return Severity.MEDIUM;
            if (score > 0) return Severity.LOW;
            return Severity.INFO;
        }

        public String header(String name) {
            return headers.entrySet().stream()
                .filter(entry -> entry.getKey().equalsIgnoreCase(name))
                .flatMap(entry -> entry.getValue().stream())
                .findFirst()
                .orElse("");
        }
    }

    public record ApiEvent(
        String eventId,
        String requestId,
        Instant timestamp,
        String endpoint,
        String method,
        String path,
        String client,
        String identityFingerprint,
        String protocol,
        int responseStatus,
        long latencyMillis,
        Action action,
        int riskScore,
        Severity riskLevel,
        List<Finding> findings
    ) {
        public ApiEvent {
            findings = List.copyOf(findings);
        }
    }
}
