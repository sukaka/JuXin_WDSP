package com.jiuzhang.apisecurity;

import java.io.IOException;
import java.math.BigDecimal;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class SchemaRegistry {
    private static final int MAX_ENDPOINTS = 10_000;
    private static final int MAX_FIELDS_PER_ENDPOINT = 256;
    private final Map<String, Map<String, FieldRule>> formalModels;
    private final Map<String, Candidate> candidates = new LinkedHashMap<>();

    private SchemaRegistry(Map<String, Map<String, FieldRule>> formalModels) {
        this.formalModels = formalModels;
    }

    public static SchemaRegistry empty() {
        return new SchemaRegistry(Map.of());
    }

    public static SchemaRegistry load(Path path) throws IOException {
        if (!Files.exists(path)) return empty();
        if (Files.size(path) > 4 * 1024 * 1024) {
            throw new IllegalArgumentException("schema registry file is too large");
        }
        var root = Json.parseObject(Files.readString(path));
        if (!(root.get("models") instanceof Map<?, ?> models)) {
            throw new IllegalArgumentException("schema registry requires a models object");
        }
        var result = new LinkedHashMap<String, Map<String, FieldRule>>();
        for (var model : models.entrySet()) {
            if (!(model.getKey() instanceof String endpoint)
                || !(model.getValue() instanceof Map<?, ?> modelBody)) {
                throw new IllegalArgumentException("invalid schema model entry");
            }
            if (!(modelBody.get("fields") instanceof Map<?, ?> fields)) {
                throw new IllegalArgumentException("schema model requires fields: " + endpoint);
            }
            var rules = new LinkedHashMap<String, FieldRule>();
            for (var field : fields.entrySet()) {
                if (!(field.getKey() instanceof String name)
                    || !(field.getValue() instanceof Map<?, ?> definition)) {
                    throw new IllegalArgumentException("invalid schema field");
                }
                rules.put(name, fieldRule(name, definition));
            }
            result.put(endpoint, Collections.unmodifiableMap(rules));
        }
        return new SchemaRegistry(Collections.unmodifiableMap(result));
    }

    private static FieldRule fieldRule(String name, Map<?, ?> definition) {
        var typeName = definition.get("type");
        if (!(typeName instanceof String text)) {
            throw new IllegalArgumentException("schema field type is required: " + name);
        }
        Models.ValueType type;
        try {
            type = Models.ValueType.valueOf(text);
        } catch (IllegalArgumentException error) {
            throw new IllegalArgumentException("unknown schema type: " + text);
        }
        var required = definition.get("required") instanceof Boolean value && value;
        var minLength = integer(definition.get("min_length"));
        var maxLength = integer(definition.get("max_length"));
        var minimum = decimal(definition.get("minimum"));
        var maximum = decimal(definition.get("maximum"));
        if (minLength != null && maxLength != null && minLength > maxLength) {
            throw new IllegalArgumentException("inverted length constraints: " + name);
        }
        if (minimum != null && maximum != null && minimum.compareTo(maximum) > 0) {
            throw new IllegalArgumentException("inverted numeric constraints: " + name);
        }
        var enumValues = Set.<String>of();
        if (definition.get("enum") instanceof List<?> values) {
            if (values.size() > 256) throw new IllegalArgumentException("enum is too large");
            var entries = new java.util.LinkedHashSet<String>();
            for (Object value : values) entries.add(String.valueOf(value));
            enumValues = Set.copyOf(entries);
        }
        return new FieldRule(name, type, required, minLength, maxLength, minimum, maximum, enumValues);
    }

    private static Integer integer(Object value) {
        if (value == null) return null;
        if (value instanceof Number number) return number.intValue();
        throw new IllegalArgumentException("expected integer schema constraint");
    }

    private static BigDecimal decimal(Object value) {
        if (value == null) return null;
        if (value instanceof Number number) return new BigDecimal(number.toString());
        throw new IllegalArgumentException("expected numeric schema constraint");
    }

    public List<Models.Finding> validate(String endpoint, List<Models.Parameter> parameters) {
        var rules = formalModels.get(endpoint);
        if (rules == null) return List.of();
        var findings = new ArrayList<Models.Finding>();
        var available = new LinkedHashMap<String, List<Models.Parameter>>();
        for (var parameter : parameters) {
            var key = parameterKey(parameter.location(), parameter.path());
            available.computeIfAbsent(key, ignored -> new ArrayList<>()).add(parameter);
        }
        for (var rule : rules.values()) {
            var values = available.get(rule.key());
            if (values == null || values.isEmpty()) {
                if (rule.required()) {
                    findings.add(finding(
                        "schema.required", Models.Severity.HIGH, Models.Action.BLOCK, rule.key()
                    ));
                }
                continue;
            }
            for (var parameter : values) {
                validateValue(rule, parameter, findings);
            }
        }
        for (var parameter : parameters) {
            if (parameter.location() != Models.ParameterLocation.BODY) continue;
            var key = parameterKey(parameter.location(), parameter.path());
            if (!rules.containsKey(key) && hasBodyRules(rules)) {
                findings.add(finding(
                    "schema.undefined_field", Models.Severity.MEDIUM, Models.Action.OBSERVE, key
                ));
            }
        }
        return List.copyOf(findings);
    }

    private void validateValue(
        FieldRule rule,
        Models.Parameter parameter,
        List<Models.Finding> findings
    ) {
        if (parameter.type() != rule.type()) {
            findings.add(finding(
                "schema.type_mismatch", Models.Severity.HIGH, Models.Action.BLOCK, rule.key()
            ).withEvidence("expected", rule.type().name())
                .withEvidence("actual", parameter.type().name()));
            return;
        }
        if (parameter.value() instanceof String text) {
            if (rule.minLength() != null && text.length() < rule.minLength()) {
                findings.add(finding(
                    "schema.min_length", Models.Severity.HIGH, Models.Action.BLOCK, rule.key()
                ));
            }
            if (rule.maxLength() != null && text.length() > rule.maxLength()) {
                findings.add(finding(
                    "schema.max_length", Models.Severity.HIGH, Models.Action.BLOCK, rule.key()
                ));
            }
            if (!rule.enumValues().isEmpty() && !rule.enumValues().contains(text)) {
                findings.add(finding(
                    "schema.enum", Models.Severity.HIGH, Models.Action.BLOCK, rule.key()
                ));
            }
        }
        if (parameter.value() instanceof Number number) {
            var value = new BigDecimal(number.toString());
            if (rule.minimum() != null && value.compareTo(rule.minimum()) < 0) {
                findings.add(finding(
                    "schema.minimum", Models.Severity.HIGH, Models.Action.BLOCK, rule.key()
                ));
            }
            if (rule.maximum() != null && value.compareTo(rule.maximum()) > 0) {
                findings.add(finding(
                    "schema.maximum", Models.Severity.HIGH, Models.Action.BLOCK, rule.key()
                ));
            }
        }
    }

    public synchronized void observe(String endpoint, List<Models.Parameter> parameters) {
        var candidate = candidates.computeIfAbsent(endpoint, ignored -> {
            if (candidates.size() >= MAX_ENDPOINTS) return null;
            return new Candidate(Instant.now());
        });
        if (candidate == null) return;
        candidate.observe(parameters);
    }

    public synchronized Map<String, Object> candidate(String endpoint) {
        var candidate = candidates.get(endpoint);
        return candidate == null ? Map.of() : candidate.toJson();
    }

    public synchronized List<Map<String, Object>> candidates() {
        return candidates.entrySet().stream()
            .<Map<String, Object>>map(entry -> {
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("endpoint", entry.getKey());
                item.putAll(entry.getValue().toJson());
                return item;
            })
            .toList();
    }

    public List<String> formalEndpoints() {
        return List.copyOf(formalModels.keySet());
    }

    private boolean hasBodyRules(Map<String, FieldRule> rules) {
        return rules.keySet().stream().anyMatch(key -> key.startsWith("body:"));
    }

    private String parameterKey(Models.ParameterLocation location, String path) {
        return switch (location) {
            case BODY -> "body:" + path;
            case QUERY -> "query:" + path;
            case HEADER -> "header:" + path;
            case PATH -> "path:" + path;
        };
    }

    private Models.Finding finding(
        String rule,
        Models.Severity severity,
        Models.Action action,
        String field
    ) {
        return Models.Finding.of(rule, "api_schema", severity, 40, action)
            .withEvidence("field", field);
    }

    private record FieldRule(
        String key,
        Models.ValueType type,
        boolean required,
        Integer minLength,
        Integer maxLength,
        BigDecimal minimum,
        BigDecimal maximum,
        Set<String> enumValues
    ) {
    }

    private static final class Candidate {
        private final Instant firstSeen;
        private Instant lastSeen;
        private long requests;
        private final Map<String, FieldStats> fields = new LinkedHashMap<>();

        private Candidate(Instant firstSeen) {
            this.firstSeen = firstSeen;
            this.lastSeen = firstSeen;
        }

        private void observe(List<Models.Parameter> parameters) {
            requests++;
            lastSeen = Instant.now();
            for (var parameter : parameters) {
                if (parameter.location() != Models.ParameterLocation.BODY
                    && parameter.location() != Models.ParameterLocation.QUERY) continue;
                var key = parameter.location().name().toLowerCase() + ":" + parameter.path();
                if (!fields.containsKey(key) && fields.size() >= MAX_FIELDS_PER_ENDPOINT) continue;
                fields.computeIfAbsent(key, ignored -> new FieldStats()).observe(parameter);
            }
        }

        private Map<String, Object> toJson() {
            var result = new LinkedHashMap<String, Object>();
            result.put("first_seen", firstSeen.toString());
            result.put("last_seen", lastSeen.toString());
            result.put("sample_count", requests);
            var fieldJson = new LinkedHashMap<String, Object>();
            fields.forEach((key, stats) -> fieldJson.put(key, stats.toJson(requests)));
            result.put("fields", fieldJson);
            result.put("status", "CANDIDATE_ONLY");
            return result;
        }
    }

    private static final class FieldStats {
        private long present;
        private final EnumMap<Models.ValueType, Long> types = new EnumMap<>(Models.ValueType.class);
        private Integer minLength;
        private Integer maxLength;
        private BigDecimal minimum;
        private BigDecimal maximum;

        private void observe(Models.Parameter parameter) {
            present++;
            types.merge(parameter.type(), 1L, Long::sum);
            if (parameter.value() instanceof String text) {
                minLength = minLength == null ? text.length() : Math.min(minLength, text.length());
                maxLength = maxLength == null ? text.length() : Math.max(maxLength, text.length());
            }
            if (parameter.value() instanceof Number number) {
                var value = new BigDecimal(number.toString());
                minimum = minimum == null ? value : minimum.min(value);
                maximum = maximum == null ? value : maximum.max(value);
            }
        }

        private Map<String, Object> toJson(long totalRequests) {
            var result = new LinkedHashMap<String, Object>();
            result.put("present", present);
            result.put("presence_rate", totalRequests == 0 ? 0 : (double) present / totalRequests);
            var observedTypes = new LinkedHashMap<String, Object>();
            types.forEach((type, count) -> observedTypes.put(type.name(), count));
            result.put("types", observedTypes);
            if (minLength != null) result.put("min_length", minLength);
            if (maxLength != null) result.put("max_length", maxLength);
            if (minimum != null) result.put("minimum", minimum);
            if (maximum != null) result.put("maximum", maximum);
            return result;
        }
    }
}
