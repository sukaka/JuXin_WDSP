package com.jiuzhang.apisecurity;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class ResponseGuard {
    private final Set<String> maskFields;
    private final SensitiveDataDetector sensitive;

    public ResponseGuard(Set<String> maskFields, SensitiveDataDetector sensitive) {
        this.maskFields = Set.copyOf(maskFields);
        this.sensitive = sensitive;
    }

    public Plan plan(int status, String contentType, byte[] body) {
        var findings = new ArrayList<Models.Finding>();
        if (status >= 500 && containsErrorSignature(body)) {
            findings.add(Models.Finding.of(
                "response.error_signature", "api_response",
                Models.Severity.MEDIUM, 5, Models.Action.OBSERVE
            ));
        }
        if (!isJson(contentType) || body.length == 0) {
            return new Plan(null, List.of(), findings);
        }

        final Object root;
        try {
            root = Json.parse(new String(body, StandardCharsets.UTF_8));
        } catch (IllegalArgumentException error) {
            findings.add(Models.Finding.of(
                "response.invalid_json", "api_response",
                Models.Severity.LOW, 5, Models.Action.OBSERVE
            ));
            return new Plan(null, List.of(), findings);
        }
        var paths = new ArrayList<String>();
        collectSensitivePaths(root, "", paths, 0);
        for (String path : paths) {
            findings.add(Models.Finding.of(
                "response.sensitive_field", "api_response",
                Models.Severity.MEDIUM, 10, Models.Action.OBSERVE
            ).withEvidence("field", path));
        }
        var maskPaths = paths.stream().filter(this::shouldMask).toList();
        return new Plan(root, maskPaths, findings);
    }

    public byte[] apply(Plan plan) {
        if (plan.root == null || plan.paths.isEmpty()) {
            throw new IllegalArgumentException("response plan contains no applicable transformation");
        }
        for (String path : plan.paths) mask(plan.root, path.split("\\."));
        return Json.stringify(plan.root).getBytes(StandardCharsets.UTF_8);
    }

    private void collectSensitivePaths(
        Object value,
        String path,
        List<String> paths,
        int depth
    ) {
        if (depth > 64) throw new IllegalArgumentException("response nesting is too deep");
        if (value instanceof Map<?, ?> object) {
            for (var entry : object.entrySet()) {
                if (!(entry.getKey() instanceof String key)) continue;
                var child = path.isEmpty() ? key : path + "." + key;
                if (sensitive.isSensitiveName(key)) paths.add(child);
                collectSensitivePaths(entry.getValue(), child, paths, depth + 1);
            }
        } else if (value instanceof List<?> list) {
            for (int index = 0; index < list.size(); index++) {
                collectSensitivePaths(list.get(index), path + "[" + index + "]", paths, depth + 1);
            }
        }
    }

    private boolean shouldMask(String path) {
        if (maskFields.contains(path)) return true;
        var leaf = path.substring(path.lastIndexOf('.') + 1);
        return maskFields.stream().anyMatch(field -> field.equalsIgnoreCase(leaf));
    }

    @SuppressWarnings("unchecked")
    private void mask(Object root, String[] segments) {
        Object current = root;
        for (int index = 0; index < segments.length - 1; index++) {
            current = child(current, segments[index]);
            if (current == null) return;
        }
        var leaf = segments[segments.length - 1];
        if (current instanceof Map<?, ?> object && object.containsKey(leaf)) {
            ((Map<String, Object>) object).put(leaf, "***");
        } else if (current instanceof List<?> list && leaf.startsWith("[")) {
            var index = Integer.parseInt(leaf.substring(1, leaf.length() - 1));
            ((List<Object>) list).set(index, "***");
        }
    }

    private Object child(Object current, String segment) {
        if (current instanceof Map<?, ?> object) return object.get(segment);
        if (current instanceof List<?> list && segment.startsWith("[")) {
            var index = Integer.parseInt(segment.substring(1, segment.length() - 1));
            return index < list.size() ? list.get(index) : null;
        }
        return null;
    }

    private boolean containsErrorSignature(byte[] body) {
        var text = new String(body, StandardCharsets.UTF_8).toLowerCase();
        return text.contains("stack trace") || text.contains("exception in thread")
            || text.contains("traceback (most recent call last)");
    }

    private boolean isJson(String contentType) {
        var normalized = contentType.toLowerCase();
        return normalized.startsWith("application/json") || normalized.contains("+json");
    }

    public static final class Plan {
        private final Object root;
        private final List<String> paths;
        private final List<Models.Finding> findings;

        private Plan(Object root, List<String> paths, List<Models.Finding> findings) {
            this.root = root;
            this.paths = List.copyOf(paths);
            this.findings = List.copyOf(findings);
        }

        public boolean hasTransformations() {
            return !paths.isEmpty();
        }

        public int transformationCount() {
            return paths.size();
        }

        public List<Models.Finding> findings() {
            return findings;
        }
    }
}
