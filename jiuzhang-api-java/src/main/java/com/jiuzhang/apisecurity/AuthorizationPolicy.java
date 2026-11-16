package com.jiuzhang.apisecurity;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class AuthorizationPolicy {
    private final Map<String, Set<String>> roleBaselines;
    private final Map<String, String> owners;
    private final String salt;

    private AuthorizationPolicy(
        Map<String, Set<String>> roleBaselines,
        Map<String, String> owners,
        String salt
    ) {
        this.roleBaselines = roleBaselines;
        this.owners = owners;
        this.salt = salt;
    }

    public static AuthorizationPolicy empty(String salt) {
        return new AuthorizationPolicy(Map.of(), Map.of(), salt);
    }

    public static AuthorizationPolicy load(Path path, String salt) throws IOException {
        if (!Files.exists(path)) return empty(salt);
        if (Files.size(path) > 2 * 1024 * 1024) {
            throw new IllegalArgumentException("authorization policy is too large");
        }
        var root = Json.parseObject(Files.readString(path));
        var roles = new LinkedHashMap<String, Set<String>>();
        if (root.get("role_baselines") instanceof Map<?, ?> definitions) {
            for (var entry : definitions.entrySet()) {
                if (!(entry.getKey() instanceof String endpoint)
                    || !(entry.getValue() instanceof List<?> allowed)) {
                    throw new IllegalArgumentException("invalid role baseline");
                }
                var roleSet = new java.util.LinkedHashSet<String>();
                for (Object role : allowed) {
                    if (!(role instanceof String name) || name.isBlank()) {
                        throw new IllegalArgumentException("invalid role name");
                    }
                    roleSet.add(name);
                }
                roles.put(endpoint, Set.copyOf(roleSet));
            }
        }
        var owners = new LinkedHashMap<String, String>();
        if (root.get("ownership") instanceof List<?> definitions) {
            for (Object item : definitions) {
                if (!(item instanceof Map<?, ?> definition)) {
                    throw new IllegalArgumentException("invalid ownership definition");
                }
                var endpoint = text(definition, "endpoint");
                var object = text(definition, "object");
                var subject = text(definition, "subject");
                var objectKey = Fingerprints.hmac(salt, "object:" + object);
                var subjectKey = Fingerprints.hmac(salt, "subject:" + subject);
                owners.put(endpoint + ":" + objectKey, subjectKey);
            }
        }
        return new AuthorizationPolicy(Map.copyOf(roles), Map.copyOf(owners), salt);
    }

    public List<Models.Finding> evaluate(
        Models.RequestContext context,
        PathNormalizer.Result path
    ) {
        var findings = new ArrayList<Models.Finding>();
        var identity = context.identity();
        if (!path.objects().isEmpty() && identity.isAnonymous()) {
            findings.add(signal(
                "authz.anonymous_object_access", "object_access", Models.Severity.MEDIUM, 15
            ));
        }

        var allowedRoles = roleBaselines.get(context.endpointKey());
        if (allowedRoles != null) {
            if (identity.isAnonymous()) {
                findings.add(signal(
                    "authz.bfla_anonymous", "function_access", Models.Severity.HIGH, 30
                ));
            } else if (!identity.verified()) {
                findings.add(signal(
                    "authz.unverified_identity", "function_access", Models.Severity.MEDIUM, 15
                ));
            } else if (!allowedRoles.contains(identity.role())) {
                findings.add(signal(
                    "authz.bfla_role_mismatch", "function_access", Models.Severity.MEDIUM, 15
                ).withEvidence("constraint", "confirmed_role_baseline"));
            }
        }

        if (!identity.verified() || identity.subject().isBlank()) {
            return List.copyOf(findings);
        }
        var subjectKey = Fingerprints.hmac(salt, "subject:" + identity.subject());
        for (var object : path.objects()) {
            var objectKey = Fingerprints.hmac(salt, "object:" + object.rawValue());
            var owner = owners.get(context.endpointKey() + ":" + objectKey);
            if (owner != null && !owner.equals(subjectKey)) {
                findings.add(signal(
                    "authz.bola_owner_mismatch", "object_access", Models.Severity.HIGH, 30
                ).withEvidence("relation", "confirmed_owner_mismatch"));
            }
        }
        return List.copyOf(findings);
    }

    public int roleBaselineCount() {
        return roleBaselines.size();
    }

    public int ownershipCount() {
        return owners.size();
    }

    private Models.Finding signal(
        String rule,
        String detector,
        Models.Severity severity,
        int score
    ) {
        return Models.Finding.of(rule, detector, severity, score, Models.Action.OBSERVE);
    }

    private static String text(Map<?, ?> definition, String key) {
        if (definition.get(key) instanceof String value && !value.isBlank()) return value;
        throw new IllegalArgumentException("authorization field must be non-empty text: " + key);
    }
}
