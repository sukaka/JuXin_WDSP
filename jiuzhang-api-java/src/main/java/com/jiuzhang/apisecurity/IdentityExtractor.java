package com.jiuzhang.apisecurity;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class IdentityExtractor {
    private final String salt;
    private final String jwtHmacSecret;

    public IdentityExtractor(String salt) {
        this(salt, null);
    }

    public IdentityExtractor(String salt, String jwtHmacSecret) {
        this.salt = salt;
        this.jwtHmacSecret = jwtHmacSecret;
    }

    public Result extract(Models.RequestContext context) {
        var findings = new ArrayList<Models.Finding>();
        var apiKey = context.header("x-api-key");
        if (!apiKey.isBlank()) {
            if (apiKey.length() < 12) findings.add(weakCredential("api_key"));
            return new Result(identity("api_key", apiKey, false, "", ""), List.copyOf(findings));
        }

        var authorization = context.header("authorization").strip();
        if (!authorization.isEmpty()) {
            if (!authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
                var identity = identity("authorization", authorization, false, "", "");
                findings.add(Models.Finding.of(
                    "auth.unsupported_scheme", "authentication",
                    Models.Severity.LOW, 5, Models.Action.OBSERVE
                ));
                return new Result(identity, List.copyOf(findings));
            }
            var token = authorization.substring(7).strip();
            if (token.isEmpty()) {
                findings.add(Models.Finding.of(
                    "auth.empty_bearer", "authentication",
                    Models.Severity.MEDIUM, 10, Models.Action.OBSERVE
                ));
                return new Result(Models.Identity.anonymous(), List.copyOf(findings));
            }
            if (token.length() < 12) findings.add(weakCredential("bearer"));
            if (token.chars().filter(character -> character == '.').count() == 2) {
                var jwt = inspectJwt(token);
                findings.addAll(jwt.findings());
                return new Result(jwt.identity(), List.copyOf(findings));
            }
            return new Result(identity("bearer", token, false, "", ""), List.copyOf(findings));
        }

        var session = cookie(context.header("cookie"), "session");
        if (session.isBlank()) session = cookie(context.header("cookie"), "SESSION");
        if (!session.isBlank()) {
            return new Result(identity("cookie_session", session, false, "", ""), List.of());
        }
        return new Result(Models.Identity.anonymous(), List.of());
    }

    private JwtResult inspectJwt(String token) {
        var findings = new ArrayList<Models.Finding>();
        var identity = identity("jwt", token, false, "", "");
        try {
            var pieces = token.split("\\.", -1);
            if (pieces.length != 3 || pieces[2].isEmpty()) {
                throw new IllegalArgumentException("JWT must contain three non-empty segments");
            }
            if (token.length() > 16_384) throw new IllegalArgumentException("JWT is too long");
            var header = decodeJson(pieces[0]);
            var payload = decodeJson(pieces[1]);
            var algorithm = header.get("alg");
            if (!(algorithm instanceof String algorithmName)) {
                throw new IllegalArgumentException("JWT algorithm is missing");
            }
            if (algorithmName.equalsIgnoreCase("none")) {
                findings.add(signal("auth.jwt_alg_none", Models.Severity.HIGH, 25));
                return new JwtResult(identity, findings);
            }
            if (header.get("kid") instanceof String keyId
                && (keyId.contains("..") || keyId.contains("/") || keyId.contains("\\"))) {
                findings.add(signal("auth.jwt_kid_traversal", Models.Severity.HIGH, 20));
            }
            if (!isTimeValid(payload, "exp", true)) {
                findings.add(signal("auth.jwt_expired", Models.Severity.HIGH, 20));
            }
            if (!isTimeValid(payload, "nbf", false)) {
                findings.add(signal("auth.jwt_not_yet_valid", Models.Severity.MEDIUM, 15));
            }

            var verified = false;
            if (jwtHmacSecret != null && !jwtHmacSecret.isBlank()) {
                if (!algorithmName.equals("HS256")) {
                    findings.add(signal("auth.jwt_unsupported_algorithm", Models.Severity.MEDIUM, 10));
                } else if (verifyHs256(pieces)) {
                    verified = true;
                } else {
                    findings.add(signal("auth.jwt_bad_signature", Models.Severity.HIGH, 30));
                }
            } else {
                findings.add(Models.Finding.of(
                    "auth.jwt_unverified", "authentication",
                    Models.Severity.INFO, 0, Models.Action.OBSERVE
                ));
            }
            if (verified) {
                var subject = payload.get("sub") instanceof String value ? value : "";
                var role = payload.get("role") instanceof String value ? value : "";
                identity = new Models.Identity(
                    "jwt", Fingerprints.hmac(salt, token), true, subject, role
                );
            }
        } catch (IllegalArgumentException error) {
            findings.add(Models.Finding.of(
                "auth.jwt_malformed", "authentication",
                Models.Severity.MEDIUM, 15, Models.Action.OBSERVE
            ).withEvidence("structure", "invalid"));
        }
        return new JwtResult(identity, findings);
    }

    private Map<String, Object> decodeJson(String segment) {
        var decoded = Base64.getUrlDecoder().decode(segment);
        return Json.parseObject(new String(decoded, StandardCharsets.UTF_8));
    }

    private boolean isTimeValid(Map<String, Object> payload, String field, boolean expiration) {
        if (!(payload.get(field) instanceof Number number)) return true;
        var timestamp = new BigDecimal(number.toString()).longValue();
        var now = Instant.now().getEpochSecond();
        return expiration ? now < timestamp : now >= timestamp;
    }

    private boolean verifyHs256(String[] pieces) {
        try {
            var mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(
                jwtHmacSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"
            ));
            var expected = mac.doFinal((pieces[0] + "." + pieces[1]).getBytes(StandardCharsets.UTF_8));
            var supplied = Base64.getUrlDecoder().decode(pieces[2]);
            return Fingerprints.constantTimeEquals(expected, supplied);
        } catch (java.security.GeneralSecurityException | IllegalArgumentException error) {
            return false;
        }
    }

    private Models.Identity identity(
        String kind,
        String credential,
        boolean verified,
        String subject,
        String role
    ) {
        return new Models.Identity(
            kind, Fingerprints.hmac(salt, kind + ":" + credential), verified, subject, role
        );
    }

    private Models.Finding weakCredential(String kind) {
        return Models.Finding.of(
            "auth.weak_credential", "authentication",
            Models.Severity.LOW, 5, Models.Action.OBSERVE
        ).withEvidence("kind", kind);
    }

    private Models.Finding signal(String rule, Models.Severity severity, int score) {
        return new Models.Finding(rule, "authentication", severity, score, Models.Action.OBSERVE, Map.of());
    }

    private String cookie(String header, String name) {
        if (header.length() > 8192) return "";
        for (String entry : header.split(";")) {
            var pair = entry.trim().split("=", 2);
            if (pair.length == 2 && pair[0].equals(name)) return pair[1];
        }
        return "";
    }

    public record Result(Models.Identity identity, List<Models.Finding> findings) {
        public Result { findings = List.copyOf(findings); }
    }

    private record JwtResult(Models.Identity identity, List<Models.Finding> findings) {
        private JwtResult { findings = List.copyOf(findings); }
    }
}
