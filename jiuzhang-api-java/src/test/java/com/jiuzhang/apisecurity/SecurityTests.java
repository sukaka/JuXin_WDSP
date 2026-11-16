package com.jiuzhang.apisecurity;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

final class SecurityTests {
    private static final String SALT = "security-tests-salt-with-at-least-32-bytes";
    private static final String JWT_SECRET = "jwt-test-secret-not-for-production-use";

    private SecurityTests() {
    }

    static void run() {
        TestSupport.test("identity fingerprints and weak credentials", SecurityTests::identityFingerprints);
        TestSupport.test("jwt valid signature and trusted subject", SecurityTests::validJwt);
        TestSupport.test("jwt malformed expired and forged", SecurityTests::invalidJwt);
        TestSupport.test("sensitive query and body signals", SecurityTests::sensitiveData);
        TestSupport.test("authorization object and role baselines", SecurityTests::authorization);
        TestSupport.test("behavior limits and object enumeration", SecurityTests::behavior);
        TestSupport.test("unified decision precedence", SecurityTests::decision);
        TestSupport.test("response sensitive masking", SecurityTests::responseMasking);
        TestSupport.test("response malformed JSON and error signatures", SecurityTests::responseSignals);
    }

    private static void identityFingerprints() {
        var extractor = new IdentityExtractor(SALT);
        var context = context("GET", "/api/items/1", Map.of("x-api-key", List.of("short")), "");
        var result = extractor.extract(context);
        TestSupport.equal("api_key", result.identity().credentialKind(), "credential type");
        TestSupport.check(!result.identity().isAnonymous(), "credential identity exists");
        TestSupport.check(!result.identity().fingerprint().contains("short"), "no raw credential");
        TestSupport.check(result.findings().stream()
            .anyMatch(item -> item.ruleId().equals("auth.weak_credential")), "weak credential signal");
        TestSupport.check(extractor.extract(context("GET", "/", Map.of(), "")).identity().isAnonymous(),
            "anonymous request");
    }

    private static void validJwt() throws Exception {
        var token = jwt("alice", "admin", Instant.now().plusSeconds(300).getEpochSecond(), JWT_SECRET);
        var extractor = new IdentityExtractor(SALT, JWT_SECRET);
        var result = extractor.extract(context("GET", "/", Map.of(
            "authorization", List.of("Bearer " + token)
        ), ""));
        TestSupport.check(result.identity().verified(), "valid signature");
        TestSupport.equal("alice", result.identity().subject(), "verified subject");
        TestSupport.equal("admin", result.identity().role(), "verified role");
        TestSupport.check(result.findings().isEmpty(), "no JWT warnings");
    }

    private static void invalidJwt() throws Exception {
        var extractor = new IdentityExtractor(SALT, JWT_SECRET);
        var expired = jwt("alice", "admin", 1, JWT_SECRET);
        var expiredResult = extractor.extract(context("GET", "/", Map.of(
            "authorization", List.of("Bearer " + expired)
        ), ""));
        TestSupport.check(expiredResult.findings().stream()
            .anyMatch(item -> item.ruleId().equals("auth.jwt_expired")), "expired JWT");

        var forged = jwt("bob", "admin", Instant.now().plusSeconds(60).getEpochSecond(), "wrong-secret");
        var forgedResult = extractor.extract(context("GET", "/", Map.of(
            "authorization", List.of("Bearer " + forged)
        ), ""));
        TestSupport.check(!forgedResult.identity().verified(), "forged JWT is untrusted");
        TestSupport.equal("", forgedResult.identity().subject(), "untrusted subject is discarded");
        TestSupport.check(forgedResult.findings().stream()
            .anyMatch(item -> item.ruleId().equals("auth.jwt_bad_signature")), "bad signature signal");

        var none = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"none\"}".getBytes())
            + "." + Base64.getUrlEncoder().withoutPadding().encodeToString("{}".getBytes()) + ".signature";
        var noneResult = extractor.extract(context("GET", "/", Map.of(
            "authorization", List.of("Bearer " + none)
        ), ""));
        TestSupport.check(noneResult.findings().stream()
            .anyMatch(item -> item.ruleId().equals("auth.jwt_alg_none")), "alg none signal");
    }

    private static void sensitiveData() {
        var detector = new SensitiveDataDetector();
        var query = new Models.Parameter(
            Models.ParameterLocation.QUERY, "access_token", "secret-value", Models.ValueType.STRING
        );
        var queryFinding = detector.inspect(List.of(query)).get(0);
        TestSupport.equal(Models.Action.BLOCK, queryFinding.proposedAction(), "query credential blocks");
        TestSupport.check(!queryFinding.evidence().toString().contains("secret-value"),
            "raw value never enters evidence");
        var body = new Models.Parameter(
            Models.ParameterLocation.BODY, "profile.phone", "13800138000", Models.ValueType.STRING
        );
        var bodyFindings = detector.inspect(List.of(body));
        TestSupport.equal(Models.Action.OBSERVE, bodyFindings.get(0).proposedAction(),
            "body phone observes");
        TestSupport.check(bodyFindings.stream()
            .anyMatch(finding -> finding.evidence().get("match").equals("phone_cn")),
            "value rule kind");
    }

    private static void authorization() throws Exception {
        var directory = Files.createTempDirectory("authz-test");
        try {
            var path = directory.resolve("authz.json");
            Files.writeString(path, """
                {"role_baselines":{"GET /users/{id}":["admin"]},
                 "ownership":[{"endpoint":"GET /users/{id}","object":"10001","subject":"alice"}]}
                """);
            var policy = AuthorizationPolicy.load(path, SALT);
            var anonymous = context("GET", "/users/10001", Map.of(), "");
            anonymous.normalizedPath("/users/{id}");
            TestSupport.check(policy.evaluate(anonymous, new PathNormalizer().normalize("/users/10001"))
                .stream().anyMatch(item -> item.ruleId().equals("authz.anonymous_object_access")),
                "anonymous object access");

            var mismatch = context("GET", "/users/10001", Map.of(), "");
            mismatch.normalizedPath("/users/{id}");
            mismatch.identity(new Models.Identity("jwt", "identity-hash", true, "bob", "user"));
            var findings = policy.evaluate(mismatch, new PathNormalizer().normalize("/users/10001"));
            TestSupport.check(findings.stream()
                .anyMatch(item -> item.ruleId().equals("authz.bola_owner_mismatch")), "owner mismatch");
            TestSupport.check(findings.stream()
                .anyMatch(item -> item.ruleId().equals("authz.bfla_role_mismatch")), "role mismatch");
            TestSupport.check(!findings.toString().contains("10001"), "raw object is not logged");
        } finally {
            Files.deleteIfExists(directory.resolve("authz.json"));
            Files.deleteIfExists(directory);
        }
    }

    private static void behavior() {
        var tracker = new BehaviorTracker(2, Duration.ofMinutes(1), 2, SALT);
        var context = context("GET", "/api/items/1", Map.of(), "");
        TestSupport.equal(null, tracker.acquire(context), "first request");
        TestSupport.equal(null, tracker.acquire(context), "second request");
        TestSupport.equal(Models.Action.RATE_LIMIT, tracker.acquire(context).proposedAction(),
            "third request limited");

        var identityContext = context("GET", "/users/1", Map.of(), "");
        identityContext.normalizedPath("/users/{id}");
        identityContext.identity(new Models.Identity("api_key", "stable-identity", false, "", ""));
        Models.Finding enumeration = null;
        for (int id = 1; id <= 21; id++) {
            enumeration = tracker.observeObjects(
                identityContext, new PathNormalizer().normalize("/users/" + id)
            );
        }
        TestSupport.equal("behavior.object_enumeration", enumeration.ruleId(), "enumeration threshold");
    }

    private static void decision() {
        var engine = new DecisionEngine();
        var block = Models.Finding.of(
            "schema.type", "api_schema", Models.Severity.HIGH, 40, Models.Action.BLOCK
        );
        var rate = Models.Finding.of(
            "behavior.rate", "behavior", Models.Severity.HIGH, 30, Models.Action.RATE_LIMIT
        );
        TestSupport.equal(Models.Action.BLOCK,
            engine.request(Models.ProtectionMode.PROTECT, List.of(block)), "protect block");
        TestSupport.equal(Models.Action.OBSERVE,
            engine.request(Models.ProtectionMode.OBSERVE, List.of(block)), "observe downgrade");
        TestSupport.equal(Models.Action.ALLOW,
            engine.request(Models.ProtectionMode.OFF, List.of(rate)), "off bypasses decisions");
        TestSupport.equal(Models.Action.RATE_LIMIT,
            engine.request(Models.ProtectionMode.PROTECT, List.of(block, rate)), "rate precedence");
        TestSupport.equal(Models.Action.MASK_RESPONSE,
            engine.response(Models.ProtectionMode.PROTECT, List.of(), true), "response masking");
    }

    private static void responseMasking() {
        var guard = new ResponseGuard(Set.of("password", "token"), new SensitiveDataDetector());
        var body = "{\"profile\":{\"password\":\"abc123\",\"token\":\"xyz\"},\"ok\":true}"
            .getBytes(StandardCharsets.UTF_8);
        var plan = guard.plan(200, "application/json", body);
        TestSupport.check(plan.hasTransformations(), "mask plan exists");
        var transformed = new String(guard.apply(plan), StandardCharsets.UTF_8);
        TestSupport.check(!transformed.contains("abc123") && !transformed.contains("xyz"),
            "raw sensitive response removed");
        TestSupport.check(transformed.contains("***"), "mask marker present");
        TestSupport.check(transformed.contains("\"ok\":true"), "non-sensitive field retained");
    }

    private static void responseSignals() {
        var guard = new ResponseGuard(Set.of(), new SensitiveDataDetector());
        var invalid = guard.plan(200, "application/json", "{".getBytes());
        TestSupport.check(invalid.findings().stream()
            .anyMatch(item -> item.ruleId().equals("response.invalid_json")), "invalid response JSON");
        var failure = guard.plan(500, "text/plain", "Exception in thread main".getBytes());
        TestSupport.check(failure.findings().stream()
            .anyMatch(item -> item.ruleId().equals("response.error_signature")), "error signature");
    }

    private static Models.RequestContext context(
        String method,
        String path,
        Map<String, List<String>> headers,
        String body
    ) {
        return new Models.RequestContext(
            UUID.randomUUID(), method, URI.create(path), "127.0.0.1", headers,
            body.getBytes(StandardCharsets.UTF_8)
        );
    }

    private static String jwt(String subject, String role, long expires, String secret) throws Exception {
        var encoder = Base64.getUrlEncoder().withoutPadding();
        var header = encoder.encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes());
        var payload = encoder.encodeToString(Json.stringify(Map.of(
            "sub", subject, "role", role, "exp", expires
        )).getBytes());
        var mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        var signature = mac.doFinal((header + "." + payload).getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + "." + encoder.encodeToString(signature);
    }
}
