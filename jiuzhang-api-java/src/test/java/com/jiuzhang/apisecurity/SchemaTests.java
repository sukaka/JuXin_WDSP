package com.jiuzhang.apisecurity;

import java.math.BigDecimal;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

final class SchemaTests {
    private SchemaTests() {
    }

    static void run() {
        TestSupport.test("schema required and type constraints", SchemaTests::requiredAndType);
        TestSupport.test("schema length range and enum constraints", SchemaTests::valueConstraints);
        TestSupport.test("schema unknown fields are observations", SchemaTests::unknownFields);
        TestSupport.test("schema candidate learning stays non-formal", SchemaTests::candidateLearning);
        TestSupport.test("schema malformed formal model rejected", SchemaTests::invalidFormalModel);
    }

    private static void requiredAndType() throws Exception {
        var registry = registry("""
            {"models":{"POST /login":{"fields":{
              "body:username":{"type":"STRING","required":true},
              "body:age":{"type":"NUMBER","required":false}
            }}}}
            """);
        var missing = registry.validate("POST /login", List.of());
        TestSupport.equal("schema.required", missing.get(0).ruleId(), "required field finding");
        var mismatch = registry.validate("POST /login", List.of(
            parameter("username", "alice"), parameter("age", "young")
        ));
        TestSupport.check(mismatch.stream().anyMatch(item -> item.ruleId().equals("schema.type_mismatch")),
            "type mismatch detected");
        TestSupport.equal(Models.Action.BLOCK, mismatch.get(0).proposedAction(), "blocking violation");
    }

    private static void valueConstraints() throws Exception {
        var registry = registry("""
            {"models":{"POST /orders":{"fields":{
              "body:code":{"type":"STRING","min_length":2,"max_length":4,"enum":["AB","XYZ"]},
              "body:amount":{"type":"NUMBER","minimum":1,"maximum":100}
            }}}}
            """);
        var findings = registry.validate("POST /orders", List.of(
            parameter("code", "A"), parameter("amount", new BigDecimal("101"))
        ));
        TestSupport.check(findings.stream().anyMatch(item -> item.ruleId().equals("schema.min_length")),
            "minimum length");
        TestSupport.check(findings.stream().anyMatch(item -> item.ruleId().equals("schema.maximum")),
            "numeric maximum");
        var valid = registry.validate("POST /orders", List.of(
            parameter("code", "AB"), parameter("amount", new BigDecimal("99.5"))
        ));
        TestSupport.check(valid.isEmpty(), "valid values should pass");
    }

    private static void unknownFields() throws Exception {
        var registry = registry("""
            {"models":{"POST /login":{"fields":{
              "body:username":{"type":"STRING","required":true}
            }}}}
            """);
        var findings = registry.validate("POST /login", List.of(
            parameter("username", "alice"), parameter("unexpected", "value")
        ));
        TestSupport.equal(1, findings.size(), "one undefined field");
        TestSupport.equal("schema.undefined_field", findings.get(0).ruleId(), "undefined field rule");
        TestSupport.equal(Models.Action.OBSERVE, findings.get(0).proposedAction(), "observe only");
    }

    private static void candidateLearning() throws Exception {
        var registry = SchemaRegistry.empty();
        registry.observe("POST /login", List.of(
            parameter("username", "alice"), parameter("age", new BigDecimal("20"))
        ));
        registry.observe("POST /login", List.of(parameter("username", "bob")));
        var candidate = registry.candidate("POST /login");
        TestSupport.equal(2L, candidate.get("sample_count"), "candidate request count");
        TestSupport.equal("CANDIDATE_ONLY", candidate.get("status"), "never automatically formal");
        TestSupport.check(registry.formalEndpoints().isEmpty(), "no formal model was created");
        var encoded = Json.stringify(registry.candidates());
        TestSupport.check(encoded.contains("presence_rate"), "candidate is serializable");
        TestSupport.check(!encoded.contains("alice"), "candidate does not contain raw values");
        TestSupport.check(registry.validate("POST /login", List.of()).isEmpty(),
            "candidate does not enforce rules");
    }

    private static void invalidFormalModel() throws Exception {
        var directory = Files.createTempDirectory("bad-schema");
        try {
            var path = directory.resolve("models.json");
            Files.writeString(path, "{\"models\":[]}");
            TestSupport.rejects(IllegalArgumentException.class, () -> SchemaRegistry.load(path));
        } finally {
            Files.deleteIfExists(directory.resolve("models.json"));
            Files.deleteIfExists(directory);
        }
    }

    private static SchemaRegistry registry(String json) throws Exception {
        var directory = Files.createTempDirectory("schema-test");
        var path = directory.resolve("models.json");
        Files.writeString(path, json);
        return SchemaRegistry.load(path);
    }

    private static Models.Parameter parameter(String path, Object value) {
        return new Models.Parameter(Models.ParameterLocation.BODY, path, value, Json.typeOf(value));
    }
}
