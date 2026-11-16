package com.jiuzhang.apisecurity;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;

final class JsonTests {
    private JsonTests() {
    }

    static void run() {
        TestSupport.test("json nested round trip", JsonTests::nestedRoundTrip);
        TestSupport.test("json unicode and controls", JsonTests::unicodeAndControls);
        TestSupport.test("json duplicate keys rejected", JsonTests::duplicateKeys);
        TestSupport.test("json malformed documents rejected", JsonTests::malformedDocuments);
        TestSupport.test("json resource limits", JsonTests::resourceLimits);
        TestSupport.test("json flattening keeps arrays bounded", JsonTests::flattening);
        TestSupport.test("json non-finite numbers rejected", JsonTests::nonFiniteNumbers);
    }

    private static void nestedRoundTrip() {
        var source = "{\"user\":{\"name\":\"alice\",\"age\":30},\"tags\":[\"a\",\"b\"],\"ok\":true}";
        var root = Json.parseObject(source);
        var user = (Map<?, ?>) root.get("user");
        TestSupport.equal("alice", user.get("name"), "nested string");
        TestSupport.equal(new BigDecimal("30"), user.get("age"), "nested number");
        TestSupport.equal(source, Json.stringify(root), "stable round trip");
    }

    private static void unicodeAndControls() {
        var source = "{\"text\":\"中文\\n\\u4e16\\u754c\"}";
        var root = Json.parseObject(source);
        TestSupport.equal("中文\n世界", root.get("text"), "unicode decoding");
        var encoded = Json.stringify(root);
        TestSupport.check(encoded.contains("\\n"), "newline must be escaped");
        TestSupport.equal(root, Json.parseObject(encoded), "escaped text round trip");
    }

    private static void duplicateKeys() {
        TestSupport.rejects(IllegalArgumentException.class, () -> Json.parse("{\"a\":1,\"a\":2}"));
        TestSupport.rejects(IllegalArgumentException.class, () -> Json.parse("{\"a\":null,\"a\":null}"));
    }

    private static void malformedDocuments() {
        for (String source : List.of("", "[1,]", "{", "01", "true false", "\"unterminated")) {
            TestSupport.rejects(IllegalArgumentException.class, () -> Json.parse(source));
        }
        TestSupport.rejects(IllegalArgumentException.class, () -> Json.parseObject("[]"));
    }

    private static void resourceLimits() {
        var deep = "[".repeat(65) + "0" + "]".repeat(65);
        TestSupport.rejects(IllegalArgumentException.class, () -> Json.parse(deep));
        var large = "0".repeat(JsonLimit.characters());
        TestSupport.rejects(IllegalArgumentException.class, () -> Json.parse(large));
    }

    private static void flattening() {
        var root = Json.parse("{\"user\":{\"name\":\"alice\"},\"roles\":[\"a\",\"b\"]}");
        var values = Json.flatten(root);
        TestSupport.equal("alice", values.get("user.name"), "nested field");
        TestSupport.check(values.get("roles") instanceof List, "array stays one parameter");
        TestSupport.equal(2, values.size(), "flattened field count");
    }

    private static void nonFiniteNumbers() {
        TestSupport.rejects(IllegalArgumentException.class, () -> Json.stringify(Double.NaN));
        TestSupport.rejects(IllegalArgumentException.class, () -> Json.stringify(Double.POSITIVE_INFINITY));
    }

    private static final class JsonLimit {
        private static int characters() {
            return 1_048_577;
        }
    }
}
