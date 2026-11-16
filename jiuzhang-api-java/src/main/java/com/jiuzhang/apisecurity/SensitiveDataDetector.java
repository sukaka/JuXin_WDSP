package com.jiuzhang.apisecurity;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

public final class SensitiveDataDetector {
    private static final Pattern SENSITIVE_NAME = Pattern.compile(
        "(?:^|_)(?:password|passwd|token|secret|apikey|api_key|authorization|idcard|id_card|bank_card|phone|email)(?:$|_)",
        Pattern.CASE_INSENSITIVE
    );
    private static final List<ValuePattern> VALUE_PATTERNS = List.of(
        new ValuePattern("email", Pattern.compile("[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}", Pattern.CASE_INSENSITIVE)),
        new ValuePattern("phone_cn", Pattern.compile("(?<!\\d)1[3-9]\\d{9}(?!\\d)")),
        new ValuePattern("id_card_cn", Pattern.compile("(?<!\\d)\\d{17}[0-9Xx](?!\\d)")),
        new ValuePattern("bank_card", Pattern.compile("(?<!\\d)\\d{16,19}(?!\\d)"))
    );
    private static final int MAX_EVALUATIONS = 512;

    public List<Models.Finding> inspect(List<Models.Parameter> parameters) {
        var findings = new ArrayList<Models.Finding>();
        int evaluations = 0;
        for (var parameter : parameters) {
            if (++evaluations > MAX_EVALUATIONS) break;
            if (isSensitiveName(parameter.path())) {
                findings.add(finding(parameter, "field_name"));
            }
            if (parameter.value() instanceof String text) {
                for (var pattern : VALUE_PATTERNS) {
                    if (pattern.expression().matcher(text).find()) {
                        findings.add(finding(parameter, pattern.kind()));
                        break;
                    }
                }
            }
        }
        return List.copyOf(findings);
    }

    public boolean isSensitiveName(String path) {
        var leaf = path.substring(path.lastIndexOf('.') + 1);
        var normalized = leaf.toLowerCase(Locale.ROOT).replace('-', '_');
        return SENSITIVE_NAME.matcher(normalized).find();
    }

    private Models.Finding finding(Models.Parameter parameter, String match) {
        var inQuery = parameter.location() == Models.ParameterLocation.QUERY;
        return Models.Finding.of(
            inQuery ? "sensitive.in_query" : "sensitive.field",
            "sensitive_data",
            inQuery ? Models.Severity.HIGH : Models.Severity.MEDIUM,
            inQuery ? 40 : 10,
            inQuery ? Models.Action.BLOCK : Models.Action.OBSERVE
        ).withEvidence("location", parameter.location().name())
            .withEvidence("field", parameter.path())
            .withEvidence("match", match);
    }

    private record ValuePattern(String kind, Pattern expression) {
    }
}
