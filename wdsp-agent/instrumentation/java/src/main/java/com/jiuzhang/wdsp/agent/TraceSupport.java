package com.jiuzhang.wdsp.agent;

import java.util.LinkedHashMap;
import java.util.Map;

import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanContext;

public class TraceSupport {
    private TraceSupport() {}

    public static Map<String, Object> current() {
        Map<String, Object> trace = new LinkedHashMap<>();
        String traceId = "";
        String spanId = "";
        try {
            SpanContext context = Span.current().getSpanContext();
            if (context.isValid()) {
                traceId = context.getTraceId();
                spanId = context.getSpanId();
            }
        } catch (NoClassDefFoundError ignored) {
        } catch (Throwable cause) {
            CaptureReporter.noteFailure("trace correlation", cause);
        }
        trace.put("trace_id", traceId);
        trace.put("span_id", spanId);
        trace.put("parent_span_id", "");
        return trace;
    }
}
