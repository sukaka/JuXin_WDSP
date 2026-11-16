package com.jiuzhang.wdsp.agent;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;

import net.bytebuddy.asm.Advice;
import org.springframework.http.HttpMethod;
import org.springframework.web.client.RequestCallback;
import org.springframework.web.client.ResponseExtractor;

public class RestTemplateAdvice {
    private RestTemplateAdvice() {}

    @Advice.OnMethodEnter
    public static void enter(
        @Advice.Argument(value = 3, readOnly = false) RequestCallback callback,
        @Advice.Argument(value = 4, readOnly = false) ResponseExtractor<?> extractor,
        @Advice.Local("wdspStart") long start,
        @Advice.Local("wdspRequest") CapturingClientHttpRequest request,
        @Advice.Local("wdspExtractor") CapturingResponseExtractor<?> capturingExtractor
    ) {
        start = System.nanoTime();
        try {
            request = new CapturingClientHttpRequest(null, CaptureConfig.MAX_BODY_BYTES);
            if (callback != null) callback = new CapturingRequestCallback(callback, request);
            if (extractor != null) {
                capturingExtractor = new CapturingResponseExtractor<>(extractor);
                extractor = capturingExtractor;
            }
        } catch (Throwable cause) {
            request = null;
            capturingExtractor = null;
            CaptureReporter.noteFailure("RestTemplate capture", cause);
        }
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(
        @Advice.Argument(0) URI uri,
        @Advice.Argument(2) HttpMethod method,
        @Advice.Local("wdspStart") long start,
        @Advice.Local("wdspRequest") CapturingClientHttpRequest request,
        @Advice.Local("wdspExtractor") CapturingResponseExtractor<?> extractor
    ) {
        if (request == null) return;
        try {
            Map<String, Object> record = CaptureReporter.baseRecord("spring-resttemplate");
            Map<String, Object> http = new LinkedHashMap<>();
            http.put("direction", "CLIENT");
            http.put("method", method == null ? "" : method.name());
            http.put("scheme", uri.getScheme());
            http.put("host", uri.getHost());
            http.put("route", "");
            http.put("path_template", CaptureReporter.normalizePath(uri.getPath()));
            http.put("status", extractor == null ? 0 : extractor.status);
            http.put("latency_ms", Math.max(0, (System.nanoTime() - start) / 1_000_000));
            http.put("peer_service", CaptureConfig.setting("wdsp.api.peer.service", "WDSP_API_PEER_SERVICE", uri.getHost()));
            http.put("request", CaptureReporter.message(request.contentType(), request.capturedBytes(), request.truncated()));
            http.put("response", extractor == null
                ? CaptureReporter.message("", new byte[0], false)
                : CaptureReporter.message(extractor.contentType, extractor.capturedBytes(), extractor.truncated()));
            record.put("http", http);
            CaptureReporter.submit(record);
        } catch (Throwable cause) {
            CaptureReporter.noteFailure("RestTemplate capture", cause);
        }
    }
}
