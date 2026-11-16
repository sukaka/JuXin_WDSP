package com.jiuzhang.wdsp.agent;

import java.util.LinkedHashMap;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import net.bytebuddy.asm.Advice;
import org.springframework.web.util.ContentCachingRequestWrapper;

public class SpringMvcAdvice {
    private SpringMvcAdvice() {}

    @Advice.OnMethodEnter
    public static void enter(
        @Advice.Argument(value = 0, readOnly = false) HttpServletRequest request,
        @Advice.Argument(value = 1, readOnly = false) HttpServletResponse response,
        @Advice.Local("wdspStart") long start,
        @Advice.Local("wdspRequest") ContentCachingRequestWrapper cachedRequest,
        @Advice.Local("wdspResponse") BoundedHttpServletResponseWrapper cachedResponse
    ) {
        start = System.nanoTime();
        try {
            cachedRequest = new ContentCachingRequestWrapper(request, CaptureConfig.MAX_BODY_BYTES);
            cachedResponse = new BoundedHttpServletResponseWrapper(response, CaptureConfig.MAX_BODY_BYTES);
            request = cachedRequest;
            response = cachedResponse;
        } catch (Throwable cause) {
            cachedRequest = null;
            cachedResponse = null;
            CaptureReporter.noteFailure("Spring MVC capture", cause);
        }
    }

    @Advice.OnMethodExit(onThrowable = Throwable.class)
    public static void exit(
        @Advice.Argument(0) HttpServletRequest request,
        @Advice.Argument(1) HttpServletResponse response,
        @Advice.Local("wdspStart") long start,
        @Advice.Local("wdspRequest") ContentCachingRequestWrapper cachedRequest,
        @Advice.Local("wdspResponse") BoundedHttpServletResponseWrapper cachedResponse
    ) {
        if (cachedRequest == null || cachedResponse == null) return;
        try {
            Map<String, Object> record = CaptureReporter.baseRecord("spring-webmvc");
            Map<String, Object> http = new LinkedHashMap<>();
            http.put("direction", "SERVER");
            http.put("method", request.getMethod());
            http.put("scheme", request.getScheme());
            http.put("host", request.getServerName());
            String peerAddress = request.getRemoteAddr();
            http.put("peer_address", peerAddress);
            http.put("client_address", peerAddress);
            http.put("client_address_source", "DIRECT_PEER");
            http.put("server_address", request.getLocalAddr());
            Object pattern = request.getAttribute("org.springframework.web.servlet.HandlerMapping.bestMatchingPattern");
            String route = pattern == null ? "" : pattern.toString();
            String pathTemplate = route.isBlank() ? CaptureReporter.normalizePath(request.getRequestURI()) : route;
            http.put("route", route);
            http.put("path_template", pathTemplate);
            http.put("status", response.getStatus());
            http.put("latency_ms", Math.max(0, (System.nanoTime() - start) / 1_000_000));
            http.put("peer_service", "");
            byte[] requestBody = cachedRequest.getContentAsByteArray();
            byte[] responseBody = cachedResponse.capturedBytes();
            http.put("request", CaptureReporter.message(request.getContentType(), requestBody,
                cachedResponse.isTruncated() || (request.getContentLengthLong() > CaptureConfig.MAX_BODY_BYTES)));
            http.put("response", CaptureReporter.message(response.getContentType(), responseBody, cachedResponse.isTruncated()));
            record.put("http", http);
            CaptureReporter.submit(record);
        } catch (Throwable cause) {
            CaptureReporter.noteFailure("Spring MVC capture", cause);
        }
    }
}
