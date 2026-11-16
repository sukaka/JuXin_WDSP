package com.jiuzhang.wdsp.agent;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

public class CaptureReporter {
    private static final AtomicLong DROPPED = new AtomicLong();
    private static final ThreadPoolExecutor EXECUTOR = new ThreadPoolExecutor(
        1, 1, 30, TimeUnit.SECONDS, new ArrayBlockingQueue<>(1024),
        runnable -> {
            Thread thread = new Thread(runnable, "wdsp-api-observation-reporter");
            thread.setDaemon(true);
            return thread;
        },
        new ThreadPoolExecutor.DiscardPolicy()
    );

    private CaptureReporter() {}

    public static void submit(Map<String, Object> record) {
        if (EXECUTOR.getQueue().remainingCapacity() == 0) {
            DROPPED.incrementAndGet();
            return;
        }
        try {
            EXECUTOR.execute(() -> {
                try {
                    Map<String, Object> batch = new LinkedHashMap<>();
                    batch.put("schema_version", 1);
                    batch.put("records", new ArrayList<>(List.of(record)));
                    UnixSocketClient.post(CaptureConfig.SOCKET_PATH, Json.stringify(batch));
                } catch (Throwable cause) {
                    noteFailure(cause);
                }
            });
        } catch (Throwable cause) {
            noteFailure(cause);
        }
    }

    private static void noteFailure(Throwable cause) {
        noteFailure("export", cause);
    }

    public static void noteFailure(String stage, Throwable cause) {
        long count = DROPPED.incrementAndGet();
        if (count == 1 || count % 100 == 0) {
            System.err.println("WDSP API observation " + stage + " failed: " + cause.getClass().getSimpleName() + " (count=" + count + ")");
        }
    }

    public static Map<String, Object> baseRecord(String framework) {
        Map<String, Object> record = new LinkedHashMap<>();
        record.put("event_id", UUID.randomUUID().toString());
        record.put("occurred_at", Instant.now().toString());
        if (!CaptureConfig.BINDING_ID.isBlank() && !CaptureConfig.BINDING_VERSION.isBlank()) {
            record.put("application_binding_id", CaptureConfig.BINDING_ID);
            record.put("binding_version", Long.parseLong(CaptureConfig.BINDING_VERSION));
        } else {
            record.put("application_binding_id", null);
            record.put("binding_version", null);
        }
        record.put("source", CaptureConfig.source(framework));
        record.put("service", CaptureConfig.service());
        record.put("trace", TraceSupport.current());
        return record;
    }

    public static Map<String, Object> message(String contentType, byte[] body, boolean truncated) {
        Map<String, Object> message = new LinkedHashMap<>();
        message.put("content_type", contentType == null ? "" : contentType);
        message.put("body_base64", body == null || body.length == 0 ? "" : Base64.getEncoder().encodeToString(body));
        message.put("body_state", truncated ? "TRUNCATED" : (body == null || body.length == 0 ? "NOT_COLLECTED" : "ANALYZED"));
        message.put("truncated", truncated);
        return message;
    }

    public static String normalizePath(String path) {
        if (path == null || path.isBlank()) return "/";
        String[] segments = path.split("/");
        StringBuilder out = new StringBuilder();
        for (String segment : segments) {
            if (segment.isEmpty()) continue;
            out.append('/');
            if (segment.matches("[0-9]+") || segment.matches("[0-9a-fA-F-]{32,36}")) out.append("{id}");
            else out.append(segment);
        }
        return out.length() == 0 ? "/" : out.toString();
    }

    public static long droppedCount() {
        return DROPPED.get();
    }
}
