package com.jiuzhang.wdsp.agent;

import java.net.InetAddress;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

public class CaptureConfig {
    public static final String AGENT_VERSION = "1.0.0";
    public static final long SOURCE_EPOCH = System.currentTimeMillis() / 1000;
    public static final int MAX_BODY_BYTES = intSetting("wdsp.api.max.body.bytes", "WDSP_API_MAX_BODY_BYTES", 256 * 1024, 1024, 1024 * 1024);
    public static final String SOCKET_PATH = setting("wdsp.api.socket", "WDSP_API_SOCKET", "/run/wdsp-agent/api.sock");
    public static final String SERVICE_NAME = setting("wdsp.service.name", "WDSP_SERVICE_NAME", setting("otel.service.name", "OTEL_SERVICE_NAME", "unknown-service"));
    public static final String INSTANCE_ID = setting("wdsp.service.instance", "WDSP_SERVICE_INSTANCE", defaultInstance());
    public static final String BINDING_ID = setting("wdsp.application.binding.id", "WDSP_APPLICATION_BINDING_ID", "");
    public static final String BINDING_VERSION = setting("wdsp.application.binding.version", "WDSP_APPLICATION_BINDING_VERSION", "");

    private CaptureConfig() {}

    public static Map<String, Object> service() {
        Map<String, Object> service = new LinkedHashMap<>();
        service.put("name", SERVICE_NAME);
        service.put("instance_id", INSTANCE_ID);
        service.put("version", setting("wdsp.service.version", "WDSP_SERVICE_VERSION", ""));
        service.put("environment", setting("wdsp.service.environment", "WDSP_SERVICE_ENVIRONMENT", ""));
        service.put("namespace", setting("wdsp.service.namespace", "WDSP_SERVICE_NAMESPACE", ""));
        service.put("cluster", setting("wdsp.service.cluster", "WDSP_SERVICE_CLUSTER", ""));
        return service;
    }

    public static Map<String, Object> source(String framework) {
        Map<String, Object> source = new LinkedHashMap<>();
        source.put("type", "IN_PROCESS");
        source.put("language", "java");
        source.put("framework", framework);
        source.put("agent_version", AGENT_VERSION);
        source.put("source_epoch", SOURCE_EPOCH);
        return source;
    }

    public static String setting(String property, String env, String fallback) {
        String value = System.getProperty(property);
        if (value == null || value.isBlank()) value = System.getenv(env);
        if (value == null || value.isBlank()) return fallback;
        return value.trim();
    }

    private static int intSetting(String property, String env, int fallback, int min, int max) {
        try {
            int value = Integer.parseInt(setting(property, env, String.valueOf(fallback)));
            return Math.max(min, Math.min(max, value));
        } catch (NumberFormatException ignored) {
            return fallback;
        }
    }

    private static String defaultInstance() {
        try {
            return InetAddress.getLocalHost().getHostName() + "-" + UUID.randomUUID();
        } catch (Exception ignored) {
            return UUID.randomUUID().toString();
        }
    }
}
