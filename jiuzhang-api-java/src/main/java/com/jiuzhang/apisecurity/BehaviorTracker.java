package com.jiuzhang.apisecurity;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public final class BehaviorTracker {
    private final long requestLimit;
    private final Duration window;
    private final int capacity;
    private final String salt;
    private final Map<String, Window> windows = new HashMap<>();
    private final Map<String, ObjectWindow> objects = new HashMap<>();

    public BehaviorTracker(long requestLimit, Duration window, int capacity, String salt) {
        this.requestLimit = requestLimit;
        this.window = window;
        this.capacity = capacity;
        this.salt = salt;
    }

    public synchronized Models.Finding acquire(Models.RequestContext context) {
        var now = Instant.now();
        var key = trackingKey(context);
        cleanup(now);
        var current = windows.get(key);
        if (current == null) {
            if (windows.size() >= capacity) return saturatedFinding();
            current = new Window(now);
            windows.put(key, current);
        }
        if (!now.isBefore(current.started.plus(window))) {
            current = new Window(now);
            windows.put(key, current);
        }
        current.count++;
        if (current.count > requestLimit) {
            return Models.Finding.of(
                "behavior.request_rate", "behavior", Models.Severity.HIGH, 30, Models.Action.RATE_LIMIT
            );
        }
        return null;
    }

    public synchronized Models.Finding observeObjects(
        Models.RequestContext context,
        PathNormalizer.Result path
    ) {
        if (context.identity().isAnonymous() || path.objects().isEmpty()) return null;
        var now = Instant.now();
        var key = context.endpointKey() + ":" + context.identity().fingerprint();
        objects.entrySet().removeIf(entry -> !now.isBefore(entry.getValue().started.plus(window)));
        if (!objects.containsKey(key) && objects.size() >= capacity) {
            return Models.Finding.of(
                "behavior.object_tracker_capacity", "behavior",
                Models.Severity.HIGH, 15, Models.Action.OBSERVE
            );
        }
        var current = objects.computeIfAbsent(key, ignored -> new ObjectWindow(now));
        if (!now.isBefore(current.started.plus(window))) {
            current = new ObjectWindow(now);
            objects.put(key, current);
        }
        for (var object : path.objects()) {
            current.references.add(Fingerprints.hmac(salt, object.kind() + ":" + object.rawValue()));
        }
        if (current.references.size() > 20) {
            return Models.Finding.of(
                "behavior.object_enumeration", "behavior",
                Models.Severity.MEDIUM, 20, Models.Action.OBSERVE
            ).withEvidence("threshold", "20_distinct_objects");
        }
        return null;
    }

    public synchronized int trackedWindows() {
        return windows.size();
    }

    public synchronized int trackedObjectWindows() {
        return objects.size();
    }

    private void cleanup(Instant now) {
        windows.entrySet().removeIf(entry -> !now.isBefore(entry.getValue().started.plus(window)));
        objects.entrySet().removeIf(entry -> !now.isBefore(entry.getValue().started.plus(window)));
    }

    private String trackingKey(Models.RequestContext context) {
        if (!context.identity().isAnonymous()) return "id:" + context.identity().fingerprint();
        return "ip:" + context.clientAddress();
    }

    private Models.Finding saturatedFinding() {
        return Models.Finding.of(
            "behavior.tracker_capacity", "behavior",
            Models.Severity.HIGH, 30, Models.Action.RATE_LIMIT
        );
    }

    private static final class Window {
        private final Instant started;
        private long count;

        private Window(Instant started) {
            this.started = started;
        }
    }

    private static final class ObjectWindow {
        private final Instant started;
        private final Set<String> references = new HashSet<>();

        private ObjectWindow(Instant started) {
            this.started = started;
        }
    }
}
