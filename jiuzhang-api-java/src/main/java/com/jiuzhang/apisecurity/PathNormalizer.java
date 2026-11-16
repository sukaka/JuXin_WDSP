package com.jiuzhang.apisecurity;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public final class PathNormalizer {
    private static final Pattern NUMBER = Pattern.compile("[0-9]+");
    private static final Pattern UUID = Pattern.compile(
        "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}"
    );
    private static final Pattern HEX = Pattern.compile("[0-9a-fA-F]{16,}");
    private static final Pattern DATE = Pattern.compile("[0-9]{4}-[0-9]{2}-[0-9]{2}");

    public Result normalize(String rawPath) {
        if (rawPath == null || !rawPath.startsWith("/") || rawPath.length() > 8192) {
            throw new IllegalArgumentException("invalid request path");
        }
        var rawSegments = rawPath.split("/", -1);
        if (rawSegments.length > 129) {
            throw new IllegalArgumentException("too many path segments");
        }
        var normalized = new StringBuilder();
        var objects = new ArrayList<ObjectReference>();
        for (int index = 0; index < rawSegments.length; index++) {
            if (index == 0 && rawSegments[index].isEmpty()) continue;
            var segment = decode(rawSegments[index]);
            if (segment.length() > 1024 || segment.chars().anyMatch(Character::isISOControl)) {
                throw new IllegalArgumentException("invalid path segment");
            }
            normalized.append('/');
            var kind = kind(segment);
            if (kind.equals("static")) {
                normalized.append(segment);
            } else {
                normalized.append('{').append(kind).append('}');
                objects.add(new ObjectReference(index, kind, segment));
            }
        }
        var result = normalized.length() == 0 ? "/" : normalized.toString();
        return new Result(result, List.copyOf(objects));
    }

    private String decode(String segment) {
        try {
            return URLDecoder.decode(segment.replace("+", "%2B"), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException error) {
            throw new IllegalArgumentException("invalid percent encoding in path", error);
        }
    }

    private String kind(String segment) {
        if (UUID.matcher(segment).matches()) return "uuid";
        if (NUMBER.matcher(segment).matches()) return "id";
        if (HEX.matcher(segment).matches()) return "hex";
        if (DATE.matcher(segment).matches()) return "date";
        return "static";
    }

    public record Result(String normalizedPath, List<ObjectReference> objects) {
        public Result {
            objects = List.copyOf(objects);
        }
    }

    public record ObjectReference(int segment, String kind, String rawValue) {
    }
}
