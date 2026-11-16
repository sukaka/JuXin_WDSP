package com.jiuzhang.wdsp.agent;

import java.lang.reflect.Array;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;

public class Json {
    private Json() {}

    public static String stringify(Object value) {
        StringBuilder out = new StringBuilder();
        append(out, value);
        return out.toString();
    }

    private static void append(StringBuilder out, Object value) {
        if (value == null) {
            out.append("null");
        } else if (value instanceof String || value instanceof Character) {
            quote(out, value.toString());
        } else if (value instanceof Number || value instanceof Boolean) {
            out.append(value);
        } else if (value instanceof Map<?, ?> map) {
            out.append('{');
            Map<String, Object> sorted = new TreeMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) sorted.put(String.valueOf(entry.getKey()), entry.getValue());
            Iterator<Map.Entry<String, Object>> iterator = sorted.entrySet().iterator();
            while (iterator.hasNext()) {
                Map.Entry<String, Object> entry = iterator.next();
                quote(out, entry.getKey());
                out.append(':');
                append(out, entry.getValue());
                if (iterator.hasNext()) out.append(',');
            }
            out.append('}');
        } else if (value instanceof Iterable<?> iterable) {
            out.append('[');
            Iterator<?> iterator = iterable.iterator();
            while (iterator.hasNext()) {
                append(out, iterator.next());
                if (iterator.hasNext()) out.append(',');
            }
            out.append(']');
        } else if (value.getClass().isArray()) {
            out.append('[');
            int length = Array.getLength(value);
            for (int i = 0; i < length; i++) {
                append(out, Array.get(value, i));
                if (i + 1 < length) out.append(',');
            }
            out.append(']');
        } else {
            quote(out, value.toString());
        }
    }

    private static void quote(StringBuilder out, String value) {
        out.append('"');
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\b' -> out.append("\\b");
                case '\f' -> out.append("\\f");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) out.append(String.format("\\u%04x", (int) c));
                    else out.append(c);
                }
            }
        }
        out.append('"');
    }
}
