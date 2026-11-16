package com.jiuzhang.apisecurity;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class Json {
    private static final int MAX_DEPTH = 64;
    private static final int MAX_NODES = 10_000;
    private static final int MAX_INPUT_CHARS = 1_048_576;

    private Json() {
    }

    public static Object parse(String source) {
        if (source == null) {
            throw new IllegalArgumentException("JSON input is null");
        }
        if (source.length() > MAX_INPUT_CHARS) {
            throw new IllegalArgumentException("JSON input exceeds the parser limit");
        }
        var parser = new Parser(source);
        var value = parser.readValue(0);
        parser.skipWhitespace();
        if (!parser.atEnd()) {
            throw parser.error("unexpected trailing content");
        }
        return value;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String source) {
        var value = parse(source);
        if (!(value instanceof Map)) {
            throw new IllegalArgumentException("JSON root must be an object");
        }
        return (Map<String, Object>) value;
    }

    public static String stringify(Object value) {
        var output = new StringBuilder();
        write(value, output);
        return output.toString();
    }

    public static Map<String, Object> flatten(Object root) {
        var output = new LinkedHashMap<String, Object>();
        flattenValue("", root, output, 0);
        return output;
    }

    public static Models.ValueType typeOf(Object value) {
        if (value == null) return Models.ValueType.NULL;
        if (value instanceof String) return Models.ValueType.STRING;
        if (value instanceof Number) return Models.ValueType.NUMBER;
        if (value instanceof Boolean) return Models.ValueType.BOOLEAN;
        if (value instanceof List) return Models.ValueType.ARRAY;
        if (value instanceof Map) return Models.ValueType.OBJECT;
        throw new IllegalArgumentException("unsupported JSON value type");
    }

    private static void flattenValue(
        String path,
        Object value,
        Map<String, Object> output,
        int depth
    ) {
        if (depth > MAX_DEPTH) {
            throw new IllegalArgumentException("JSON flattening depth exceeded");
        }
        if (value instanceof Map<?, ?> object && !object.isEmpty()) {
            for (var entry : object.entrySet()) {
                if (!(entry.getKey() instanceof String key)) {
                    throw new IllegalArgumentException("JSON object key is not a string");
                }
                var child = path.isEmpty() ? key : path + "." + key;
                flattenValue(child, entry.getValue(), output, depth + 1);
            }
            return;
        }
        if (!path.isEmpty()) {
            output.put(path, value);
        }
    }

    private static void write(Object value, StringBuilder output) {
        switch (value) {
            case null -> output.append("null");
            case String text -> writeString(text, output);
            case Boolean bool -> output.append(bool);
            case BigDecimal number -> output.append(number.toPlainString());
            case Integer number -> output.append(number);
            case Long number -> output.append(number);
            case Double number -> {
                if (!Double.isFinite(number)) {
                    throw new IllegalArgumentException("non-finite number cannot be JSON");
                }
                output.append(number);
            }
            case Float number -> {
                if (!Float.isFinite(number)) {
                    throw new IllegalArgumentException("non-finite number cannot be JSON");
                }
                output.append(number);
            }
            case Map<?, ?> object -> writeObject(object, output);
            case List<?> array -> writeArray(array, output);
            default -> throw new IllegalArgumentException(
                "unsupported value for JSON serialization: " + value.getClass().getName()
            );
        }
    }

    private static void writeObject(Map<?, ?> object, StringBuilder output) {
        output.append('{');
        var first = true;
        for (var entry : object.entrySet()) {
            if (!(entry.getKey() instanceof String key)) {
                throw new IllegalArgumentException("JSON object key is not a string");
            }
            if (!first) output.append(',');
            first = false;
            writeString(key, output);
            output.append(':');
            write(entry.getValue(), output);
        }
        output.append('}');
    }

    private static void writeArray(List<?> array, StringBuilder output) {
        output.append('[');
        for (int index = 0; index < array.size(); index++) {
            if (index > 0) output.append(',');
            write(array.get(index), output);
        }
        output.append(']');
    }

    private static void writeString(String value, StringBuilder output) {
        output.append('"');
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '"' -> output.append("\\\"");
                case '\\' -> output.append("\\\\");
                case '\b' -> output.append("\\b");
                case '\f' -> output.append("\\f");
                case '\n' -> output.append("\\n");
                case '\r' -> output.append("\\r");
                case '\t' -> output.append("\\t");
                default -> {
                    if (character < 0x20) {
                        output.append(String.format("\\u%04x", (int) character));
                    } else {
                        output.append(character);
                    }
                }
            }
        }
        output.append('"');
    }

    private static final class Parser {
        private final String source;
        private int position;
        private int nodes;

        private Parser(String source) {
            this.source = source;
        }

        private Object readValue(int depth) {
            if (depth > MAX_DEPTH) {
                throw error("nesting depth exceeded");
            }
            nodes++;
            if (nodes > MAX_NODES) {
                throw error("node count exceeded");
            }
            skipWhitespace();
            if (atEnd()) throw error("expected a JSON value");
            return switch (source.charAt(position)) {
                case '{' -> readObject(depth);
                case '[' -> readArray(depth);
                case '"' -> readString();
                case 't' -> readLiteral("true", Boolean.TRUE);
                case 'f' -> readLiteral("false", Boolean.FALSE);
                case 'n' -> readLiteral("null", null);
                default -> readNumber();
            };
        }

        private Map<String, Object> readObject(int depth) {
            position++;
            var object = new LinkedHashMap<String, Object>();
            skipWhitespace();
            if (consume('}')) return object;
            while (true) {
                skipWhitespace();
                if (atEnd() || source.charAt(position) != '"') {
                    throw error("expected an object key");
                }
                var key = readString();
                skipWhitespace();
                require(':');
                if (object.containsKey(key)) {
                    throw error("duplicate object key");
                }
                object.put(key, readValue(depth + 1));
                skipWhitespace();
                if (consume('}')) return object;
                require(',');
            }
        }

        private List<Object> readArray(int depth) {
            position++;
            var array = new ArrayList<Object>();
            skipWhitespace();
            if (consume(']')) return array;
            while (true) {
                array.add(readValue(depth + 1));
                skipWhitespace();
                if (consume(']')) return array;
                require(',');
            }
        }

        private String readString() {
            require('"');
            var output = new StringBuilder();
            while (!atEnd()) {
                char character = source.charAt(position++);
                if (character == '"') return output.toString();
                if (character < 0x20) throw error("control character in string");
                if (character != '\\') {
                    output.append(character);
                    continue;
                }
                if (atEnd()) throw error("unfinished string escape");
                char escaped = source.charAt(position++);
                switch (escaped) {
                    case '"' -> output.append('"');
                    case '\\' -> output.append('\\');
                    case '/' -> output.append('/');
                    case 'b' -> output.append('\b');
                    case 'f' -> output.append('\f');
                    case 'n' -> output.append('\n');
                    case 'r' -> output.append('\r');
                    case 't' -> output.append('\t');
                    case 'u' -> output.append(readUnicodeEscape());
                    default -> throw error("unknown string escape");
                }
            }
            throw error("unterminated string");
        }

        private char readUnicodeEscape() {
            if (position + 4 > source.length()) throw error("short unicode escape");
            var digits = source.substring(position, position + 4);
            position += 4;
            try {
                return (char) Integer.parseInt(digits, 16);
            } catch (NumberFormatException error) {
                throw error("invalid unicode escape");
            }
        }

        private Object readLiteral(String literal, Object value) {
            if (!source.startsWith(literal, position)) throw error("invalid literal");
            position += literal.length();
            return value;
        }

        private BigDecimal readNumber() {
            int start = position;
            if (consume('-')) {
                if (atEnd()) throw error("incomplete number");
            }
            if (consume('0')) {
                if (!atEnd() && Character.isDigit(source.charAt(position))) {
                    throw error("leading zero in number");
                }
            } else {
                readDigits(true);
            }
            if (consume('.')) readDigits(true);
            if (!atEnd() && (source.charAt(position) == 'e' || source.charAt(position) == 'E')) {
                position++;
                if (!atEnd() && (source.charAt(position) == '+' || source.charAt(position) == '-')) {
                    position++;
                }
                readDigits(true);
            }
            if (start == position) throw error("expected a JSON value");
            try {
                return new BigDecimal(source.substring(start, position));
            } catch (NumberFormatException error) {
                throw error("invalid number");
            }
        }

        private void readDigits(boolean requireOne) {
            int start = position;
            while (!atEnd() && Character.isDigit(source.charAt(position))) position++;
            if (requireOne && start == position) throw error("expected a digit");
        }

        private void skipWhitespace() {
            while (!atEnd()) {
                char character = source.charAt(position);
                if (character != ' ' && character != '\n' && character != '\r' && character != '\t') {
                    return;
                }
                position++;
            }
        }

        private boolean consume(char expected) {
            if (!atEnd() && source.charAt(position) == expected) {
                position++;
                return true;
            }
            return false;
        }

        private void require(char expected) {
            if (!consume(expected)) throw error("expected '" + expected + "'");
        }

        private boolean atEnd() {
            return position == source.length();
        }

        private IllegalArgumentException error(String message) {
            return new IllegalArgumentException(message + " at character " + position);
        }
    }
}
