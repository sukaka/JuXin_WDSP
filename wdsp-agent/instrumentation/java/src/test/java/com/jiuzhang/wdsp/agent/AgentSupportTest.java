package com.jiuzhang.wdsp.agent;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Proxy;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.springframework.web.util.ContentCachingRequestWrapper;

class AgentSupportTest {
    @Test
    void jsonEscapesControlCharacters() {
        String json = Json.stringify(Map.of("path", "$.mobile", "value", "a\"b\n"));
        assertEquals("{\"path\":\"$.mobile\",\"value\":\"a\\\"b\\n\"}", json);
    }

    @Test
    void outputStreamIsBoundedWithoutDroppingBusinessBytes() throws Exception {
        ByteArrayOutputStream business = new ByteArrayOutputStream();
        BoundedOutputStream stream = new BoundedOutputStream(business, 4);
        byte[] input = "12345678".getBytes(StandardCharsets.UTF_8);
        stream.write(input, 0, input.length);
        assertArrayEquals(input, business.toByteArray());
        assertEquals(4, stream.capturedBytes().length);
        assertTrue(stream.isTruncated());
    }

    @Test
    void pathNormalizationDoesNotIncludeQuery() {
        assertEquals("/orders/{id}", CaptureReporter.normalizePath("/orders/123"));
        assertEquals("/orders/{id}/items", CaptureReporter.normalizePath("/orders/550e8400-e29b-41d4-a716-446655440000/items"));
    }

    @Test
    void messageContainsOnlyBoundedBase64() {
        var message = CaptureReporter.message("application/json", "{\"mobile\":\"13800138000\"}".getBytes(StandardCharsets.UTF_8), false);
        assertEquals("ANALYZED", message.get("body_state"));
        assertTrue(String.valueOf(message.get("body_base64")).length() > 0);
    }

    @Test
    void springMvcServerCapturesDirectConnectionAddresses() throws Exception {
        String previousSocket = System.getProperty("wdsp.api.socket");
        Path socket = Files.createTempDirectory("wdsp-spring-mvc-test").resolve("api.sock");
        System.setProperty("wdsp.api.socket", socket.toString());
        StringBuilder capture = new StringBuilder();
        var executor = Executors.newSingleThreadExecutor();
        try (ServerSocketChannel server = ServerSocketChannel.open(StandardProtocolFamily.UNIX)
            .bind(UnixDomainSocketAddress.of(socket))) {
            executor.submit(() -> {
                try (var channel = server.accept()) {
                    ByteBuffer buffer = ByteBuffer.allocate(65536);
                    while (channel.read(buffer) >= 0) { }
                    capture.append(new String(buffer.array(), 0, buffer.position(), StandardCharsets.UTF_8));
                    channel.write(ByteBuffer.wrap(
                        "HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".getBytes(StandardCharsets.US_ASCII)));
                } catch (Exception cause) {
                    throw new RuntimeException(cause);
                }
            });

            var request = servletStub(HttpServletRequest.class, Map.of(
                "getMethod", "POST",
                "getScheme", "https",
                "getServerName", "orders.internal",
                "getRemoteAddr", "192.0.2.10",
                "getLocalAddr", "10.20.30.40",
                "getAttribute", "/orders/{id}",
                "getRequestURI", "/orders/42",
                "getContentType", "",
                "getContentLengthLong", 0L));
            var response = servletStub(HttpServletResponse.class, Map.of(
                "getStatus", 201,
                "getContentType", ""));
            var cachedRequest = new ContentCachingRequestWrapper(request, 1024);
            var cachedResponse = new BoundedHttpServletResponseWrapper(response, 1024);
            SpringMvcAdvice.exit(cachedRequest, cachedResponse, System.nanoTime(), cachedRequest, cachedResponse);

            executor.shutdown();
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));
        } finally {
            executor.shutdownNow();
            Files.deleteIfExists(socket);
            Files.deleteIfExists(socket.getParent());
            if (previousSocket == null) System.clearProperty("wdsp.api.socket");
            else System.setProperty("wdsp.api.socket", previousSocket);
        }

        String json = capture.toString();
        assertTrue(json.contains("\"peer_address\":\"192.0.2.10\""), json);
        assertTrue(json.contains("\"client_address\":\"192.0.2.10\""), json);
        assertTrue(json.contains("\"client_address_source\":\"DIRECT_PEER\""), json);
        assertTrue(json.contains("\"server_address\":\"10.20.30.40\""), json);
        assertFalse(json.contains("198.51.100.200"), json);
    }

    private static <T> T servletStub(Class<T> type, Map<String, ?> values) {
        return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type},
            (proxy, method, arguments) -> {
                if (method.getName().equals("getHeader")) return "198.51.100.200";
                if (values.containsKey(method.getName())) return values.get(method.getName());
                Class<?> result = method.getReturnType();
                if (result == boolean.class) return false;
                if (result == int.class) return 0;
                if (result == long.class) return 0L;
                if (result == short.class) return (short) 0;
                if (result == byte.class) return (byte) 0;
                if (result == char.class) return (char) 0;
                if (result == float.class) return 0F;
                if (result == double.class) return 0D;
                return null;
            }));
    }
}
