package com.jiuzhang.wdsp.agent;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Executors;

import org.junit.jupiter.api.Test;

class UnixSocketClientTest {
    @Test
    void postsCaptureToLocalUnixSocket() throws Exception {
        Path socket = Files.createTempDirectory("wdsp-java-test").resolve("api.sock");
        StringBuilder request = new StringBuilder();
        try (ServerSocketChannel server = ServerSocketChannel.open(java.net.StandardProtocolFamily.UNIX).bind(UnixDomainSocketAddress.of(socket))) {
            var executor = Executors.newSingleThreadExecutor();
            executor.submit(() -> {
                try (SocketChannel channel = server.accept()) {
                    ByteBuffer buffer = ByteBuffer.allocate(16384);
                    while (channel.read(buffer) >= 0) { }
                    request.append(new String(buffer.array(), 0, buffer.position(), StandardCharsets.UTF_8));
                    channel.write(ByteBuffer.wrap("HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".getBytes(StandardCharsets.US_ASCII)));
                } catch (Exception ignored) {
                }
            });
            UnixSocketClient.post(socket.toString(), "{\"schema_version\":1,\"records\":[]}");
            executor.shutdown();
            assertTrue(executor.awaitTermination(5, java.util.concurrent.TimeUnit.SECONDS));
        } finally {
            Files.deleteIfExists(socket);
        }
        assertTrue(request.toString().contains("POST /v1/api-captures"));
        assertTrue(request.toString().contains("schema_version"));
    }
}
