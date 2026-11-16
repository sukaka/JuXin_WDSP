package com.jiuzhang.wdsp.agent;

import java.io.IOException;
import java.net.UnixDomainSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

public class UnixSocketClient {
    private UnixSocketClient() {}

    public static void post(String socketPath, String json) throws IOException {
        UnixDomainSocketAddress address = UnixDomainSocketAddress.of(Path.of(socketPath));
        try (SocketChannel channel = SocketChannel.open(address)) {
            byte[] body = json.getBytes(StandardCharsets.UTF_8);
            String headers = "POST /v1/api-captures HTTP/1.1\r\n" +
                "Host: localhost\r\n" +
                "Content-Type: application/json\r\n" +
                "Content-Length: " + body.length + "\r\n" +
                "Connection: close\r\n\r\n";
            write(channel, headers.getBytes(StandardCharsets.US_ASCII));
            write(channel, body);
            channel.shutdownOutput();
            String response = new String(readBounded(channel, 65536), StandardCharsets.UTF_8);
            if (!response.startsWith("HTTP/1.1 202") && !response.startsWith("HTTP/1.0 202")) {
                throw new IOException("local API capture rejected");
            }
        }
    }

    private static void write(SocketChannel channel, byte[] bytes) throws IOException {
        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        while (buffer.hasRemaining()) channel.write(buffer);
    }

    private static byte[] readBounded(SocketChannel channel, int max) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(max);
        int read = channel.read(buffer);
        if (read < 0) return new byte[0];
        byte[] out = new byte[read];
        buffer.flip();
        buffer.get(out);
        return out;
    }
}
