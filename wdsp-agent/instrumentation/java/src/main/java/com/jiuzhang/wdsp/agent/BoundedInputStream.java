package com.jiuzhang.wdsp.agent;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class BoundedInputStream extends InputStream {
    private final InputStream delegate;
    private final int limit;
    private final ByteArrayOutputStream captured = new ByteArrayOutputStream();
    private boolean truncated;

    public BoundedInputStream(InputStream delegate, int limit) {
        this.delegate = delegate;
        this.limit = limit;
    }

    @Override public int read() throws IOException {
        int value = delegate.read();
        if (value >= 0) capture(new byte[]{(byte) value}, 0, 1);
        return value;
    }

    @Override public int read(byte[] bytes, int offset, int length) throws IOException {
        int read = delegate.read(bytes, offset, length);
        if (read > 0) capture(bytes, offset, read);
        return read;
    }

    private void capture(byte[] bytes, int offset, int length) {
        int remaining = limit - captured.size();
        if (length > remaining) truncated = true;
        if (remaining > 0) captured.write(bytes, offset, Math.min(length, remaining));
    }

    @Override public int available() throws IOException { return delegate.available(); }
    @Override public void close() throws IOException { delegate.close(); }
    public byte[] capturedBytes() { return captured.toByteArray(); }
    public boolean isTruncated() { return truncated; }
}
