package com.jiuzhang.wdsp.agent;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class BoundedOutputStream extends OutputStream {
    private final OutputStream delegate;
    private final int limit;
    private final ByteArrayOutputStream captured = new ByteArrayOutputStream();
    private boolean truncated;

    public BoundedOutputStream(OutputStream delegate, int limit) {
        this.delegate = delegate;
        this.limit = limit;
    }

    @Override public void write(int value) throws IOException {
        delegate.write(value);
        capture(new byte[]{(byte) value}, 0, 1);
    }

    @Override public void write(byte[] bytes, int offset, int length) throws IOException {
        delegate.write(bytes, offset, length);
        capture(bytes, offset, length);
    }

    private void capture(byte[] bytes, int offset, int length) {
        int remaining = limit - captured.size();
        if (length > remaining) truncated = true;
        if (remaining > 0) captured.write(bytes, offset, Math.min(length, remaining));
    }

    @Override public void flush() throws IOException { delegate.flush(); }
    @Override public void close() throws IOException { delegate.close(); }
    public byte[] capturedBytes() { return captured.toByteArray(); }
    public boolean isTruncated() { return truncated; }
}
