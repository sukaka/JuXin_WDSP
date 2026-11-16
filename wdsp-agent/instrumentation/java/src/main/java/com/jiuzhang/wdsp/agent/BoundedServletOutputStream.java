package com.jiuzhang.wdsp.agent;

import java.io.IOException;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.WriteListener;

public class BoundedServletOutputStream extends ServletOutputStream {
    private final ServletOutputStream delegate;
    private final BoundedOutputStream stream;

    public BoundedServletOutputStream(ServletOutputStream delegate, int limit) {
        this.delegate = delegate;
        this.stream = new BoundedOutputStream(delegate, limit);
    }

    public BoundedOutputStream stream() { return stream; }
    @Override public void write(int value) throws IOException { stream.write(value); }
    @Override public void write(byte[] bytes, int offset, int length) throws IOException { stream.write(bytes, offset, length); }
    @Override public void flush() throws IOException { stream.flush(); }
    @Override public void close() throws IOException { stream.close(); }
    @Override public boolean isReady() { return delegate.isReady(); }
    @Override public void setWriteListener(WriteListener listener) { delegate.setWriteListener(listener); }
}
