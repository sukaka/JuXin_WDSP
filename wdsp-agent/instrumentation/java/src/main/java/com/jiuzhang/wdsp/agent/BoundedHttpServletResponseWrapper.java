package com.jiuzhang.wdsp.agent;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;

import jakarta.servlet.ServletOutputStream;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;

public class BoundedHttpServletResponseWrapper extends HttpServletResponseWrapper {
    private final int limit;
    private BoundedServletOutputStream output;
    private PrintWriter writer;

    public BoundedHttpServletResponseWrapper(HttpServletResponse response, int limit) {
        super(response);
        this.limit = limit;
    }

    @Override public ServletOutputStream getOutputStream() throws IOException {
        if (writer != null) throw new IllegalStateException("getWriter already called");
        if (output == null) output = new BoundedServletOutputStream(super.getOutputStream(), limit);
        return output;
    }

    @Override public PrintWriter getWriter() throws IOException {
        if (output != null) throw new IllegalStateException("getOutputStream already called");
        if (writer == null) {
            output = new BoundedServletOutputStream(super.getOutputStream(), limit);
            writer = new PrintWriter(new OutputStreamWriter(output, getCharacterEncoding()));
        }
        return writer;
    }

    @Override public void flushBuffer() throws IOException {
        if (writer != null) writer.flush();
        else if (output != null) output.flush();
    }

    public byte[] capturedBytes() {
        return output == null ? new byte[0] : output.stream().capturedBytes();
    }

    public boolean isTruncated() {
        return output != null && output.stream().isTruncated();
    }
}
