package com.jiuzhang.wdsp.agent;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpResponse;

public class CapturingClientHttpRequest implements ClientHttpRequest {
    public ClientHttpRequest delegate;
    private final int limit;
    private BoundedOutputStream body;
    private String contentType = "";

    public CapturingClientHttpRequest(ClientHttpRequest delegate, int limit) {
        this.delegate = delegate;
        this.limit = limit;
    }

    @Override public OutputStream getBody() throws IOException {
        if (body == null) body = new BoundedOutputStream(delegate.getBody(), limit);
        contentType = String.valueOf(delegate.getHeaders().getFirst(HttpHeaders.CONTENT_TYPE));
        return body;
    }

    @Override public ClientHttpResponse execute() throws IOException { return delegate.execute(); }
    @Override public HttpMethod getMethod() { return delegate.getMethod(); }
    @Override public URI getURI() { return delegate.getURI(); }
    @Override public HttpHeaders getHeaders() { return delegate.getHeaders(); }
    @Override public Map<String, Object> getAttributes() { return delegate.getAttributes(); }

    public String contentType() { return contentType; }
    public byte[] capturedBytes() { return body == null ? new byte[0] : body.capturedBytes(); }
    public boolean truncated() { return body != null && body.isTruncated(); }
}
