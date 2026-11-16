package com.jiuzhang.wdsp.agent;

import java.io.IOException;
import java.io.InputStream;

import org.springframework.http.HttpHeaders;
import org.springframework.http.client.ClientHttpResponse;

public class DelegatingClientHttpResponse implements ClientHttpResponse {
    private final ClientHttpResponse delegate;
    private final BoundedInputStream body;

    public DelegatingClientHttpResponse(ClientHttpResponse delegate, BoundedInputStream body) {
        this.delegate = delegate;
        this.body = body;
    }

    @Override public org.springframework.http.HttpStatusCode getStatusCode() throws IOException { return delegate.getStatusCode(); }
    @Override public String getStatusText() throws IOException { return delegate.getStatusText(); }
    @Override public HttpHeaders getHeaders() { return delegate.getHeaders(); }
    @Override public InputStream getBody() { return body; }
    @Override public void close() { delegate.close(); }
}
