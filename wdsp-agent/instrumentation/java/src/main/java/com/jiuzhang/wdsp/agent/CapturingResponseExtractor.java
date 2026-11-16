package com.jiuzhang.wdsp.agent;

import java.io.IOException;

import org.springframework.http.HttpHeaders;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.web.client.ResponseExtractor;

public class CapturingResponseExtractor<T> implements ResponseExtractor<T> {
    private final ResponseExtractor<T> delegate;
    private BoundedInputStream body;
    public int status;
    public String contentType = "";

    public CapturingResponseExtractor(ResponseExtractor<T> delegate) {
        this.delegate = delegate;
    }

    @Override public T extractData(ClientHttpResponse response) throws IOException {
        status = response.getStatusCode().value();
        contentType = String.valueOf(response.getHeaders().getFirst(HttpHeaders.CONTENT_TYPE));
        body = new BoundedInputStream(response.getBody(), CaptureConfig.MAX_BODY_BYTES);
        return delegate.extractData(new DelegatingClientHttpResponse(response, body));
    }

    public byte[] capturedBytes() { return body == null ? new byte[0] : body.capturedBytes(); }
    public boolean truncated() { return body != null && body.isTruncated(); }
}
