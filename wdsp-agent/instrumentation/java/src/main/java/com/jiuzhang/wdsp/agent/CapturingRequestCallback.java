package com.jiuzhang.wdsp.agent;

import java.io.IOException;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.web.client.RequestCallback;

public class CapturingRequestCallback implements RequestCallback {
    private final RequestCallback delegate;
    private final CapturingClientHttpRequest request;

    public CapturingRequestCallback(RequestCallback delegate, CapturingClientHttpRequest request) {
        this.delegate = delegate;
        this.request = request;
    }

    @Override public void doWithRequest(ClientHttpRequest ignored) throws IOException {
        request.delegate = ignored;
        delegate.doWithRequest(request);
    }
}
