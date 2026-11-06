package com.wisebrains.iam;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ClientAddressResolverTest {
    @Test
    void ignoresForwardedAddressFromUntrustedPeer() {
        ClientAddressResolver resolver = new ClientAddressResolver("10.0.0.2");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("198.51.100.10");
        request.addHeader("X-Forwarded-For", "203.0.113.1");

        assertEquals("198.51.100.10", resolver.resolve(request));
    }

    @Test
    void usesForwardedAddressOnlyFromConfiguredProxy() {
        ClientAddressResolver resolver = new ClientAddressResolver("10.0.0.2");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("10.0.0.2");
        request.addHeader("X-Forwarded-For", "203.0.113.1, 10.0.0.2");

        assertEquals("203.0.113.1", resolver.resolve(request));
    }
}
