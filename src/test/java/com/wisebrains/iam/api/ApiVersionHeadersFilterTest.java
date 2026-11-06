package com.wisebrains.iam.api;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class ApiVersionHeadersFilterTest {
    private final ApiVersionHeadersFilter filter = new ApiVersionHeadersFilter();

    @Test
    void identifiesCanonicalVersionedRoutes() throws Exception {
        MockHttpServletRequest request = request("/api/v1/auth/me");
        MockHttpServletResponse response = filter(request);

        assertEquals("1", response.getHeader("API-Version"));
        assertNull(response.getHeader("Link"));
    }

    @Test
    void pointsCompatibilityAliasesToEquivalentVersionedRouteWithoutCopyingQuery() throws Exception {
        MockHttpServletRequest request = request("/api/auth/me");
        request.setQueryString("token=do-not-copy");
        MockHttpServletResponse response = filter(request);

        assertEquals("1", response.getHeader("API-Version"));
        assertEquals("</iam/api/v1/auth/me>; rel=\"successor-version\"", response.getHeader("Link"));
    }

    @Test
    void ignoresPathsOutsideTheApiContract() throws Exception {
        MockHttpServletResponse response = filter(request("/api/authenticators/me"));

        assertNull(response.getHeader("API-Version"));
        assertNull(response.getHeader("Link"));
    }

    private MockHttpServletRequest request(String servletPath) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/iam" + servletPath);
        request.setContextPath("/iam");
        request.setServletPath(servletPath);
        return request;
    }

    private MockHttpServletResponse filter(MockHttpServletRequest request) throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = (servletRequest, servletResponse) -> { };
        filter.doFilter(request, response, chain);
        return response;
    }
}
