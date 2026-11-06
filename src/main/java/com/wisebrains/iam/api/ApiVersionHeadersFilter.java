package com.wisebrains.iam.api;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class ApiVersionHeadersFilter extends OncePerRequestFilter {
    private static final String VERSIONED_PREFIX = "/api/v1";
    private static final String AUTH_ALIAS_PREFIX = "/api/auth";
    private static final String ADMIN_ALIAS_PREFIX = "/api/admin";

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        String servletPath = request.getServletPath();
        if (isPath(servletPath, VERSIONED_PREFIX)
                || isPath(servletPath, AUTH_ALIAS_PREFIX)
                || isPath(servletPath, ADMIN_ALIAS_PREFIX)) {
            response.setHeader("API-Version", "1");
        }

        if (isPath(servletPath, AUTH_ALIAS_PREFIX) || isPath(servletPath, ADMIN_ALIAS_PREFIX)) {
            String canonicalPath = servletPath.replaceFirst("^/api/", "/api/v1/");
            response.setHeader(
                    "Link",
                    "<" + request.getContextPath() + canonicalPath + ">; rel=\"successor-version\"");
        }

        filterChain.doFilter(request, response);
    }

    private boolean isPath(String path, String prefix) {
        return path.equals(prefix) || path.startsWith(prefix + "/");
    }
}
