package com.wisebrains.iam;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class ClientAddressResolver {
    private final Set<String> trustedProxies;

    public ClientAddressResolver(@Value("${iam.security.trusted-proxies:}") String configuredProxies) {
        this.trustedProxies = Arrays.stream(configuredProxies.split(","))
                .map(String::trim)
                .filter(value -> !value.isEmpty())
                .collect(Collectors.toUnmodifiableSet());
    }

    public String resolve(HttpServletRequest request) {
        if (request == null) return null;
        String peer = request.getRemoteAddr();
        if (peer == null || !trustedProxies.contains(peer)) return peer;

        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor == null || forwardedFor.isBlank()) return peer;
        String candidate = forwardedFor.split(",", 2)[0].trim();
        return isIpLiteral(candidate) ? candidate : peer;
    }

    private boolean isIpLiteral(String value) {
        if (value.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
            return Arrays.stream(value.split("\\."))
                    .allMatch(part -> Integer.parseInt(part) <= 255);
        }
        return value.contains(":") && value.matches("[0-9a-fA-F:.]+");
    }
}
