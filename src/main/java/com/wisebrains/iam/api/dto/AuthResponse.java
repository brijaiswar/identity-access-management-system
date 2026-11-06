package com.wisebrains.iam.api.dto;

import java.util.List;
import java.time.Instant;
import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Access and refresh credentials returned after authentication or refresh")
public class AuthResponse {
    @Schema(description = "Short-lived bearer access token", example = "eyJhbGciOiJIUzI1NiJ9...")
    private String token;
    private String username;
    private String email;
    private List<String> roles;
    @Schema(description = "Opaque, single-use refresh token", example = "opaque-refresh-token")
    private String refreshToken;
    @Schema(description = "Access token lifetime in seconds", example = "3600")
    private long expiresIn;
    @Schema(description = "Identifier for the server-side session", example = "a18d4d69-5e64-4a6f-a466-17d20f7debd4")
    private String sessionId;
    private Instant refreshExpiresAt;

    public AuthResponse() {
    }

    public AuthResponse(String token, String username, String email, List<String> roles) {
        this.token = token;
        this.username = username;
        this.email = email;
        this.roles = roles;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public long getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(long expiresIn) {
        this.expiresIn = expiresIn;
    }

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    public Instant getRefreshExpiresAt() {
        return refreshExpiresAt;
    }

    public void setRefreshExpiresAt(Instant refreshExpiresAt) {
        this.refreshExpiresAt = refreshExpiresAt;
    }
}
