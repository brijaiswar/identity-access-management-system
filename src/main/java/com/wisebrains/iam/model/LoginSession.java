package com.wisebrains.iam.model;

import jakarta.persistence.*;

import java.time.Instant;

@Entity
@Table(name = "login_sessions", indexes = {
        @Index(name = "idx_login_sessions_user", columnList = "user_id"),
        @Index(name = "idx_login_sessions_expires_at", columnList = "expires_at")
})
public class LoginSession {
    @Id
    @Column(length = 36)
    private String id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "credentials_version", nullable = false)
    private long credentialsVersion;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "last_used_at", nullable = false)
    private Instant lastUsedAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(name = "source_ip", length = 64)
    private String sourceIp;

    @Column(name = "user_agent", length = 512)
    private String userAgent;

    protected LoginSession() {
    }

    public LoginSession(String id, User user, Instant now, Instant expiresAt, String sourceIp, String userAgent) {
        this.id = id;
        this.user = user;
        this.credentialsVersion = user.getCredentialsVersion();
        this.createdAt = now;
        this.expiresAt = expiresAt;
        this.lastUsedAt = now;
        this.sourceIp = sourceIp;
        this.userAgent = userAgent;
    }

    public String getId() { return id; }
    public User getUser() { return user; }
    public long getCredentialsVersion() { return credentialsVersion; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getExpiresAt() { return expiresAt; }
    public Instant getLastUsedAt() { return lastUsedAt; }
    public Instant getRevokedAt() { return revokedAt; }
    public String getSourceIp() { return sourceIp; }
    public String getUserAgent() { return userAgent; }
    public boolean isActiveAt(Instant now) {
        return revokedAt == null && expiresAt.isAfter(now) && user.isEnabled()
                && user.getCredentialsVersion() == credentialsVersion;
    }
    public void touch(Instant now) { this.lastUsedAt = now; }
    public void revoke(Instant now) { if (revokedAt == null) this.revokedAt = now; }
}
