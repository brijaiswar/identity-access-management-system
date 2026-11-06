package com.wisebrains.iam.model;

import jakarta.persistence.*;

import java.time.Instant;

@Entity
@Table(name = "session_refresh_tokens", indexes = {
        @Index(name = "idx_session_refresh_tokens_session", columnList = "session_id")
})
public class SessionRefreshToken {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "session_id", nullable = false)
    private LoginSession session;

    @Column(name = "token_hash", nullable = false, unique = true, length = 64)
    private String tokenHash;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "consumed_at")
    private Instant consumedAt;

    protected SessionRefreshToken() {
    }

    public SessionRefreshToken(LoginSession session, String tokenHash, Instant createdAt) {
        this.session = session;
        this.tokenHash = tokenHash;
        this.createdAt = createdAt;
    }

    public Long getId() { return id; }
    public LoginSession getSession() { return session; }
    public String getTokenHash() { return tokenHash; }
    public Instant getConsumedAt() { return consumedAt; }
    public void consume(Instant now) { this.consumedAt = now; }
}
