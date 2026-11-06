package com.wisebrains.iam.model;

import jakarta.persistence.*;

import java.time.Instant;

@Entity
@Table(name = "login_attempt_buckets")
public class LoginAttemptBucket {
    @Id
    @Column(name = "bucket_key", length = 64)
    private String bucketKey;

    @Column(name = "window_started_at", nullable = false)
    private Instant windowStartedAt;

    @Column(name = "failed_attempts", nullable = false)
    private int failedAttempts;

    @Column(name = "blocked_until")
    private Instant blockedUntil;

    protected LoginAttemptBucket() {
    }

    public LoginAttemptBucket(String bucketKey, Instant now) {
        this.bucketKey = bucketKey;
        this.windowStartedAt = now;
    }

    public String getBucketKey() { return bucketKey; }
    public Instant getWindowStartedAt() { return windowStartedAt; }
    public int getFailedAttempts() { return failedAttempts; }
    public Instant getBlockedUntil() { return blockedUntil; }
    public boolean isBlockedAt(Instant now) { return blockedUntil != null && blockedUntil.isAfter(now); }

    public void recordFailure(Instant now, Instant windowStart, Instant lockUntil, int maxAttempts) {
        if ((blockedUntil != null && !blockedUntil.isAfter(now))
                || !windowStartedAt.isAfter(windowStart)) {
            windowStartedAt = now;
            failedAttempts = 1;
            blockedUntil = null;
        } else {
            failedAttempts++;
        }
        if (failedAttempts >= maxAttempts) blockedUntil = lockUntil;
    }

    public void clear() {
        failedAttempts = 0;
        blockedUntil = null;
    }
}
