package com.wisebrains.iam.security;

import com.wisebrains.iam.model.LoginAttemptBucket;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.UnexpectedRollbackException;
import org.springframework.transaction.annotation.Propagation;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;

@Service
public class LoginAbuseControlService {
    private final LoginAttemptBucketRepository repository;
    private final LoginAttemptBucketCreator creator;
    private final int maxFailures;
    private final Duration window;
    private final Duration lockDuration;
    private final int emailMaxRequests;
    private final Duration emailWindow;
    private final Duration emailBlockDuration;

    public LoginAbuseControlService(LoginAttemptBucketRepository repository,
                                    LoginAttemptBucketCreator creator,
                                    @Value("${iam.security.login.max-failures:5}") int maxFailures,
                                    @Value("${iam.security.login.window:PT15M}") Duration window,
                                    @Value("${iam.security.login.lock-duration:PT15M}") Duration lockDuration,
                                    @Value("${iam.security.email.max-requests:5}") int emailMaxRequests,
                                    @Value("${iam.security.email.window:PT1H}") Duration emailWindow,
                                    @Value("${iam.security.email.block-duration:PT1H}") Duration emailBlockDuration) {
        if (maxFailures < 1 || window.isNegative() || window.isZero()
                || lockDuration.isNegative() || lockDuration.isZero()
                || emailMaxRequests < 1 || emailWindow.isNegative() || emailWindow.isZero()
                || emailBlockDuration.isNegative() || emailBlockDuration.isZero()) {
            throw new IllegalArgumentException("Invalid login abuse-control settings");
        }
        this.repository = repository;
        this.creator = creator;
        this.maxFailures = maxFailures;
        this.window = window;
        this.lockDuration = lockDuration;
        this.emailMaxRequests = emailMaxRequests;
        this.emailWindow = emailWindow;
        this.emailBlockDuration = emailBlockDuration;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public Duration recordEmailAction(String email, String sourceIp) {
        Instant now = Instant.now();
        List<String> keys = java.util.stream.Stream.of(
                        key("email-action-email", email), key("email-action-ip", sourceIp))
                .distinct().sorted().toList();
        List<LoginAttemptBucket> buckets = keys.stream().map(this::loadForUpdate).toList();
        Duration remaining = buckets.stream()
                .filter(bucket -> bucket.isBlockedAt(now))
                .map(bucket -> Duration.between(now, bucket.getBlockedUntil()))
                .max(Duration::compareTo)
                .orElse(Duration.ZERO);
        if (!remaining.isZero()) {
            return remaining;
        }

        Instant windowStart = now.minus(emailWindow);
        Instant blockUntil = now.plus(emailBlockDuration);
        buckets.forEach(bucket -> bucket.recordRequest(now, windowStart, blockUntil, emailMaxRequests));
        repository.saveAll(buckets);
        return buckets.stream()
                .filter(bucket -> bucket.isBlockedAt(now))
                .map(bucket -> Duration.between(now, bucket.getBlockedUntil()))
                .max(Duration::compareTo)
                .orElse(Duration.ZERO);
    }

    @Transactional
    public Duration blockedFor(String username, String sourceIp) {
        Instant now = Instant.now();
        return withBuckets(username, sourceIp, buckets -> {
            Duration remaining = Duration.ZERO;
            for (LoginAttemptBucket bucket : buckets) {
                if (bucket.isBlockedAt(now)) {
                    Duration candidate = Duration.between(now, bucket.getBlockedUntil());
                    if (candidate.compareTo(remaining) > 0) remaining = candidate;
                } else if (!bucket.getWindowStartedAt().isAfter(now.minus(window))) {
                    bucket.clear();
                }
            }
            return remaining;
        });
    }

    @Transactional
    public Duration recordFailure(String username, String sourceIp) {
        Instant now = Instant.now();
        return withBuckets(username, sourceIp, buckets -> {
            Instant lockUntil = now.plus(lockDuration);
            buckets.forEach(bucket -> bucket.recordFailure(now, now.minus(window), lockUntil, maxFailures));
            Duration remaining = Duration.ZERO;
            for (LoginAttemptBucket bucket : buckets) {
                if (bucket.isBlockedAt(now)) {
                    Duration candidate = Duration.between(now, bucket.getBlockedUntil());
                    if (candidate.compareTo(remaining) > 0) remaining = candidate;
                }
            }
            return remaining;
        });
    }

    @Transactional
    public void recordSuccess(String username) {
        Instant now = Instant.now();
        LoginAttemptBucket bucket = loadForUpdate(key("username", username));
        if (!bucket.getWindowStartedAt().isAfter(now.minus(window))) bucket.clear();
        repository.save(bucket);
    }

    private Duration withBuckets(String username, String sourceIp,
                                 java.util.function.Function<List<LoginAttemptBucket>, Duration> operation) {
        List<String> keys = java.util.stream.Stream.of(key("username", username), key("ip", sourceIp))
                .distinct().sorted().toList();
        List<LoginAttemptBucket> buckets = keys.stream().map(this::loadForUpdate).toList();
        Duration result = operation.apply(buckets);
        repository.saveAll(buckets);
        return result;
    }

    private LoginAttemptBucket loadForUpdate(String key) {
        try {
            creator.createIfMissing(key);
        } catch (DataIntegrityViolationException | UnexpectedRollbackException duplicate) {
            // A concurrent request won the initial insert; load its row under a write lock.
        }
        return repository.findByKeyForUpdate(key)
                .orElseThrow(() -> new IllegalStateException("Login abuse-control bucket was not created"));
    }

    private String key(String type, String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest((type + ":" + (value == null ? "" : value.trim().toLowerCase(java.util.Locale.ROOT)))
                            .getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }
}
