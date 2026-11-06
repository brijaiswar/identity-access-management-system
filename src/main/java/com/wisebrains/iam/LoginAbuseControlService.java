package com.wisebrains.iam;

import com.wisebrains.iam.model.LoginAttemptBucket;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.UnexpectedRollbackException;

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

    public LoginAbuseControlService(LoginAttemptBucketRepository repository,
                                    LoginAttemptBucketCreator creator,
                                    @Value("${iam.security.login.max-failures:5}") int maxFailures,
                                    @Value("${iam.security.login.window:PT15M}") Duration window,
                                    @Value("${iam.security.login.lock-duration:PT15M}") Duration lockDuration) {
        if (maxFailures < 1 || window.isNegative() || window.isZero()
                || lockDuration.isNegative() || lockDuration.isZero()) {
            throw new IllegalArgumentException("Invalid login abuse-control settings");
        }
        this.repository = repository;
        this.creator = creator;
        this.maxFailures = maxFailures;
        this.window = window;
        this.lockDuration = lockDuration;
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
