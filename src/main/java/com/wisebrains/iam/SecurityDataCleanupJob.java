package com.wisebrains.iam;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;

@Component
public class SecurityDataCleanupJob {
    private final LoginSessionRepository sessionRepository;
    private final LoginAttemptBucketRepository bucketRepository;
    private final Duration loginWindow;

    public SecurityDataCleanupJob(LoginSessionRepository sessionRepository,
                                  LoginAttemptBucketRepository bucketRepository,
                                  @Value("${iam.security.login.window:PT15M}") Duration loginWindow) {
        this.sessionRepository = sessionRepository;
        this.bucketRepository = bucketRepository;
        this.loginWindow = loginWindow;
    }

    @Scheduled(cron = "0 0 3 * * *")
    @Transactional
    public void cleanupExpiredSecurityData() {
        Instant now = Instant.now();
        sessionRepository.deleteExpiredOrOldRevoked(now.minus(Duration.ofDays(30)));
        bucketRepository.deleteInactiveBefore(now.minus(loginWindow), now);
    }
}
