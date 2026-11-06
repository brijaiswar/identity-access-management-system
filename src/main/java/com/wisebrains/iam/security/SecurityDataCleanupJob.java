package com.wisebrains.iam.security;

import com.wisebrains.iam.session.LoginSessionRepository;

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
    private final Duration bucketRetentionWindow;

    public SecurityDataCleanupJob(LoginSessionRepository sessionRepository,
                                  LoginAttemptBucketRepository bucketRepository,
                                  @Value("${iam.security.login.window:PT15M}") Duration loginWindow,
                                  @Value("${iam.security.email.window:PT1H}") Duration emailWindow) {
        this.sessionRepository = sessionRepository;
        this.bucketRepository = bucketRepository;
        this.bucketRetentionWindow = loginWindow.compareTo(emailWindow) >= 0 ? loginWindow : emailWindow;
    }

    @Scheduled(cron = "0 0 3 * * *")
    @Transactional
    public void cleanupExpiredSecurityData() {
        Instant now = Instant.now();
        sessionRepository.deleteExpiredOrOldRevoked(now.minus(Duration.ofDays(30)));
        bucketRepository.deleteInactiveBefore(now.minus(bucketRetentionWindow), now);
    }
}
