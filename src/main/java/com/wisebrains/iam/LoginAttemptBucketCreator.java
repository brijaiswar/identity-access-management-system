package com.wisebrains.iam;

import com.wisebrains.iam.model.LoginAttemptBucket;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Service
public class LoginAttemptBucketCreator {
    private final LoginAttemptBucketRepository repository;

    public LoginAttemptBucketCreator(LoginAttemptBucketRepository repository) {
        this.repository = repository;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void createIfMissing(String key) {
        if (!repository.existsById(key)) {
            repository.saveAndFlush(new LoginAttemptBucket(key, Instant.now()));
        }
    }
}
