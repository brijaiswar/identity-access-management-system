package com.wisebrains.iam;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class SystemLockService {
    private final JdbcTemplate jdbcTemplate;

    public SystemLockService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public void lockAdministration() {
        Integer lockId = jdbcTemplate.queryForObject(
                "SELECT id FROM iam_system_lock WHERE id = 1 FOR UPDATE",
                Integer.class);
        if (lockId == null) {
            throw new IllegalStateException("IAM administration lock is not initialized");
        }
    }
}
