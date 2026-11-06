package com.wisebrains.iam;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.Duration;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(properties = "iam.security.login.max-failures=3")
@ActiveProfiles("test")
class LoginAbuseControlIntegrationTest {
    @Value("${iam.security.login.max-failures}")
    private int configuredMaxFailures;

    @Autowired
    private LoginAbuseControlService loginAbuseControlService;

    @Test
    void blocksRepeatedFailuresForTheAccountAndSource() {
        assertEquals(3, configuredMaxFailures);
        String suffix = UUID.randomUUID().toString();
        String username = "rate-limit-" + suffix;
        String sourceIp = "192.0.2.1";

        assertTrue(loginAbuseControlService.blockedFor(username, sourceIp).isZero());
        loginAbuseControlService.recordFailure(username, sourceIp);
        loginAbuseControlService.recordFailure(username, sourceIp);
        Duration blocked = loginAbuseControlService.recordFailure(username, sourceIp);

        assertTrue(blocked.compareTo(Duration.ZERO) > 0);
        assertTrue(loginAbuseControlService.blockedFor(username, sourceIp).compareTo(Duration.ZERO) > 0);
    }
}
