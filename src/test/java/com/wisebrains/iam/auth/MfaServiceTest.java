package com.wisebrains.iam.auth;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class MfaServiceTest {
    private final MfaService service = new MfaService();

    @Test
    void generateSecretProducesDecodableRandomSecret() {
        String first = service.generateSecret();
        String second = service.generateSecret();

        assertNotEquals(first, second);
        assertEquals(20, java.util.Base64.getDecoder().decode(first).length);
    }

    @Test
    void generatedCodeIsAcceptedForCurrentTimeWindow() throws Exception {
        String secret = service.generateSecret();
        long now = System.currentTimeMillis() / 1000L;
        int code = service.generateTotp(secret, now);

        assertTrue(service.validateTotp(secret, code));
    }

    @Test
    void invalidCodeIsRejected() throws Exception {
        String secret = service.generateSecret();

        assertFalse(service.validateTotp(secret, 999999));
    }
}
