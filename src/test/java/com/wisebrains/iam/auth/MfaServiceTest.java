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
        assertEquals(32, first.length());
        assertTrue(first.matches("[A-Z2-7]+"));
    }

    @Test
    void acceptsLegacyBase64SecretsForExistingMfaAccounts() throws Exception {
        String legacySecret = java.util.Base64.getEncoder().encodeToString(new byte[20]);
        long now = System.currentTimeMillis() / 1000L;
        int code = service.generateTotp(legacySecret, now);

        assertTrue(service.validateTotp(legacySecret, code));
    }

    @Test
    void matchesRfc6238Sha1TestVector() throws Exception {
        String secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

        assertEquals(287082, service.generateTotp(secret, 59));
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
