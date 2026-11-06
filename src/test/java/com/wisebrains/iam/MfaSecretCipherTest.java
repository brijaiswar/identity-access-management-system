package com.wisebrains.iam;

import com.wisebrains.iam.security.MfaSecretCipher;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class MfaSecretCipherTest {
    private static final String KEY = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
    private final MfaSecretCipher cipher = new MfaSecretCipher(KEY);

    @Test
    void encryptsSecretsWithAuthenticatedEncryption() {
        String secret = "JBSWY3DPEHPK3PXP";
        String encrypted = cipher.encrypt(secret);

        assertNotEquals(secret, encrypted);
        assertEquals(secret, cipher.decrypt(encrypted));
    }

    @Test
    void rejectsTamperedCiphertext() {
        String encrypted = cipher.encrypt("JBSWY3DPEHPK3PXP");
        String tampered = encrypted.substring(0, encrypted.length() - 1)
                + (encrypted.endsWith("A") ? "B" : "A");

        assertThrows(IllegalStateException.class, () -> cipher.decrypt(tampered));
    }
}
