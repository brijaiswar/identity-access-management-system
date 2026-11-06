package com.wisebrains.iam.auth;

import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class PasswordHasherTest {
    private final PasswordHasher hasher = new PasswordHasher();

    @Test
    void hashesAndVerifiesPasswordWithoutStoringPlainText() {
        String hash = hasher.hash("secret");

        assertNotEquals("secret", hash);
        assertTrue(hasher.verify("secret", hash));
        assertFalse(hasher.verify("wrong", hash));
    }

    @Test
    void generatesUniqueBase64Salt() {
        String first = hasher.generateSalt();
        String second = hasher.generateSalt();

        assertNotEquals(first, second);
        assertEquals(16, Base64.getDecoder().decode(first).length);
    }
}
