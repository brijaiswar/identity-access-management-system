package com.wisebrains.iam.auth;

import com.wisebrains.iam.model.Role;
import com.wisebrains.iam.model.User;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class TokenServiceTest {
    private TokenService service;
    private User user;

    @BeforeEach
    void setUp() {
        service = new TokenService("identity-access-management-system-development-secret-key", 3600000);
        service.init();
        user = new User("alice", "hash", "alice@example.com");
        user.setId(7L);
        user.setRoles(Set.of(new Role("USER")));
    }

    @Test
    void generatesTokenThatValidatesAndContainsUsername() {
        String token = service.generateJwt(user);

        assertTrue(service.validateJwt(token));
        assertEquals("alice", service.getUsername(token));
    }

    @Test
    void rejectsBlankMalformedAndTamperedTokens() {
        String token = service.generateJwt(user);

        assertFalse(service.validateJwt(null));
        assertFalse(service.validateJwt(" "));
        assertFalse(service.validateJwt("not-a-jwt"));
        assertFalse(service.validateJwt(token + "tampered"));
    }

    @Test
    void rejectsUnsafeConfiguration() {
        assertThrows(IllegalArgumentException.class,
                () -> new TokenService("short-secret", 3600000));
        assertThrows(IllegalArgumentException.class,
                () -> new TokenService("identity-access-management-system-development-secret-key", 0));
    }
}
