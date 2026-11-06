package com.wisebrains.iam;

import com.wisebrains.iam.auth.AuthenticationService;
import com.wisebrains.iam.AccountLifecycleService;
import com.wisebrains.iam.auth.TokenService;
import com.wisebrains.iam.model.User;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthenticationServiceTest {
    @Mock
    UserRepository userRepository;
    @Mock
    PasswordEncoder passwordEncoder;
    @Mock
    TokenService tokenService;
    @Mock
    AccountLifecycleService accountLifecycleService;
    @InjectMocks
    AuthenticationService service;

    @Test
    void authenticatesUserWithValidPassword() {
        User user = new User("alice", "encoded", "alice@example.com");
        user.setEmailVerified(true);
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("secret", "encoded")).thenReturn(true);

        assertEquals(Optional.of(user), service.authenticate("alice", "secret", null));
    }

    @Test
    void rejectsUnknownUserAndInvalidPassword() {
        when(userRepository.findByUsername("missing")).thenReturn(Optional.empty());
        assertTrue(service.authenticate("missing", "secret", null).isEmpty());

        User user = new User("alice", "encoded", "alice@example.com");
        user.setEmailVerified(true);
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches(anyString(), eq("encoded"))).thenReturn(false);
        assertTrue(service.authenticate("alice", "wrong", null).isEmpty());
    }

    @Test
    void rejectsDisabledUserEvenWithValidPassword() {
        User user = new User("alice", "encoded", "alice@example.com");
        user.setEmailVerified(true);
        user.setEnabled(false);
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(user));

        assertTrue(service.authenticate("alice", "secret", null).isEmpty());
        verifyNoInteractions(passwordEncoder);
    }

    @Test
    void requiresValidMfaForMfaEnabledUser() throws Exception {
        User user = new User("alice", "encoded", "alice@example.com");
        user.setEmailVerified(true);
        user.setMfaEnabled(true);
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("secret", "encoded")).thenReturn(true);
        when(accountLifecycleService.verifyMfaForAuthentication(user, "123456")).thenReturn(true);
        when(accountLifecycleService.verifyMfaForAuthentication(user, null)).thenReturn(false);
        when(accountLifecycleService.verifyMfaForAuthentication(user, "invalid")).thenReturn(false);

        assertEquals(Optional.of(user), service.authenticate("alice", "secret", "123456"));
        assertTrue(service.authenticate("alice", "secret", null).isEmpty());
        assertTrue(service.authenticate("alice", "secret", "invalid").isEmpty());
    }

    @Test
    void issuesTokenForUser() {
        User user = new User();
        when(tokenService.generateJwt(user)).thenReturn("token");

        assertEquals("token", service.issueToken(user));
    }
}
