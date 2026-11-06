package com.wisebrains.iam.api;

import com.wisebrains.iam.account.AccountLifecycleService;
import com.wisebrains.iam.api.dto.AuthRequest;
import com.wisebrains.iam.api.dto.EmailVerificationRequest;
import com.wisebrains.iam.api.dto.RegisterRequest;
import com.wisebrains.iam.audit.AuditEventService;
import com.wisebrains.iam.auth.AuthenticationService;
import com.wisebrains.iam.auth.TokenService;
import com.wisebrains.iam.model.Role;
import com.wisebrains.iam.model.User;
import com.wisebrains.iam.security.ClientAddressResolver;
import com.wisebrains.iam.security.LoginAbuseControlService;
import com.wisebrains.iam.session.SessionService;
import com.wisebrains.iam.user.UserService;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.mock.web.MockHttpServletRequest;
import java.time.Duration;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {
    @Mock
    AuthenticationService authenticationService;
    @Mock
    UserService userService;
    @Mock
    TokenService tokenService;
    @Mock
    AccountLifecycleService accountLifecycleService;
    @Mock
    SessionService sessionService;
    @Mock
    LoginAbuseControlService loginAbuseControlService;
    @Mock
    AuditEventService auditEventService;
    @Mock
    ClientAddressResolver clientAddressResolver;
    @InjectMocks
    AuthController controller;

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void registersAndReturnsCreatedAuthResponse() {
        RegisterRequest request = new RegisterRequest();
        User user = user("alice");
        when(clientAddressResolver.resolve(org.mockito.ArgumentMatchers.any())).thenReturn("127.0.0.1");
        when(loginAbuseControlService.recordEmailAction(null, "127.0.0.1")).thenReturn(Duration.ZERO);
        when(userService.register(request)).thenReturn(user);

        var response = controller.register(request, new MockHttpServletRequest());

        assertEquals(202, response.getStatusCode().value());
        assertEquals("Check your email to verify your account",
                ((com.wisebrains.iam.api.dto.RegistrationResponse) response.getBody()).message());
        org.mockito.Mockito.verify(accountLifecycleService).sendVerification(user);
    }

    @Test
    void throttlesEmailVerificationResendWithoutCallingEmailService() {
        EmailVerificationRequest request = new EmailVerificationRequest();
        request.setEmail("alice@example.com");
        MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        when(clientAddressResolver.resolve(servletRequest)).thenReturn("127.0.0.1");
        when(loginAbuseControlService.recordEmailAction("alice@example.com", "127.0.0.1"))
                .thenReturn(Duration.ofMinutes(5));

        var response = controller.resendEmailVerification(request, servletRequest);

        assertEquals(429, response.getStatusCode().value());
        assertTrue(response.getHeaders().containsKey("Retry-After"));
        verifyNoInteractions(accountLifecycleService);
    }

    @Test
    void loginReturnsUnauthorizedForInvalidCredentials() {
        AuthRequest request = new AuthRequest();
        request.setUsername("alice");
        request.setPassword("wrong");
        when(authenticationService.authenticate("alice", "wrong", null)).thenReturn(Optional.empty());
        when(loginAbuseControlService.blockedFor("alice", "127.0.0.1")).thenReturn(Duration.ZERO);
        when(loginAbuseControlService.recordFailure("alice", "127.0.0.1")).thenReturn(Duration.ZERO);
        when(clientAddressResolver.resolve(org.mockito.ArgumentMatchers.any())).thenReturn("127.0.0.1");

        assertEquals(401, controller.login(request, new MockHttpServletRequest()).getStatusCode().value());
    }

    @Test
    void throttledLoginReturnsRetryAfterWithoutCheckingCredentials() {
        AuthRequest request = new AuthRequest();
        request.setUsername("alice");
        request.setPassword("secret");
        MockHttpServletRequest servletRequest = new MockHttpServletRequest();
        when(clientAddressResolver.resolve(servletRequest)).thenReturn("127.0.0.1");
        when(loginAbuseControlService.blockedFor("alice", "127.0.0.1"))
                .thenReturn(Duration.ofSeconds(30));

        var response = controller.login(request, servletRequest);

        assertEquals(429, response.getStatusCode().value());
        assertTrue(response.getHeaders().containsKey("Retry-After"));
        org.mockito.Mockito.verifyNoInteractions(authenticationService);
    }

    @Test
    void validatesBearerTokenAndRejectsMissingHeader() {
        String token = "tok" + "en";

        when(tokenService.validateJwt(token)).thenReturn(true);
        when(tokenService.getUsername(token)).thenReturn("alice");
        when(tokenService.getCredentialsVersion(token)).thenReturn(0L);
        when(tokenService.getSessionId(token)).thenReturn("session-id");
        when(sessionService.isActive("session-id", "alice")).thenReturn(true);
        User user = user("alice");
        when(userService.findByUsername("alice")).thenReturn(user);
        assertEquals(Map.of("valid", true), controller.validate("Bearer " + token,
                new MockHttpServletRequest()).getBody());
        assertEquals(401, controller.validate(null, new MockHttpServletRequest()).getStatusCode().value());
        assertEquals(401, controller.validate("Basic token", new MockHttpServletRequest()).getStatusCode().value());
    }

    @Test
    void rejectsUnauthenticatedCurrentUserRequest() {
        SecurityContextHolder.clearContext();

        assertEquals(401, controller.getCurrentUser().getStatusCode().value());
        verifyNoInteractions(userService);
    }

    @Test
    void rejectsAnonymousCurrentUserRequest() {
        SecurityContextHolder.getContext().setAuthentication(
                new AnonymousAuthenticationToken("key", "anonymous",
                        List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_ANONYMOUS"))));

        assertEquals(401, controller.getCurrentUser().getStatusCode().value());
        verifyNoInteractions(userService);
    }

    @Test
    void returnsCurrentAuthenticatedUser() {
        User user = user("alice");
        user.setId(3L);
        when(userService.findByUsername("alice")).thenReturn(user);
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("alice", null, List.of()));

        var response = controller.getCurrentUser();

        assertEquals(200, response.getStatusCode().value());
        assertEquals("alice", response.getBody().getUsername());
        assertEquals(3L, response.getBody().getId());
    }

    private User user(String username) {
        User user = new User(username, "hash", username + "@example.com");
        user.setEmailVerified(true);
        user.setRoles(Set.of(new Role("USER")));
        return user;
    }
}
