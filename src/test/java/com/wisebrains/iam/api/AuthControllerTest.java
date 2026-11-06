package com.wisebrains.iam.api;

import com.wisebrains.iam.AuthRequest;
import com.wisebrains.iam.RegisterRequest;
import com.wisebrains.iam.UserService;
import com.wisebrains.iam.AccountLifecycleService;
import com.wisebrains.iam.auth.AuthenticationService;
import com.wisebrains.iam.auth.TokenService;
import com.wisebrains.iam.model.Role;
import com.wisebrains.iam.model.User;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
        when(userService.register(request)).thenReturn(user);

        var response = controller.register(request);

        assertEquals(202, response.getStatusCode().value());
        assertEquals("Check your email to verify your account", response.getBody().message());
        org.mockito.Mockito.verify(accountLifecycleService).sendVerification(user);
    }

    @Test
    void loginReturnsUnauthorizedForInvalidCredentials() {
        AuthRequest request = new AuthRequest();
        request.setUsername("alice");
        request.setPassword("wrong");
        when(authenticationService.authenticate("alice", "wrong", null)).thenReturn(Optional.empty());

        assertEquals(401, controller.login(request).getStatusCode().value());
    }

    @Test
    void validatesBearerTokenAndRejectsMissingHeader() {
        String token = "tok" + "en";

        when(tokenService.validateJwt(token)).thenReturn(true);
        when(tokenService.getUsername(token)).thenReturn("alice");
        when(tokenService.getCredentialsVersion(token)).thenReturn(0L);
        User user = user("alice");
        when(userService.findByUsername("alice")).thenReturn(user);
        assertEquals(Map.of("valid", true), controller.validate("Bearer " + token).getBody());
        assertEquals(401, controller.validate(null).getStatusCode().value());
        assertEquals(Map.of("valid", false), controller.validate("Basic token").getBody());
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
