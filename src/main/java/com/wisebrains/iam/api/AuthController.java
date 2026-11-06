package com.wisebrains.iam.api;

import com.wisebrains.iam.*;
import com.wisebrains.iam.auth.AuthenticationService;
import com.wisebrains.iam.auth.TokenService;
import com.wisebrains.iam.model.Role;
import com.wisebrains.iam.model.User;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.bind.annotation.*;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.http.HttpHeaders;
import org.springframework.http.CacheControl;

import java.util.List;
import java.util.Map;
import java.time.Duration;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AuthenticationService authenticationService;
    private final UserService userService;
    private final TokenService tokenService;
    private final AccountLifecycleService accountLifecycleService;
    private final SessionService sessionService;
    private final LoginAbuseControlService loginAbuseControlService;
    private final AuditEventService auditEventService;
    private final ClientAddressResolver clientAddressResolver;
    @Value("${iam.registration.enabled:true}")
    private boolean registrationEnabled = true;

    public AuthController(AuthenticationService authenticationService,
                          UserService userService,
                          TokenService tokenService,
                          AccountLifecycleService accountLifecycleService,
                          SessionService sessionService,
                          LoginAbuseControlService loginAbuseControlService,
                          AuditEventService auditEventService,
                          ClientAddressResolver clientAddressResolver) {
        this.authenticationService = authenticationService;
        this.userService = userService;
        this.tokenService = tokenService;
        this.accountLifecycleService = accountLifecycleService;
        this.sessionService = sessionService;
        this.loginAbuseControlService = loginAbuseControlService;
        this.auditEventService = auditEventService;
        this.clientAddressResolver = clientAddressResolver;
    }

    @PostMapping("/register")
    @Transactional
    public ResponseEntity<RegistrationResponse> register(@Valid @RequestBody RegisterRequest request) {
        if (!registrationEnabled) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Registration is not available");
        }
        User user = userService.register(request);
        accountLifecycleService.sendVerification(user);
        return ResponseEntity.accepted()
                .body(new RegistrationResponse("Check your email to verify your account", user.getUsername()));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody AuthRequest request,
                                               HttpServletRequest servletRequest) {
        String sourceIp = clientAddressResolver.resolve(servletRequest);
        Duration blockedFor = loginAbuseControlService.blockedFor(request.getUsername(), sourceIp);
        if (!blockedFor.isZero()) {
            auditEventService.record("LOGIN_RATE_LIMITED", null, request.getUsername(), null, servletRequest);
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .header(HttpHeaders.RETRY_AFTER, Long.toString(Math.max(1, blockedFor.toSeconds())))
                    .build();
        }

        var result = authenticationService.authenticate(request.getUsername(), request.getPassword(), request.getMfaCode());
        if (result.isEmpty()) {
            Duration lockout = loginAbuseControlService.recordFailure(request.getUsername(), sourceIp);
            auditEventService.record("LOGIN_FAILED", null, request.getUsername(), null, servletRequest);
            ResponseEntity.BodyBuilder response = ResponseEntity.status(
                    lockout.isZero() ? HttpStatus.UNAUTHORIZED : HttpStatus.TOO_MANY_REQUESTS);
            if (!lockout.isZero()) {
                response.header(HttpHeaders.RETRY_AFTER, Long.toString(Math.max(1, lockout.toSeconds())));
            }
            return response.build();
        }

        User user = result.get();
        loginAbuseControlService.recordSuccess(user.getUsername());
        SessionTokenResult tokens = sessionService.create(user, servletRequest);
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(buildAuthResponse(user, tokens));
    }

    @GetMapping("/me")
    public ResponseEntity<UserResponse> getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null
                || !authentication.isAuthenticated()
                || authentication instanceof AnonymousAuthenticationToken) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        User user = userService.findByUsername(authentication.getName());
        return ResponseEntity.ok(new UserResponse(user.getId(), user.getUsername(), user.getEmail(),
                user.getRoles().stream().map(Role::getName).toList(), user.isEmailVerified()));
    }

    @PostMapping("/validate")
    public ResponseEntity<Map<String, Boolean>> validate(@RequestHeader(value = "Authorization", required = false) String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("valid", false));
        }

        String token = authorizationHeader.substring(7);
        boolean valid = tokenService.validateJwt(token);
        if (valid) {
            try {
                User user = userService.findByUsername(tokenService.getUsername(token));
                valid = user.isEnabled()
                        && tokenService.getCredentialsVersion(token) == user.getCredentialsVersion()
                        && sessionService.isActive(tokenService.getSessionId(token), user.getUsername());
            } catch (IllegalArgumentException exception) {
                valid = false;
            }
        }
        return ResponseEntity.ok(Map.of("valid", valid));
    }

    private AuthResponse buildAuthResponse(User user, String token) {
        List<String> roles = user.getRoles().stream().map(Role::getName).toList();
        return new AuthResponse(token, user.getUsername(), user.getEmail(), roles);
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshTokenRequest request,
                                                HttpServletRequest servletRequest) {
        return sessionService.refresh(request.getRefreshToken(), servletRequest)
                .map(tokens -> ResponseEntity.ok().cacheControl(CacheControl.noStore())
                        .body(buildAuthResponse(tokens.user(), tokens)))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.UNAUTHORIZED).build());
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(Authentication authentication, HttpServletRequest request) {
        String sessionId = currentSessionId(request);
        sessionService.revokeCurrent(sessionId, authentication.getName(), request);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/sessions")
    public ResponseEntity<List<LoginSessionResponse>> listSessions(Authentication authentication) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(sessionService.listSessions(authentication.getName()));
    }

    @DeleteMapping("/sessions/{id}")
    public ResponseEntity<Void> revokeSession(Authentication authentication, @PathVariable String id,
                                              HttpServletRequest request) {
        sessionService.revoke(authentication.getName(), id, request);
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/sessions/others")
    public ResponseEntity<Void> revokeOtherSessions(Authentication authentication, HttpServletRequest request) {
        sessionService.revokeOthers(authentication.getName(), currentSessionId(request), request);
        return ResponseEntity.noContent().build();
    }

    private String currentSessionId(HttpServletRequest request) {
        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }
        return tokenService.getSessionId(authorization.substring(7));
    }

    private AuthResponse buildAuthResponse(User user, SessionTokenResult tokens) {
        AuthResponse response = buildAuthResponse(user, tokens.accessToken());
        response.setRefreshToken(tokens.refreshToken());
        response.setExpiresIn(tokens.expiresIn());
        response.setSessionId(tokens.sessionId());
        response.setRefreshExpiresAt(tokens.refreshExpiresAt());
        return response;
    }

    @PostMapping("/email/verification/resend")
    public ResponseEntity<Map<String, String>> resendEmailVerification(
            @Valid @RequestBody EmailVerificationRequest request) {
        accountLifecycleService.resendEmailVerification(request.getEmail());
        return ResponseEntity.accepted()
                .body(Map.of("message", "If the account requires verification, instructions will be sent"));
    }
}
