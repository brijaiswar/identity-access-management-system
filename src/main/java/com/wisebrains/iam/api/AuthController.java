package com.wisebrains.iam.api;

import com.wisebrains.iam.account.AccountLifecycleService;
import com.wisebrains.iam.api.dto.AuthRequest;
import com.wisebrains.iam.api.dto.AuthResponse;
import com.wisebrains.iam.api.dto.EmailVerificationRequest;
import com.wisebrains.iam.api.dto.LoginSessionResponse;
import com.wisebrains.iam.api.dto.MessageResponse;
import com.wisebrains.iam.api.dto.RefreshTokenRequest;
import com.wisebrains.iam.api.dto.RegisterRequest;
import com.wisebrains.iam.api.dto.RegistrationResponse;
import com.wisebrains.iam.api.dto.UserResponse;
import com.wisebrains.iam.audit.AuditEventService;
import com.wisebrains.iam.auth.AuthenticationService;
import com.wisebrains.iam.auth.TokenService;
import com.wisebrains.iam.model.Role;
import com.wisebrains.iam.model.User;
import com.wisebrains.iam.security.ClientAddressResolver;
import com.wisebrains.iam.security.LoginAbuseControlService;
import com.wisebrains.iam.session.SessionService;
import com.wisebrains.iam.session.SessionTokenResult;
import com.wisebrains.iam.user.UserService;

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
import org.springframework.http.ProblemDetail;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;

import java.util.List;
import java.util.Map;
import java.time.Duration;

@RestController
@RequestMapping({"/api/v1/auth", "/api/auth"})
@Tag(name = "Authentication", description = "Registration, sign-in, tokens, sessions, and verification email")
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
    @Operation(summary = "Register an account and send email verification instructions",
            responses = {
                    @ApiResponse(responseCode = "202", description = "Registration accepted",
                            content = @Content(schema = @Schema(implementation = RegistrationResponse.class))),
                    @ApiResponse(responseCode = "default", description = "RFC 9457 problem response",
                            content = @Content(mediaType = "application/problem+json",
                                    schema = @Schema(implementation = org.springframework.http.ProblemDetail.class)))
            })
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request,
                                      HttpServletRequest servletRequest) {
        if (!registrationEnabled) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Registration is not available");
        }
        ResponseEntity<?> rateLimitResponse = emailActionRateLimit(request.getEmail(), servletRequest);
        if (rateLimitResponse != null) {
            return rateLimitResponse;
        }
        User user = userService.register(request);
        accountLifecycleService.sendVerification(user);
        return ResponseEntity.accepted().cacheControl(CacheControl.noStore())
                .body(new RegistrationResponse("Check your email to verify your account", user.getUsername()));
    }

    @PostMapping("/login")
    @Operation(summary = "Authenticate with password and optional MFA",
            responses = {
                    @ApiResponse(responseCode = "200", description = "Authentication succeeded",
                            content = @Content(schema = @Schema(implementation = AuthResponse.class))),
                    @ApiResponse(responseCode = "401", description = "Credentials are invalid",
                            content = @Content(mediaType = "application/problem+json",
                                    schema = @Schema(implementation = org.springframework.http.ProblemDetail.class))),
                    @ApiResponse(responseCode = "429", description = "Login attempts are rate limited",
                            content = @Content(mediaType = "application/problem+json",
                                    schema = @Schema(implementation = org.springframework.http.ProblemDetail.class))),
                    @ApiResponse(responseCode = "default", description = "RFC 9457 problem response",
                            content = @Content(mediaType = "application/problem+json",
                                    schema = @Schema(implementation = org.springframework.http.ProblemDetail.class)))
            })
    public ResponseEntity<?> login(@Valid @RequestBody AuthRequest request,
                                   HttpServletRequest servletRequest) {
        String sourceIp = clientAddressResolver.resolve(servletRequest);
        Duration blockedFor = loginAbuseControlService.blockedFor(request.getUsername(), sourceIp);
        if (!blockedFor.isZero()) {
            auditEventService.record("LOGIN_RATE_LIMITED", null, request.getUsername(), null, servletRequest);
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .contentType(org.springframework.http.MediaType.APPLICATION_PROBLEM_JSON)
                    .header(HttpHeaders.RETRY_AFTER, Long.toString(Math.max(1, blockedFor.toSeconds())))
                    .cacheControl(CacheControl.noStore())
                    .body(ApiProblemResponses.problem(HttpStatus.TOO_MANY_REQUESTS,
                            "Too many login attempts; try again later", servletRequest));
        }

        var result = authenticationService.authenticate(request.getUsername(), request.getPassword(), request.getMfaCode());
        if (result.isEmpty()) {
            Duration lockout = loginAbuseControlService.recordFailure(request.getUsername(), sourceIp);
            auditEventService.record("LOGIN_FAILED", null, request.getUsername(), null, servletRequest);
            HttpStatus status = lockout.isZero() ? HttpStatus.UNAUTHORIZED : HttpStatus.TOO_MANY_REQUESTS;
            ResponseEntity.BodyBuilder response = ResponseEntity.status(status)
                    .contentType(org.springframework.http.MediaType.APPLICATION_PROBLEM_JSON)
                    .cacheControl(CacheControl.noStore());
            if (!lockout.isZero()) {
                response.header(HttpHeaders.RETRY_AFTER, Long.toString(Math.max(1, lockout.toSeconds())));
            }
            return response.body(ApiProblemResponses.problem(status,
                    status == HttpStatus.UNAUTHORIZED
                            ? "Invalid username, password, or MFA code"
                            : "Too many login attempts; try again later",
                    servletRequest));
        }

        User user = result.get();
        loginAbuseControlService.recordSuccess(user.getUsername());
        SessionTokenResult tokens = sessionService.create(user, servletRequest);
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(buildAuthResponse(user, tokens));
    }

    @GetMapping("/me")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Get the authenticated user's profile")
    @ApiResponse(responseCode = "default", description = "RFC 9457 problem response",
            content = @Content(mediaType = "application/problem+json",
                    schema = @Schema(implementation = org.springframework.http.ProblemDetail.class)))
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
    @Operation(summary = "Check whether an access token is active")
    @ApiResponse(responseCode = "default", description = "RFC 9457 problem response",
            content = @Content(mediaType = "application/problem+json",
                    schema = @Schema(implementation = org.springframework.http.ProblemDetail.class)))
    public ResponseEntity<?> validate(@RequestHeader(value = "Authorization", required = false) String authorizationHeader,
                                      HttpServletRequest request) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            return ApiProblemResponses.response(HttpStatus.UNAUTHORIZED, "A bearer token is required", request);
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
    @Operation(summary = "Rotate a refresh token and issue a new access token",
            responses = {
                    @ApiResponse(responseCode = "200", description = "Tokens rotated",
                            content = @Content(schema = @Schema(implementation = AuthResponse.class))),
                    @ApiResponse(responseCode = "401", description = "Refresh token is invalid or expired",
                            content = @Content(mediaType = "application/problem+json",
                                    schema = @Schema(implementation = org.springframework.http.ProblemDetail.class)))
            })
    public ResponseEntity<?> refresh(@Valid @RequestBody RefreshTokenRequest request,
                                     HttpServletRequest servletRequest) {
        return sessionService.refresh(request.getRefreshToken(), servletRequest)
                .<ResponseEntity<?>>map(tokens -> ResponseEntity.ok().cacheControl(CacheControl.noStore())
                        .body(buildAuthResponse(tokens.user(), tokens)))
                .orElseGet(() -> ApiProblemResponses.response(
                        HttpStatus.UNAUTHORIZED, "Invalid or expired refresh token", servletRequest));
    }

    @PostMapping("/logout")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Revoke the current session")
    @ApiResponse(responseCode = "default", description = "RFC 9457 problem response",
            content = @Content(mediaType = "application/problem+json",
                    schema = @Schema(implementation = org.springframework.http.ProblemDetail.class)))
    public ResponseEntity<Void> logout(Authentication authentication, HttpServletRequest request) {
        String sessionId = currentSessionId(request);
        sessionService.revokeCurrent(sessionId, authentication.getName(), request);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/sessions")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "List the authenticated user's sessions")
    @ApiResponse(responseCode = "default", description = "RFC 9457 problem response",
            content = @Content(mediaType = "application/problem+json",
                    schema = @Schema(implementation = org.springframework.http.ProblemDetail.class)))
    public ResponseEntity<List<LoginSessionResponse>> listSessions(Authentication authentication) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(sessionService.listSessions(authentication.getName()));
    }

    @DeleteMapping("/sessions/{id}")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Revoke one of the authenticated user's sessions")
    @ApiResponse(responseCode = "default", description = "RFC 9457 problem response",
            content = @Content(mediaType = "application/problem+json",
                    schema = @Schema(implementation = org.springframework.http.ProblemDetail.class)))
    public ResponseEntity<Void> revokeSession(Authentication authentication, @PathVariable String id,
                                              HttpServletRequest request) {
        sessionService.revoke(authentication.getName(), id, request);
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/sessions/others")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Revoke all sessions except the current session")
    @ApiResponse(responseCode = "default", description = "RFC 9457 problem response",
            content = @Content(mediaType = "application/problem+json",
                    schema = @Schema(implementation = org.springframework.http.ProblemDetail.class)))
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
    @Operation(summary = "Resend email verification instructions")
    @ApiResponse(responseCode = "default", description = "RFC 9457 problem response",
            content = @Content(mediaType = "application/problem+json",
                    schema = @Schema(implementation = org.springframework.http.ProblemDetail.class)))
    @ApiResponse(responseCode = "202", description = "Accepted; account state is not disclosed",
            content = @Content(schema = @Schema(implementation = MessageResponse.class)))
    @ApiResponse(responseCode = "429", description = "Email action limit exceeded",
            content = @Content(mediaType = "application/problem+json",
                    schema = @Schema(implementation = org.springframework.http.ProblemDetail.class)))
    public ResponseEntity<?> resendEmailVerification(
            @Valid @RequestBody EmailVerificationRequest request, HttpServletRequest servletRequest) {
        ResponseEntity<?> rateLimitResponse = emailActionRateLimit(request.getEmail(), servletRequest);
        if (rateLimitResponse != null) {
            return rateLimitResponse;
        }
        accountLifecycleService.resendEmailVerification(request.getEmail());
        return ResponseEntity.accepted().cacheControl(CacheControl.noStore())
                .body(new MessageResponse("If the account requires verification, instructions will be sent"));
    }

    private ResponseEntity<?> emailActionRateLimit(String email, HttpServletRequest request) {
        Duration blockedFor = loginAbuseControlService.recordEmailAction(
                email, clientAddressResolver.resolve(request));
        if (blockedFor.isZero()) {
            return null;
        }
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .contentType(org.springframework.http.MediaType.APPLICATION_PROBLEM_JSON)
                .header(HttpHeaders.RETRY_AFTER, Long.toString(Math.max(1, blockedFor.toSeconds())))
                .cacheControl(CacheControl.noStore())
                .body(ApiProblemResponses.problem(HttpStatus.TOO_MANY_REQUESTS,
                        "Too many email actions; try again later", request));
    }
}
