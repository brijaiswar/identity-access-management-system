package com.wisebrains.iam.api;

import com.wisebrains.iam.*;
import com.wisebrains.iam.auth.AuthenticationService;
import com.wisebrains.iam.auth.TokenService;
import com.wisebrains.iam.model.Role;
import com.wisebrains.iam.model.User;
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

import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AuthenticationService authenticationService;
    private final UserService userService;
    private final TokenService tokenService;
    private final AccountLifecycleService accountLifecycleService;
    @Value("${iam.registration.enabled:true}")
    private boolean registrationEnabled = true;

    public AuthController(AuthenticationService authenticationService,
                          UserService userService,
                          TokenService tokenService,
                          AccountLifecycleService accountLifecycleService) {
        this.authenticationService = authenticationService;
        this.userService = userService;
        this.tokenService = tokenService;
        this.accountLifecycleService = accountLifecycleService;
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
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody AuthRequest request) {
        Optional<User> result = authenticationService.authenticate(request.getUsername(), request.getPassword(), request.getMfaCode());
        if (result.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        User user = result.get();
        return ResponseEntity.ok(buildAuthResponse(user, authenticationService.issueToken(user)));
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
                valid = user.isEnabled() && tokenService.getCredentialsVersion(token) == user.getCredentialsVersion();
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

    @PostMapping("/email/verification/resend")
    public ResponseEntity<Map<String, String>> resendEmailVerification(
            @Valid @RequestBody EmailVerificationRequest request) {
        accountLifecycleService.resendEmailVerification(request.getEmail());
        return ResponseEntity.accepted()
                .body(Map.of("message", "If the account requires verification, instructions will be sent"));
    }
}
