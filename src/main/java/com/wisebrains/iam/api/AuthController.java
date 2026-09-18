package com.wisebrains.iam.api;

import com.wisebrains.iam.AuthRequest;
import com.wisebrains.iam.AuthResponse;
import com.wisebrains.iam.RegisterRequest;
import com.wisebrains.iam.UserResponse;
import com.wisebrains.iam.UserService;
import com.wisebrains.iam.auth.AuthenticationService;
import com.wisebrains.iam.auth.TokenService;
import com.wisebrains.iam.model.Role;
import com.wisebrains.iam.model.User;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AuthenticationService authenticationService;
    private final UserService userService;
    private final TokenService tokenService;

    public AuthController(AuthenticationService authenticationService, UserService userService, TokenService tokenService) {
        this.authenticationService = authenticationService;
        this.userService = userService;
        this.tokenService = tokenService;
    }

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        User user = userService.register(request);
        String token = authenticationService.issueToken(user);
        return ResponseEntity.status(HttpStatus.CREATED).body(buildAuthResponse(user, token));
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
        if (authentication == null || !authentication.isAuthenticated()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        User user = userService.findByUsername(authentication.getName());
        return ResponseEntity.ok(new UserResponse(user.getId(), user.getUsername(), user.getEmail(),
                user.getRoles().stream().map(Role::getName).toList()));
    }

    @PostMapping("/validate")
    public ResponseEntity<Map<String, Boolean>> validate(@RequestHeader(value = "Authorization", required = false) String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("valid", false));
        }

        String token = authorizationHeader.substring(7);
        boolean valid = tokenService.validateJwt(token);
        return ResponseEntity.ok(Map.of("valid", valid));
    }

    private AuthResponse buildAuthResponse(User user, String token) {
        List<String> roles = user.getRoles().stream().map(Role::getName).toList();
        return new AuthResponse(token, user.getUsername(), user.getEmail(), roles);
    }
}

