package com.wisebrains.iam.bootstrap;

import com.wisebrains.iam.api.dto.AdminUserRequest;
import com.wisebrains.iam.model.Role;
import com.wisebrains.iam.model.User;
import com.wisebrains.iam.role.RoleRepository;
import com.wisebrains.iam.user.UserRepository;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class BootstrapAdminService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final SystemLockService systemLockService;
    private final Validator validator;

    public BootstrapAdminService(UserRepository userRepository,
                                 RoleRepository roleRepository,
                                 PasswordEncoder passwordEncoder,
                                 SystemLockService systemLockService,
                                 Validator validator) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.systemLockService = systemLockService;
        this.validator = validator;
    }

    @Transactional
    public void bootstrap(String username, String email, String password) {
        systemLockService.lockAdministration();

        if (userRepository.count() != 0) {
            throw new IllegalStateException("Administrator bootstrap is only allowed before the first user exists");
        }

        AdminUserRequest request = new AdminUserRequest();
        request.setUsername(username);
        request.setEmail(email);
        request.setPassword(password);
        Set<ConstraintViolation<AdminUserRequest>> violations = validator.validate(request);
        if (!violations.isEmpty()) {
            String reasons = violations.stream()
                    .map(violation -> violation.getPropertyPath() + " " + violation.getMessage())
                    .sorted()
                    .collect(Collectors.joining(", "));
            throw new IllegalArgumentException("Invalid bootstrap administrator configuration: " + reasons);
        }

        String normalizedUsername = username.trim().toLowerCase(Locale.ROOT);
        String normalizedEmail = email.trim().toLowerCase(Locale.ROOT);
        if (userRepository.existsByUsername(normalizedUsername) || userRepository.existsByEmail(normalizedEmail)) {
            throw new IllegalStateException("Bootstrap administrator conflicts with an existing user");
        }

        Role adminRole = roleRepository.findByName("ADMIN")
                .orElseThrow(() -> new IllegalStateException("Required ADMIN role is missing; apply database migrations"));
        User administrator = new User();
        administrator.setUsername(normalizedUsername);
        administrator.setEmail(normalizedEmail);
        administrator.setPassword(passwordEncoder.encode(password));
        administrator.setEnabled(true);
        administrator.setEmailVerified(true);
        administrator.setRoles(Set.of(adminRole));
        userRepository.save(administrator);
    }
}
