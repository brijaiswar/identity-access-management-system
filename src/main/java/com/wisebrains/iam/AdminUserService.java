package com.wisebrains.iam;

import com.wisebrains.iam.model.Role;
import com.wisebrains.iam.model.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class AdminUserService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final SystemLockService systemLockService;
    private final AccountLifecycleService accountLifecycleService;

    public AdminUserService(UserRepository userRepository,
                            RoleRepository roleRepository,
                            PasswordEncoder passwordEncoder,
                            SystemLockService systemLockService,
                            AccountLifecycleService accountLifecycleService) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.systemLockService = systemLockService;
        this.accountLifecycleService = accountLifecycleService;
    }

    @Transactional(readOnly = true)
    public Page<UserResponse> listUsers(Pageable pageable) {
        return userRepository.findAll(pageable).map(this::toResponse);
    }

    @Transactional(readOnly = true)
    public UserResponse getUser(long id) {
        return toResponse(findUser(id));
    }

    @Transactional
    public UserResponse createUser(AdminUserRequest request) {
        String username = normalizeIdentity(request.getUsername());
        String email = normalizeIdentity(request.getEmail());
        if (userRepository.existsByUsername(username) || userRepository.existsByEmail(email)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Username or email already exists");
        }

        Role userRole = roleRepository.findByName("USER")
                .orElseThrow(() -> new IllegalStateException("Required USER role is missing; apply database migrations"));
        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setEnabled(true);
        user.setRoles(Set.of(userRole));
        User createdUser = userRepository.save(user);
        accountLifecycleService.sendVerification(createdUser);
        return toResponse(createdUser);
    }

    @Transactional
    public UserResponse setRoles(long id, Set<String> requestedRoleNames) {
        systemLockService.lockAdministration();
        User user = findUser(id);
        Set<Role> roles = resolveRoles(requestedRoleNames);

        boolean isRemovingAdmin = user.isEnabled()
                && hasRole(user, "ADMIN")
                && roles.stream().noneMatch(role -> role.getName().equals("ADMIN"));
        if (isRemovingAdmin && userRepository.countEnabledByRoleName("ADMIN") <= 1) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Cannot remove the last enabled administrator");
        }

        user.setRoles(roles);
        return toResponse(userRepository.save(user));
    }

    @Transactional
    public UserResponse setEnabled(long id, boolean enabled) {
        systemLockService.lockAdministration();
        User user = findUser(id);
        if (!enabled && user.isEnabled() && hasRole(user, "ADMIN")
                && userRepository.countEnabledByRoleName("ADMIN") <= 1) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Cannot disable the last enabled administrator");
        }
        if (user.isEnabled() != enabled) {
            user.setCredentialsVersion(user.getCredentialsVersion() + 1);
        }
        user.setEnabled(enabled);
        return toResponse(userRepository.save(user));
    }

    @Transactional
    public void resetMfa(long id) {
        accountLifecycleService.resetMfaByAdministrator(id);
    }

    private User findUser(long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
    }

    private Set<Role> resolveRoles(Set<String> roleNames) {
        if (roleNames == null || roleNames.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "At least one role is required");
        }
        Set<String> normalizedNames = roleNames.stream()
                .map(this::normalize)
                .collect(Collectors.toSet());
        Set<Role> roles = new HashSet<>(roleRepository.findAllByNameIn(normalizedNames));
        if (roles.size() != normalizedNames.size()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "One or more requested roles do not exist");
        }
        return roles;
    }

    private boolean hasRole(User user, String roleName) {
        return user.getRoles().stream().anyMatch(role -> role.getName().equals(roleName));
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    private String normalizeIdentity(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    private UserResponse toResponse(User user) {
        return new UserResponse(user.getId(), user.getUsername(), user.getEmail(),
                user.getRoles().stream().map(Role::getName).sorted().toList(), user.isEmailVerified());
    }
}
