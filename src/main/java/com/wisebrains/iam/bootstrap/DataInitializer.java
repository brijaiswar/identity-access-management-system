package com.wisebrains.iam.bootstrap;

import com.wisebrains.iam.model.Permission;
import com.wisebrains.iam.model.Role;
import com.wisebrains.iam.model.User;
import com.wisebrains.iam.role.PermissionRepository;
import com.wisebrains.iam.role.RoleRepository;
import com.wisebrains.iam.user.UserRepository;

import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.context.annotation.Profile;

import java.util.Set;
import java.util.HashSet;
import java.util.List;

@Component
@Profile("!prod")
public class DataInitializer implements CommandLineRunner {
    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public DataInitializer(RoleRepository roleRepository,
                           PermissionRepository permissionRepository,
                           UserRepository userRepository,
                           PasswordEncoder passwordEncoder) {
        this.roleRepository = roleRepository;
        this.permissionRepository = permissionRepository;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        List<Permission> permissions = List.of(
                permission("READ_USER", "user", "read"),
                permission("WRITE_USER", "user", "write"),
                permission("DELETE_USER", "user", "delete"),
                permission("USER_READ_ALL", "users", "read"),
                permission("USER_CREATE", "users", "create"),
                permission("USER_UPDATE", "users", "update"),
                permission("USER_ASSIGN_ROLES", "users", "assign_roles"),
                permission("USER_MFA_RESET", "users", "mfa_reset"),
                permission("ROLE_READ", "roles", "read"),
                permission("ROLE_MANAGE", "roles", "manage"));

        Role adminRole = roleRepository.findByName("ADMIN").orElseGet(() -> roleRepository.save(new Role("ADMIN")));
        adminRole.setPermissions(new HashSet<>(permissions));
        roleRepository.save(adminRole);

        Permission readUser = permissions.get(0);
        Role userRole = roleRepository.findByName("USER").orElseGet(() -> roleRepository.save(new Role("USER")));
        userRole.setPermissions(Set.of(readUser));
        roleRepository.save(userRole);

        if (userRepository.findByUsername("admin").isEmpty()) {
            User admin = new User();
            admin.setUsername("admin");
            admin.setEmail("admin@wisebrains.com");
            admin.setPassword(passwordEncoder.encode("admin123"));
            admin.setEnabled(true);
            admin.setEmailVerified(true);
            admin.setRoles(Set.of(adminRole, userRole));
            userRepository.save(admin);
        }
    }

    private Permission permission(String name, String resource, String action) {
        return permissionRepository.findByName(name)
                .orElseGet(() -> permissionRepository.save(new Permission(name, resource, action)));
    }
}
