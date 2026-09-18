package com.wisebrains.iam;

import com.wisebrains.iam.model.Permission;
import com.wisebrains.iam.model.Role;
import com.wisebrains.iam.model.User;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
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
        Permission readUser = permissionRepository.findByName("READ_USER").orElseGet(() ->
                permissionRepository.save(new Permission("READ_USER", "user", "read")));
        Permission writeUser = permissionRepository.findByName("WRITE_USER").orElseGet(() ->
                permissionRepository.save(new Permission("WRITE_USER", "user", "write")));
        Permission deleteUser = permissionRepository.findByName("DELETE_USER").orElseGet(() ->
                permissionRepository.save(new Permission("DELETE_USER", "user", "delete")));

        Role adminRole = roleRepository.findByName("ADMIN").orElseGet(() -> {
            Role role = new Role("ADMIN");
            role.setPermissions(Set.of(readUser, writeUser, deleteUser));
            return roleRepository.save(role);
        });

        Role userRole = roleRepository.findByName("USER").orElseGet(() -> {
            Role role = new Role("USER");
            role.setPermissions(Set.of(readUser));
            return roleRepository.save(role);
        });

        if (userRepository.findByUsername("admin").isEmpty()) {
            User admin = new User();
            admin.setUsername("admin");
            admin.setEmail("admin@wisebrains.com");
            admin.setPassword(passwordEncoder.encode("admin123"));
            admin.setEnabled(true);
            admin.setRoles(Set.of(adminRole, userRole));
            userRepository.save(admin);
        }
    }
}
