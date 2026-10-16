package com.wisebrains.iam;

import com.wisebrains.iam.model.Role;
import com.wisebrains.iam.model.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository,
                       RoleRepository roleRepository,
                       PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public User register(RegisterRequest request) {
        String username = request.getUsername() == null ? null : request.getUsername().trim();
        String normalizedUsername = username == null ? null : username.toLowerCase(Locale.ROOT);
        String email = request.getEmail() == null ? null : request.getEmail().trim().toLowerCase(Locale.ROOT);
        String password = request.getPassword();

        if (userRepository.existsByUsername(normalizedUsername)) {
            throw new IllegalArgumentException("Username already exists");
        }
        if (userRepository.existsByEmail(email)) {
            throw new IllegalArgumentException("Email already exists");
        }

        Role userRole = roleRepository.findByName("USER")
                .orElseGet(() -> roleRepository.save(new Role("USER")));

        User user = new User();
        user.setUsername(normalizedUsername);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        user.setEnabled(true);
        Set<Role> roles = new HashSet<>();
        roles.add(userRole);
        user.setRoles(roles);
        return userRepository.save(user);
    }

    public User findByUsername(String username) {
        String normalizedUsername = username == null ? null : username.trim().toLowerCase(Locale.ROOT);
        return userRepository.findByUsername(normalizedUsername)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + normalizedUsername));
    }

    public Optional<User> findById(Long id) {
        return userRepository.findById(id);
    }
}
