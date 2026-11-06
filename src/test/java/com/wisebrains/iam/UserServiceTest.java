package com.wisebrains.iam;

import com.wisebrains.iam.model.Role;
import com.wisebrains.iam.model.User;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {
    @Mock
    UserRepository userRepository;
    @Mock
    RoleRepository roleRepository;
    @Mock
    PasswordEncoder passwordEncoder;
    @InjectMocks
    UserService service;

    @Test
    void registersUserWithEncodedPasswordAndDefaultRole() {
        RegisterRequest request = new RegisterRequest();
        request.setUsername("alice");
        request.setEmail("alice@example.com");
        request.setPassword("secret");
        Role role = new Role("USER");
        when(userRepository.existsByUsername("alice")).thenReturn(false);
        when(roleRepository.findByName("USER")).thenReturn(Optional.of(role));
        when(passwordEncoder.encode("secret")).thenReturn("encoded");
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        User result = service.register(request);

        assertEquals("alice", result.getUsername());
        assertEquals("alice@example.com", result.getEmail());
        assertEquals("encoded", result.getPassword());
        assertTrue(result.isEnabled());
        assertEquals(Set.of(role), result.getRoles());
    }

    @Test
    void createsRoleWhenDefaultRoleDoesNotExist() {
        RegisterRequest request = new RegisterRequest();
        request.setUsername("alice");
        request.setEmail("alice@example.com");
        request.setPassword("secret");
        when(roleRepository.findByName("USER")).thenReturn(Optional.empty());
        when(roleRepository.save(any(Role.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        User result = service.register(request);

        assertEquals("USER", result.getRoles().iterator().next().getName());
        verify(roleRepository).save(any(Role.class));
    }

    @Test
    void rejectsDuplicateUsernameAndThrowsForMissingUser() {
        RegisterRequest request = new RegisterRequest();
        request.setUsername("alice");
        request.setEmail("alice@example.com");
        when(userRepository.existsByUsername("alice")).thenReturn(true);
        assertThrows(IllegalArgumentException.class, () -> service.register(request));

        when(userRepository.findByUsername("missing")).thenReturn(Optional.empty());
        assertThrows(IllegalArgumentException.class, () -> service.findByUsername("missing"));
    }

    @Test
    void rejectsDuplicateEmail() {
        RegisterRequest request = new RegisterRequest();
        request.setUsername("alice");
        request.setEmail("alice@example.com");
        when(userRepository.existsByEmail("alice@example.com")).thenReturn(true);

        assertThrows(IllegalArgumentException.class, () -> service.register(request));
    }
}
