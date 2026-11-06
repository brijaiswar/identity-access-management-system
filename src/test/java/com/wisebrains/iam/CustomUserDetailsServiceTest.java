package com.wisebrains.iam;

import com.wisebrains.iam.model.Permission;
import com.wisebrains.iam.model.Role;
import com.wisebrains.iam.model.User;
import com.wisebrains.iam.security.CustomUserDetailsService;
import com.wisebrains.iam.user.UserRepository;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CustomUserDetailsServiceTest {
    @Mock
    UserRepository userRepository;
    @InjectMocks
    CustomUserDetailsService service;

    @Test
    void mapsRolesAndPermissionsToAuthorities() {
        Role role = new Role("ADMIN");
        role.setPermissions(Set.of(new Permission("READ_USER", "user", "read")));
        User user = new User("alice", "encoded", "alice@example.com");
        user.setEmailVerified(true);
        user.setRoles(Set.of(role));
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(user));

        var details = service.loadUserByUsername("alice");

        assertEquals("encoded", details.getPassword());
        assertTrue(details.isEnabled());
        assertTrue(details.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ADMIN")));
        assertTrue(details.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("READ_USER")));
    }

    @Test
    void throwsWhenUserDoesNotExist() {
        when(userRepository.findByUsername("missing")).thenReturn(Optional.empty());

        assertThrows(UsernameNotFoundException.class, () -> service.loadUserByUsername("missing"));
    }
}
