package com.wisebrains.iam;

import com.wisebrains.iam.model.Role;
import com.wisebrains.iam.model.User;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class BootstrapAdminServiceTest {
    @Mock
    UserRepository userRepository;
    @Mock
    RoleRepository roleRepository;
    @Mock
    PasswordEncoder passwordEncoder;
    @Mock
    SystemLockService systemLockService;
    @Mock
    Validator validator;
    @InjectMocks
    BootstrapAdminService service;

    @Test
    void createsFirstAdministratorUsingTheSeededAdminRole() {
        Role adminRole = new Role("ADMIN");
        when(userRepository.count()).thenReturn(0L);
        when(validator.validate(any(AdminUserRequest.class))).thenReturn(Set.of());
        when(roleRepository.findByName("ADMIN")).thenReturn(Optional.of(adminRole));
        when(passwordEncoder.encode("Very-Strong-Password-123!")).thenReturn("encoded-password");

        assertDoesNotThrow(() -> service.bootstrap(
                "RootAdmin", "root@example.com", "Very-Strong-Password-123!"));

        verify(systemLockService).lockAdministration();
        verify(userRepository).save(any(User.class));
    }

    @Test
    void refusesToBootstrapWhenAnyUserAlreadyExists() {
        when(userRepository.count()).thenReturn(1L);

        assertThrows(IllegalStateException.class, () -> service.bootstrap(
                "RootAdmin", "root@example.com", "Very-Strong-Password-123!"));

        verify(systemLockService).lockAdministration();
    }
}
