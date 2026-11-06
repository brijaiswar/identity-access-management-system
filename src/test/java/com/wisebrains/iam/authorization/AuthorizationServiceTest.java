package com.wisebrains.iam.authorization;

import com.wisebrains.iam.model.Permission;
import com.wisebrains.iam.model.Role;
import com.wisebrains.iam.model.User;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthorizationServiceTest {
    private final AuthorizationService service = new AuthorizationService();

    @Test
    void authorizesMatchingPermission() {
        Permission permission = new Permission("READ_USER", "user", "read");
        Role role = new Role("USER");
        role.setPermissions(Set.of(permission));
        User user = new User();
        user.setRoles(Set.of(role));

        assertTrue(service.isAuthorized(user, "user", "read"));
        assertFalse(service.isAuthorized(user, "user", "delete"));
    }

    @Test
    void rejectsMissingUserRolesAndPermissions() {
        User user = new User();
        user.setRoles(null);
        assertFalse(service.isAuthorized(null, "user", "read"));
        assertFalse(service.isAuthorized(user, "user", "read"));

        Role role = new Role("EMPTY");
        role.setPermissions(null);
        user.setRoles(Set.of(role));
        assertFalse(service.isAuthorized(user, "user", "read"));
    }
}
