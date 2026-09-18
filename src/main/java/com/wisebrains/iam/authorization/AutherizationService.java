package com.wisebrains.iam.authorization;

import com.wisebrains.iam.model.Permission;
import com.wisebrains.iam.model.Role;
import com.wisebrains.iam.model.User;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
public class AutherizationService {
    public boolean isAuthorized(User user, String resource, String action) {
        if (user == null || user.getRoles() == null) {
            return false;
        }

        for (Role role : user.getRoles()) {
            Set<Permission> permissions = role.getPermissions();
            if (permissions == null) {
                continue;
            }

            for (Permission permission : permissions) {
                if (permission.getResource().equals(resource) && permission.getAction().equals(action)) {
                    return true;
                }
            }
        }
        return false;
    }
}

