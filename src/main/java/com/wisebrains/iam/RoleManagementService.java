package com.wisebrains.iam;

import com.wisebrains.iam.model.Permission;
import com.wisebrains.iam.model.Role;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class RoleManagementService {
    private static final Set<String> BUILT_IN_ROLES = Set.of("ADMIN", "USER");

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;

    public RoleManagementService(RoleRepository roleRepository, PermissionRepository permissionRepository) {
        this.roleRepository = roleRepository;
        this.permissionRepository = permissionRepository;
    }

    @Transactional(readOnly = true)
    public java.util.List<RoleResponse> listRoles() {
        return roleRepository.findAll().stream()
                .map(this::toResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    public java.util.List<PermissionResponse> listPermissions() {
        return permissionRepository.findAll().stream()
                .map(permission -> new PermissionResponse(permission.getId(), permission.getName(),
                        permission.getResource(), permission.getAction()))
                .toList();
    }

    @Transactional
    public RoleResponse createRole(RoleRequest request) {
        String name = normalize(request.getName());
        if (BUILT_IN_ROLES.contains(name)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Built-in role names are reserved");
        }
        if (roleRepository.findByName(name).isPresent()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Role already exists");
        }

        Role role = new Role(name);
        role.setPermissions(resolvePermissions(request.getPermissions()));
        return toResponse(roleRepository.save(role));
    }

    @Transactional
    public RoleResponse updateRole(long id, RoleRequest request) {
        Role role = roleRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Role not found"));
        if (BUILT_IN_ROLES.contains(role.getName())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Built-in roles cannot be modified");
        }

        String name = normalize(request.getName());
        if (BUILT_IN_ROLES.contains(name)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Built-in role names are reserved");
        }
        roleRepository.findByName(name)
                .filter(existing -> !existing.getId().equals(role.getId()))
                .ifPresent(existing -> {
                    throw new ResponseStatusException(HttpStatus.CONFLICT, "Role already exists");
                });

        role.setName(name);
        role.setPermissions(resolvePermissions(request.getPermissions()));
        return toResponse(roleRepository.save(role));
    }

    private Set<Permission> resolvePermissions(Set<String> permissionNames) {
        if (permissionNames == null || permissionNames.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "At least one permission is required");
        }
        Set<String> normalizedNames = permissionNames.stream()
                .map(this::normalize)
                .collect(Collectors.toSet());
        Set<Permission> permissions = new HashSet<>(permissionRepository.findAllByNameIn(normalizedNames));
        if (permissions.size() != normalizedNames.size()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "One or more requested permissions do not exist");
        }
        return permissions;
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    private RoleResponse toResponse(Role role) {
        return new RoleResponse(role.getId(), role.getName(),
                role.getPermissions().stream().map(Permission::getName).sorted().toList());
    }
}
