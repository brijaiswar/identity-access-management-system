package com.wisebrains.iam.api;

import com.wisebrains.iam.AdminUserRequest;
import com.wisebrains.iam.AdminUserService;
import com.wisebrains.iam.UserEnabledRequest;
import com.wisebrains.iam.UserResponse;
import com.wisebrains.iam.UserRolesRequest;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin/users")
public class AdminUserController {
    private final AdminUserService adminUserService;

    public AdminUserController(AdminUserService adminUserService) {
        this.adminUserService = adminUserService;
    }

    @GetMapping
    @PreAuthorize("hasAuthority('USER_READ_ALL')")
    public Page<UserResponse> listUsers(@PageableDefault(size = 20) Pageable pageable) {
        return adminUserService.listUsers(pageable);
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('USER_READ_ALL')")
    public UserResponse getUser(@PathVariable long id) {
        return adminUserService.getUser(id);
    }

    @PostMapping
    @PreAuthorize("hasAuthority('USER_CREATE')")
    @ResponseStatus(HttpStatus.CREATED)
    public UserResponse createUser(@Valid @RequestBody AdminUserRequest request) {
        return adminUserService.createUser(request);
    }

    @PutMapping("/{id}/roles")
    @PreAuthorize("hasAuthority('USER_ASSIGN_ROLES')")
    public UserResponse setRoles(@PathVariable long id, @Valid @RequestBody UserRolesRequest request) {
        return adminUserService.setRoles(id, request.getRoles());
    }

    @PatchMapping("/{id}/enabled")
    @PreAuthorize("hasAuthority('USER_UPDATE')")
    public UserResponse setEnabled(@PathVariable long id, @Valid @RequestBody UserEnabledRequest request) {
        return adminUserService.setEnabled(id, request.getEnabled());
    }
}
