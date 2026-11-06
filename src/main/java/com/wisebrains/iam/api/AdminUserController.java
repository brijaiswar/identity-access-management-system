package com.wisebrains.iam.api;

import com.wisebrains.iam.api.dto.AdminUserRequest;
import com.wisebrains.iam.api.dto.UserEnabledRequest;
import com.wisebrains.iam.api.dto.UserResponse;
import com.wisebrains.iam.api.dto.UserRolesRequest;
import com.wisebrains.iam.api.dto.PagedResponse;
import com.wisebrains.iam.user.AdminUserService;

import jakarta.validation.Valid;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping({"/api/v1/admin/users", "/api/admin/users"})
@SecurityRequirement(name = "bearerAuth")
@Tag(name = "User administration", description = "Permission-protected user and account administration")
public class AdminUserController {
    private final AdminUserService adminUserService;

    public AdminUserController(AdminUserService adminUserService) {
        this.adminUserService = adminUserService;
    }

    @GetMapping
    @PreAuthorize("hasAuthority('USER_READ_ALL')")
    @Operation(summary = "List users with pagination")
    @ApiResponse(responseCode = "default", description = "RFC 9457 problem response",
            content = @Content(mediaType = "application/problem+json",
                    schema = @Schema(implementation = org.springframework.http.ProblemDetail.class)))
    public PagedResponse<UserResponse> listUsers(@PageableDefault(size = 20) Pageable pageable) {
        return PagedResponse.from(adminUserService.listUsers(pageable));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('USER_READ_ALL')")
    @Operation(summary = "Get a user by ID")
    @ApiResponse(responseCode = "default", description = "RFC 9457 problem response",
            content = @Content(mediaType = "application/problem+json",
                    schema = @Schema(implementation = org.springframework.http.ProblemDetail.class)))
    public UserResponse getUser(@PathVariable long id) {
        return adminUserService.getUser(id);
    }

    @PostMapping
    @PreAuthorize("hasAuthority('USER_CREATE')")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Create a user with the default USER role")
    @ApiResponse(responseCode = "default", description = "RFC 9457 problem response",
            content = @Content(mediaType = "application/problem+json",
                    schema = @Schema(implementation = org.springframework.http.ProblemDetail.class)))
    public UserResponse createUser(@Valid @RequestBody AdminUserRequest request) {
        return adminUserService.createUser(request);
    }

    @PutMapping("/{id}/roles")
    @PreAuthorize("hasAuthority('USER_ASSIGN_ROLES')")
    @Operation(summary = "Replace a user's role assignments")
    @ApiResponse(responseCode = "default", description = "RFC 9457 problem response",
            content = @Content(mediaType = "application/problem+json",
                    schema = @Schema(implementation = org.springframework.http.ProblemDetail.class)))
    public UserResponse setRoles(@PathVariable long id, @Valid @RequestBody UserRolesRequest request) {
        return adminUserService.setRoles(id, request.getRoles());
    }

    @PatchMapping("/{id}/enabled")
    @PreAuthorize("hasAuthority('USER_UPDATE')")
    @Operation(summary = "Enable or disable a user account")
    @ApiResponse(responseCode = "default", description = "RFC 9457 problem response",
            content = @Content(mediaType = "application/problem+json",
                    schema = @Schema(implementation = org.springframework.http.ProblemDetail.class)))
    public UserResponse setEnabled(@PathVariable long id, @Valid @RequestBody UserEnabledRequest request) {
        return adminUserService.setEnabled(id, request.getEnabled());
    }

    @DeleteMapping("/{id}/mfa")
    @PreAuthorize("hasAuthority('USER_MFA_RESET')")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(summary = "Reset a user's MFA enrollment and recovery codes")
    @ApiResponse(responseCode = "default", description = "RFC 9457 problem response",
            content = @Content(mediaType = "application/problem+json",
                    schema = @Schema(implementation = org.springframework.http.ProblemDetail.class)))
    public void resetMfa(@PathVariable long id) {
        adminUserService.resetMfa(id);
    }
}
