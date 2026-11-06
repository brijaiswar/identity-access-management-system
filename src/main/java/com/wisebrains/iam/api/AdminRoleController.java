package com.wisebrains.iam.api;

import com.wisebrains.iam.api.dto.PermissionResponse;
import com.wisebrains.iam.api.dto.RoleRequest;
import com.wisebrains.iam.api.dto.RoleResponse;
import com.wisebrains.iam.role.RoleManagementService;

import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping({"/api/v1/admin", "/api/admin"})
@SecurityRequirement(name = "bearerAuth")
@Tag(name = "Role administration", description = "Manage roles and their assignable permissions")
public class AdminRoleController {
    private final RoleManagementService roleManagementService;

    public AdminRoleController(RoleManagementService roleManagementService) {
        this.roleManagementService = roleManagementService;
    }

    @GetMapping("/roles")
    @PreAuthorize("hasAuthority('ROLE_READ')")
    @Operation(summary = "List roles and their permissions")
    @ApiResponse(responseCode = "default", description = "RFC 9457 problem response",
            content = @Content(mediaType = "application/problem+json",
                    schema = @Schema(implementation = org.springframework.http.ProblemDetail.class)))
    public List<RoleResponse> listRoles() {
        return roleManagementService.listRoles();
    }

    @PostMapping("/roles")
    @PreAuthorize("hasAuthority('ROLE_MANAGE')")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Create a role")
    @ApiResponse(responseCode = "default", description = "RFC 9457 problem response",
            content = @Content(mediaType = "application/problem+json",
                    schema = @Schema(implementation = org.springframework.http.ProblemDetail.class)))
    public RoleResponse createRole(@Valid @RequestBody RoleRequest request) {
        return roleManagementService.createRole(request);
    }

    @PutMapping("/roles/{id}")
    @PreAuthorize("hasAuthority('ROLE_MANAGE')")
    @Operation(summary = "Replace a role's name and permissions")
    @ApiResponse(responseCode = "default", description = "RFC 9457 problem response",
            content = @Content(mediaType = "application/problem+json",
                    schema = @Schema(implementation = org.springframework.http.ProblemDetail.class)))
    public RoleResponse updateRole(@PathVariable long id, @Valid @RequestBody RoleRequest request) {
        return roleManagementService.updateRole(id, request);
    }

    @GetMapping("/permissions")
    @PreAuthorize("hasAuthority('ROLE_READ')")
    @Operation(summary = "List assignable permissions")
    @ApiResponse(responseCode = "default", description = "RFC 9457 problem response",
            content = @Content(mediaType = "application/problem+json",
                    schema = @Schema(implementation = org.springframework.http.ProblemDetail.class)))
    public List<PermissionResponse> listPermissions() {
        return roleManagementService.listPermissions();
    }
}
