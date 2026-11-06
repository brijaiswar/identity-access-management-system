package com.wisebrains.iam.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;

import java.util.Set;

public class RoleRequest {
    @NotBlank
    @Pattern(regexp = "[A-Za-z][A-Za-z0-9_]{1,63}")
    private String name;

    @NotEmpty
    private Set<@NotBlank String> permissions;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Set<String> getPermissions() {
        return permissions;
    }

    public void setPermissions(Set<String> permissions) {
        this.permissions = permissions;
    }
}
