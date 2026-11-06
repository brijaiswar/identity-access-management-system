package com.wisebrains.iam.api.dto;

public record PermissionResponse(Long id, String name, String resource, String action) {
}
