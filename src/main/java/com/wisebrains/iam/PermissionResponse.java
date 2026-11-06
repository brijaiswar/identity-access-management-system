package com.wisebrains.iam;

public record PermissionResponse(Long id, String name, String resource, String action) {
}
