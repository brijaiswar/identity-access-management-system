package com.wisebrains.iam.api.dto;

import java.util.List;

public record RoleResponse(Long id, String name, List<String> permissions) {
}
