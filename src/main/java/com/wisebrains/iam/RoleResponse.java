package com.wisebrains.iam;

import java.util.List;

public record RoleResponse(Long id, String name, List<String> permissions) {
}
