package com.wisebrains.iam.api.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "A non-sensitive operation result message")
public record MessageResponse(@Schema(example = "If the account exists, instructions will be sent") String message) {
}
