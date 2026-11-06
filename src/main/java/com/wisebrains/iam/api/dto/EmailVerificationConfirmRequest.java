package com.wisebrains.iam.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "One-time email verification token")
public class EmailVerificationConfirmRequest {
    @NotBlank
    @Size(max = 128)
    @Schema(example = "opaque-one-time-token", format = "password")
    private String token;

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }
}
