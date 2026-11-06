package com.wisebrains.iam.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Complete a password reset using a one-time email token")
public class PasswordResetRequest {
    @NotBlank
    @Size(max = 128)
    @Schema(example = "opaque-one-time-token", format = "password")
    private String token;

    @NotBlank
    @Size(min = 12, max = 128)
    @Schema(example = "use-a-unique-password", format = "password")
    private String newPassword;

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }
}
