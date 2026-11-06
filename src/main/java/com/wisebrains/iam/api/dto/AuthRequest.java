package com.wisebrains.iam.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Credentials and optional MFA/recovery code")
public class AuthRequest {
    @NotBlank
    @Size(max = 128)
    @Schema(example = "alice")
    private String username;

    @NotBlank
    @jakarta.validation.constraints.Size(max = 128)
    @Schema(example = "use-your-account-password", format = "password")
    private String password;

    @Size(max = 32)
    @Schema(description = "Six-digit TOTP or one-time recovery code", example = "123456")
    private String mfaCode;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getMfaCode() {
        return mfaCode;
    }

    public void setMfaCode(String mfaCode) {
        this.mfaCode = mfaCode;
    }
}
