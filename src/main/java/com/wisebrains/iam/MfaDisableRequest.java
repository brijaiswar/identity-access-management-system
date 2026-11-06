package com.wisebrains.iam;

import jakarta.validation.constraints.NotBlank;

public class MfaDisableRequest {
    @NotBlank
    private String currentPassword;

    @NotBlank
    private String code;

    public String getCurrentPassword() {
        return currentPassword;
    }

    public void setCurrentPassword(String currentPassword) {
        this.currentPassword = currentPassword;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }
}
