package com.wisebrains.iam;

import jakarta.validation.constraints.NotBlank;

public class MfaEnrollmentRequest {
    @NotBlank
    private String currentPassword;

    public String getCurrentPassword() {
        return currentPassword;
    }

    public void setCurrentPassword(String currentPassword) {
        this.currentPassword = currentPassword;
    }
}
