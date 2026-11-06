package com.wisebrains.iam;

import jakarta.validation.constraints.NotBlank;

public class MfaCodeRequest {
    @NotBlank
    private String code;

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }
}
