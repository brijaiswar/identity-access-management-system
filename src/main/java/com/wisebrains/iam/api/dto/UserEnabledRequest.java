package com.wisebrains.iam.api.dto;

import jakarta.validation.constraints.NotNull;

public class UserEnabledRequest {
    @NotNull
    private Boolean enabled;

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }
}
