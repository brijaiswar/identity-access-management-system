package com.wisebrains.iam;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public class RegisterRequest {
    @NotBlank
    @jakarta.validation.constraints.Size(min = 3, max = 100)
    private String username;

    @NotBlank
    @Email
    private String email;

    @NotBlank
    @jakarta.validation.constraints.Size(min = 12, max = 128)
    private String password;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
