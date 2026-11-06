package com.wisebrains.iam.api.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Public account registration request")
public class RegisterRequest {
    @NotBlank
    @jakarta.validation.constraints.Size(min = 3, max = 100)
    @Schema(example = "alice")
    private String username;

    @NotBlank
    @Email
    @Schema(example = "alice@example.com")
    private String email;

    @NotBlank
    @jakarta.validation.constraints.Size(min = 12, max = 128)
    @Schema(example = "use-a-unique-password", format = "password")
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
