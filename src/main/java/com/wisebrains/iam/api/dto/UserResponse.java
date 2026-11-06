package com.wisebrains.iam.api.dto;

import java.util.List;

public class UserResponse {
    private Long id;
    private String username;
    private String email;
    private List<String> roles;
    private boolean emailVerified;

    public UserResponse() {
    }

    public UserResponse(Long id, String username, String email, List<String> roles, boolean emailVerified) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.roles = roles;
        this.emailVerified = emailVerified;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

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

    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }

    public boolean isEmailVerified() {
        return emailVerified;
    }

    public void setEmailVerified(boolean emailVerified) {
        this.emailVerified = emailVerified;
    }
}
