package com.wisebrains.iam;

import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class IamUserDetails extends org.springframework.security.core.userdetails.User {
    private static final long serialVersionUID = 1L;
    private final long credentialsVersion;

    public IamUserDetails(String username,
                          String password,
                          boolean enabled,
                          Collection<? extends GrantedAuthority> authorities,
                          long credentialsVersion) {
        super(username, password, enabled, true, true, true, authorities);
        this.credentialsVersion = credentialsVersion;
    }

    public long getCredentialsVersion() {
        return credentialsVersion;
    }
}
