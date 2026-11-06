package com.wisebrains.iam;

import com.wisebrains.iam.model.User;

import java.time.Instant;

public record SessionTokenResult(User user, String accessToken, String refreshToken,
                                long expiresIn, String sessionId, Instant refreshExpiresAt) {
}
