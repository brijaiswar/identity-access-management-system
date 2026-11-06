package com.wisebrains.iam;

import java.time.Instant;

public record LoginSessionResponse(String id, Instant createdAt, Instant expiresAt, Instant lastUsedAt,
                                   String sourceIp, String userAgent) {
}
