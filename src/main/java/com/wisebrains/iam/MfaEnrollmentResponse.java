package com.wisebrains.iam;

public record MfaEnrollmentResponse(String secret, String otpauthUri) {
}
