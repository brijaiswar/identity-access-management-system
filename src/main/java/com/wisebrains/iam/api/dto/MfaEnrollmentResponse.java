package com.wisebrains.iam.api.dto;

public record MfaEnrollmentResponse(String secret, String otpauthUri) {
}
