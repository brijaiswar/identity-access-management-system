package com.wisebrains.iam.api.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import org.springframework.data.domain.Page;

import java.util.List;

@Schema(description = "A page of audit events with stable pagination metadata")
public record AuditEventPageResponse(
        List<AuditEventResponse> content,
        int number,
        int size,
        long totalElements,
        int totalPages) {
    public static AuditEventPageResponse from(Page<AuditEventResponse> page) {
        return new AuditEventPageResponse(page.getContent(), page.getNumber(), page.getSize(),
                page.getTotalElements(), page.getTotalPages());
    }
}
