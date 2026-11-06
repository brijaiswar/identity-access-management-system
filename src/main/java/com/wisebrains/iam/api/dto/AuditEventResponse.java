package com.wisebrains.iam.api.dto;

import com.wisebrains.iam.model.AuditEvent;
import io.swagger.v3.oas.annotations.media.Schema;

import java.time.Instant;

@Schema(description = "A recorded IAM security or administration event")
public record AuditEventResponse(
        @Schema(example = "42") Long id,
        @Schema(example = "2026-11-06T12:00:00Z") Instant occurredAt,
        @Schema(example = "LOGIN_SUCCEEDED") String eventType,
        Long actorUserId,
        String actorUsername,
        Long targetUserId,
        String targetType,
        String targetId,
        String sourceIp,
        String userAgent) {
    public static AuditEventResponse from(AuditEvent event) {
        return new AuditEventResponse(event.getId(), event.getOccurredAt(), event.getEventType(),
                event.getActorUserId(), event.getActorUsername(), event.getTargetUserId(),
                event.getTargetType(), event.getTargetId(), event.getSourceIp(), event.getUserAgent());
    }
}
