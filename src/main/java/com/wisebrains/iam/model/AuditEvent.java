package com.wisebrains.iam.model;

import jakarta.persistence.*;

import java.time.Instant;

@Entity
@Table(name = "audit_events", indexes = {
        @Index(name = "idx_audit_events_occurred_at", columnList = "occurred_at"),
        @Index(name = "idx_audit_events_actor", columnList = "actor_username")
})
public class AuditEvent {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "occurred_at", nullable = false)
    private Instant occurredAt;

    @Column(name = "event_type", nullable = false, length = 64)
    private String eventType;

    @Column(name = "actor_user_id")
    private Long actorUserId;

    @Column(name = "actor_username", length = 128)
    private String actorUsername;

    @Column(name = "target_user_id")
    private Long targetUserId;

    @Column(name = "target_type", length = 32)
    private String targetType;

    @Column(name = "target_id", length = 128)
    private String targetId;

    @Column(name = "source_ip", length = 64)
    private String sourceIp;

    @Column(name = "user_agent", length = 512)
    private String userAgent;

    protected AuditEvent() {
    }

    public AuditEvent(Instant occurredAt, String eventType, Long actorUserId, String actorUsername,
                      Long targetUserId, String sourceIp, String userAgent) {
        this(occurredAt, eventType, actorUserId, actorUsername, targetUserId,
                targetUserId == null ? null : "user",
                targetUserId == null ? null : targetUserId.toString(), sourceIp, userAgent);
    }

    public AuditEvent(Instant occurredAt, String eventType, Long actorUserId, String actorUsername,
                      Long targetUserId, String targetType, String targetId, String sourceIp, String userAgent) {
        this.occurredAt = occurredAt;
        this.eventType = eventType;
        this.actorUserId = actorUserId;
        this.actorUsername = actorUsername;
        this.targetUserId = targetUserId;
        this.targetType = targetType;
        this.targetId = targetId;
        this.sourceIp = sourceIp;
        this.userAgent = userAgent;
    }

    public Long getId() { return id; }
    public Instant getOccurredAt() { return occurredAt; }
    public String getEventType() { return eventType; }
    public Long getActorUserId() { return actorUserId; }
    public String getActorUsername() { return actorUsername; }
    public Long getTargetUserId() { return targetUserId; }
    public String getTargetType() { return targetType; }
    public String getTargetId() { return targetId; }
    public String getSourceIp() { return sourceIp; }
    public String getUserAgent() { return userAgent; }
}
