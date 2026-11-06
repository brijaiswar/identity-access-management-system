package com.wisebrains.iam.api;

import com.wisebrains.iam.audit.AuditEventService;
import com.wisebrains.iam.api.dto.AuditEventResponse;
import com.wisebrains.iam.api.dto.AuditEventPageResponse;

import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.security.access.prepost.PreAuthorize;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping({"/api/v1/admin/audit-events", "/api/admin/audit-events"})
@SecurityRequirement(name = "bearerAuth")
@Tag(name = "Audit", description = "Read-only access to paginated security and administration events")
public class AdminAuditController {
    private final AuditEventService auditEventService;

    public AdminAuditController(AuditEventService auditEventService) {
        this.auditEventService = auditEventService;
    }

    @GetMapping
    @PreAuthorize("hasAuthority('AUDIT_READ')")
    @Operation(summary = "List audit events with pagination",
            responses = @ApiResponse(responseCode = "200", description = "Page of audit event response DTOs",
                    content = @Content(schema = @Schema(implementation = AuditEventPageResponse.class))))
    @ApiResponse(responseCode = "default", description = "RFC 9457 problem response",
            content = @Content(mediaType = "application/problem+json",
                    schema = @Schema(implementation = org.springframework.http.ProblemDetail.class)))
    public ResponseEntity<AuditEventPageResponse> listEvents(
            @PageableDefault(size = 50) Pageable pageable) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(AuditEventPageResponse.from(
                        auditEventService.list(pageable).map(AuditEventResponse::from)));
    }
}
