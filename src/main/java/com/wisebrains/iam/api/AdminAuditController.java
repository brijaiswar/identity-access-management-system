package com.wisebrains.iam.api;

import com.wisebrains.iam.AuditEventService;
import com.wisebrains.iam.model.AuditEvent;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin/audit-events")
public class AdminAuditController {
    private final AuditEventService auditEventService;

    public AdminAuditController(AuditEventService auditEventService) {
        this.auditEventService = auditEventService;
    }

    @GetMapping
    @PreAuthorize("hasAuthority('AUDIT_READ')")
    public ResponseEntity<Page<AuditEvent>> listEvents(@PageableDefault(size = 50) Pageable pageable) {
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(auditEventService.list(pageable));
    }
}
