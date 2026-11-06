package com.wisebrains.iam.audit;

import com.wisebrains.iam.model.AuditEvent;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuditEventRepository extends JpaRepository<AuditEvent, Long> {
    Page<AuditEvent> findAllByOrderByOccurredAtDesc(Pageable pageable);
}
