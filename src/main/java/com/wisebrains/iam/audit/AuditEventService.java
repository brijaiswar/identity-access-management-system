package com.wisebrains.iam.audit;

import com.wisebrains.iam.model.AuditEvent;
import com.wisebrains.iam.model.User;
import com.wisebrains.iam.security.ClientAddressResolver;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuditEventService {
    private final AuditEventRepository repository;
    private final ClientAddressResolver clientAddressResolver;

    public AuditEventService(AuditEventRepository repository, ClientAddressResolver clientAddressResolver) {
        this.repository = repository;
        this.clientAddressResolver = clientAddressResolver;
    }

    @Transactional
    public void record(String type, User actor, String actorName, Long targetUserId, HttpServletRequest request) {
        String sourceIp = limit(clientAddressResolver.resolve(request), 64);
        String userAgent = request == null ? null : limit(request.getHeader("User-Agent"), 512);
        repository.save(new AuditEvent(java.time.Instant.now(), type,
                actor == null ? null : actor.getId(),
                actor == null ? limit(actorName, 128) : limit(actor.getUsername(), 128),
                targetUserId, sourceIp, userAgent));
    }

    @Transactional
    public void record(String type, User actor, String actorName, Long targetUserId) {
        record(type, actor, actorName, targetUserId, null);
    }

    @Transactional
    public void recordTarget(String type, String actorName, String targetType, String targetId) {
        repository.save(new AuditEvent(java.time.Instant.now(), type, null, limit(actorName, 128),
                null, limit(targetType, 32), limit(targetId, 128), null, null));
    }

    @Transactional(readOnly = true)
    public Page<AuditEvent> list(Pageable pageable) {
        return repository.findAllByOrderByOccurredAtDesc(pageable);
    }

    private String limit(String value, int length) {
        if (value == null) return null;
        return value.length() <= length ? value : value.substring(0, length);
    }
}
