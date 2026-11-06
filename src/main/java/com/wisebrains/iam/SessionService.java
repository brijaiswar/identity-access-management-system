package com.wisebrains.iam;

import com.wisebrains.iam.auth.TokenService;
import com.wisebrains.iam.model.LoginSession;
import com.wisebrains.iam.model.SessionRefreshToken;
import com.wisebrains.iam.model.User;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class SessionService {
    private final LoginSessionRepository sessionRepository;
    private final SessionRefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final TokenService tokenService;
    private final AuditEventService auditEventService;
    private final ClientAddressResolver clientAddressResolver;
    private final Duration refreshLifetime;
    private final SecureRandom secureRandom = new SecureRandom();

    public SessionService(LoginSessionRepository sessionRepository,
                          SessionRefreshTokenRepository refreshTokenRepository,
                          UserRepository userRepository,
                          TokenService tokenService,
                          AuditEventService auditEventService,
                          ClientAddressResolver clientAddressResolver,
                          @Value("${iam.security.session.refresh-lifetime:PT720H}") Duration refreshLifetime) {
        if (refreshLifetime.isNegative() || refreshLifetime.isZero()) {
            throw new IllegalArgumentException("Refresh-token lifetime must be positive");
        }
        this.sessionRepository = sessionRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
        this.tokenService = tokenService;
        this.auditEventService = auditEventService;
        this.clientAddressResolver = clientAddressResolver;
        this.refreshLifetime = refreshLifetime;
    }

    @Transactional
    public SessionTokenResult create(User user, HttpServletRequest request) {
        Instant now = Instant.now();
        LoginSession session = new LoginSession(UUID.randomUUID().toString(), user, now,
                now.plus(refreshLifetime), remoteAddress(request), userAgent(request));
        sessionRepository.save(session);
        String refreshToken = createRefreshToken(session, now);
        auditEventService.record("SESSION_CREATED", user, user.getUsername(), user.getId(), request);
        auditEventService.record("LOGIN_SUCCEEDED", user, user.getUsername(), user.getId(), request);
        return tokenResult(user, session, refreshToken);
    }

    @Transactional
    public Optional<SessionTokenResult> refresh(String rawToken, HttpServletRequest request) {
        if (rawToken == null || rawToken.isBlank()) return Optional.empty();
        Optional<SessionRefreshToken> found = refreshTokenRepository.findByHashForUpdate(TokenHash.sha256(rawToken));
        if (found.isEmpty()) return Optional.empty();

        SessionRefreshToken refreshToken = found.get();
        LoginSession session = refreshToken.getSession();
        Instant now = Instant.now();
        if (refreshToken.getConsumedAt() != null) {
            session.revoke(now);
            auditEventService.record("SESSION_REFRESH_REUSE_DETECTED", session.getUser(),
                    session.getUser().getUsername(), session.getUser().getId(), request);
            return Optional.empty();
        }
        if (!session.isActiveAt(now)) {
            session.revoke(now);
            refreshToken.consume(now);
            return Optional.empty();
        }

        refreshToken.consume(now);
        session.touch(now);
        String replacement = createRefreshToken(session, now);
        auditEventService.record("SESSION_REFRESHED", session.getUser(),
                session.getUser().getUsername(), session.getUser().getId(), request);
        return Optional.of(tokenResult(session.getUser(), session, replacement));
    }

    @Transactional(readOnly = true)
    public boolean isActive(String sessionId, String username) {
        if (sessionId == null || sessionId.isBlank()) return false;
        return sessionRepository.findById(sessionId)
                .filter(session -> session.getUser().getUsername().equals(username))
                .filter(session -> session.isActiveAt(Instant.now()))
                .isPresent();
    }

    @Transactional(readOnly = true)
    public List<LoginSessionResponse> listSessions(String username) {
        User user = findUser(username);
        return sessionRepository.findActiveForUser(user.getId(), Instant.now()).stream()
                .filter(session -> session.isActiveAt(Instant.now()))
                .map(session -> new LoginSessionResponse(session.getId(), session.getCreatedAt(),
                        session.getExpiresAt(), session.getLastUsedAt(), session.getSourceIp(), session.getUserAgent()))
                .toList();
    }

    @Transactional
    public void revoke(String username, String sessionId, HttpServletRequest request) {
        LoginSession session = sessionRepository.findOwnedById(findUser(username).getId(), sessionId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Session not found"));
        session.revoke(Instant.now());
        auditEventService.record("SESSION_REVOKED", session.getUser(), username, session.getUser().getId(), request);
    }

    @Transactional
    public void revokeCurrent(String sessionId, String username, HttpServletRequest request) {
        revoke(username, sessionId, request);
    }

    @Transactional
    public void revokeOthers(String username, String currentSessionId, HttpServletRequest request) {
        long userId = findUser(username).getId();
        Instant now = Instant.now();
        List<LoginSession> sessions = sessionRepository.findActiveForUser(userId, now);
        for (LoginSession session : sessions) {
            if (!session.getId().equals(currentSessionId)) {
                session.revoke(now);
                auditEventService.record("SESSION_REVOKED", session.getUser(), username,
                        session.getUser().getId(), request);
            }
        }
    }

    private User findUser(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
    }

    private String createRefreshToken(LoginSession session, Instant now) {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        String rawToken = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        refreshTokenRepository.save(new SessionRefreshToken(session, TokenHash.sha256(rawToken), now));
        return rawToken;
    }

    private SessionTokenResult tokenResult(User user, LoginSession session, String refreshToken) {
        return new SessionTokenResult(user, tokenService.generateJwt(user, session.getId()), refreshToken,
                tokenService.getExpirationMs() / 1000, session.getId(), session.getExpiresAt());
    }

    private String remoteAddress(HttpServletRequest request) {
        return limit(clientAddressResolver.resolve(request), 64);
    }

    private String userAgent(HttpServletRequest request) {
        return request == null ? null : limit(request.getHeader("User-Agent"), 512);
    }

    private String limit(String value, int length) {
        if (value == null) return null;
        return value.length() <= length ? value : value.substring(0, length);
    }
}
