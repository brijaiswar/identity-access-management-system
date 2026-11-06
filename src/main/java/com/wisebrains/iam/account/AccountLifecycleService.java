package com.wisebrains.iam.account;

import com.wisebrains.iam.api.dto.MfaEnrollmentResponse;
import com.wisebrains.iam.audit.AuditEventService;
import com.wisebrains.iam.auth.MfaService;
import com.wisebrains.iam.model.AccountActionToken;
import com.wisebrains.iam.model.MfaRecoveryCode;
import com.wisebrains.iam.model.User;
import com.wisebrains.iam.security.MfaSecretCipher;
import com.wisebrains.iam.security.TokenHash;
import com.wisebrains.iam.user.UserRepository;

import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

@Service
public class AccountLifecycleService {
    private static final String EMAIL_VERIFICATION = "EMAIL_VERIFICATION";
    private static final String PASSWORD_RESET = "PASSWORD_RESET";
    private static final Duration EMAIL_VERIFICATION_LIFETIME = Duration.ofHours(24);
    private static final Duration PASSWORD_RESET_LIFETIME = Duration.ofMinutes(30);
    private static final int RECOVERY_CODE_COUNT = 10;
    private static final char[] RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".toCharArray();

    private final UserRepository userRepository;
    private final AccountActionTokenRepository actionTokenRepository;
    private final MfaRecoveryCodeRepository recoveryCodeRepository;
    private final PasswordEncoder passwordEncoder;
    private final AccountEmailService accountEmailService;
    private final MfaService mfaService;
    private final MfaSecretCipher mfaSecretCipher;
    private final AuditEventService auditEventService;
    private final SecureRandom secureRandom = new SecureRandom();

    public AccountLifecycleService(UserRepository userRepository,
                                   AccountActionTokenRepository actionTokenRepository,
                                   MfaRecoveryCodeRepository recoveryCodeRepository,
                                   PasswordEncoder passwordEncoder,
                                   AccountEmailService accountEmailService,
                                   MfaService mfaService,
                                   MfaSecretCipher mfaSecretCipher,
                                   AuditEventService auditEventService) {
        this.userRepository = userRepository;
        this.actionTokenRepository = actionTokenRepository;
        this.recoveryCodeRepository = recoveryCodeRepository;
        this.passwordEncoder = passwordEncoder;
        this.accountEmailService = accountEmailService;
        this.mfaService = mfaService;
        this.mfaSecretCipher = mfaSecretCipher;
        this.auditEventService = auditEventService;
    }

    @Transactional
    public void sendVerification(User user) {
        issueToken(user, EMAIL_VERIFICATION, EMAIL_VERIFICATION_LIFETIME,
                accountEmailService::sendVerification);
        auditEventService.record("EMAIL_VERIFICATION_SENT", user, user.getUsername(), user.getId());
    }

    @Transactional
    public void verifyEmail(String rawToken) {
        AccountActionToken token = consumeToken(rawToken, EMAIL_VERIFICATION);
        token.getUser().setEmailVerified(true);
        userRepository.save(token.getUser());
        auditEventService.record("EMAIL_VERIFIED", token.getUser(), token.getUser().getUsername(),
                token.getUser().getId());
    }

    @Transactional
    public void startPasswordReset(String email) {
        String normalizedEmail = normalizeEmail(email);
        Optional<User> user = userRepository.findByEmail(normalizedEmail);
        user.filter(User::isEnabled)
                .ifPresent(account -> {
                    issueToken(account, PASSWORD_RESET, PASSWORD_RESET_LIFETIME, accountEmailService::sendPasswordReset);
                    auditEventService.record("PASSWORD_RESET_REQUESTED", account, account.getUsername(), account.getId());
                });
    }

    @Transactional
    public void resetPassword(String rawToken, String newPassword) {
        AccountActionToken token = consumeToken(rawToken, PASSWORD_RESET);
        User user = token.getUser();
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setCredentialsVersion(user.getCredentialsVersion() + 1);
        userRepository.save(user);
        consumeOutstandingTokens(user, PASSWORD_RESET);
        auditEventService.record("PASSWORD_RESET", user, user.getUsername(), user.getId());
    }

    @Transactional
    public void changePassword(String username, String currentPassword, String newPassword, String mfaCode) {
        User user = findUserByUsername(username);
        verifyCurrentPassword(user, currentPassword);
        if (user.isMfaEnabled() && !verifyMfa(user, mfaCode)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid MFA code");
        }
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setCredentialsVersion(user.getCredentialsVersion() + 1);
        userRepository.save(user);
        consumeOutstandingTokens(user, PASSWORD_RESET);
        auditEventService.record("PASSWORD_CHANGED", user, user.getUsername(), user.getId());
    }

    @Transactional
    public boolean verifyMfaForAuthentication(User user, String code) {
        return user.isMfaEnabled() && verifyMfa(user, code);
    }

    @Transactional
    public void resendEmailVerification(String email) {
        userRepository.findByEmail(normalizeEmail(email))
                .filter(User::isEnabled)
                .filter(user -> !user.isEmailVerified())
                .ifPresent(this::sendVerification);
    }

    @Transactional
    public MfaEnrollmentResponse beginMfaEnrollment(String username, String currentPassword) {
        User user = findUserByUsername(username);
        verifyCurrentPassword(user, currentPassword);
        if (user.isMfaEnabled()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "MFA is already enabled");
        }

        String secret = mfaService.generateSecret();
        user.setPendingMfaSecret(mfaSecretCipher.encrypt(secret));
        user.setPendingMfaExpiresAt(Instant.now().plus(Duration.ofMinutes(10)));
        userRepository.save(user);
        auditEventService.record("MFA_ENROLLMENT_STARTED", user, user.getUsername(), user.getId());
        String label = user.getEmail() + "?issuer=Identity%20Access%20Management";
        String uri = "otpauth://totp/" + label + "&secret=" + secret + "&algorithm=SHA1&digits=6&period=30";
        return new MfaEnrollmentResponse(secret, uri);
    }

    @Transactional
    public List<String> confirmMfaEnrollment(String username, String code) {
        User user = findUserByUsername(username);
        if (user.isMfaEnabled() || user.getPendingMfaSecret() == null
                || user.getPendingMfaExpiresAt() == null
                || !user.getPendingMfaExpiresAt().isAfter(Instant.now())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "No MFA enrollment is pending");
        }
        String secret = mfaSecretCipher.decrypt(user.getPendingMfaSecret());
        if (!isValidTotp(secret, code)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid MFA code");
        }

        user.setMfaSecret(mfaSecretCipher.encrypt(secret));
        user.setPendingMfaSecret(null);
        user.setPendingMfaExpiresAt(null);
        user.setMfaEnabled(true);
        user.setCredentialsVersion(user.getCredentialsVersion() + 1);
        userRepository.save(user);
        auditEventService.record("MFA_ENROLLED", user, user.getUsername(), user.getId());
        return replaceRecoveryCodes(user);
    }

    @Transactional
    public List<String> regenerateMfaRecoveryCodes(String username, String code) {
        User user = findUserByUsername(username);
        if (!user.isMfaEnabled() || !verifyMfa(user, code)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid MFA code");
        }
        user.setCredentialsVersion(user.getCredentialsVersion() + 1);
        userRepository.save(user);
        auditEventService.record("MFA_RECOVERY_CODES_ROTATED", user, user.getUsername(), user.getId());
        return replaceRecoveryCodes(user);
    }

    @Transactional
    public void disableMfa(String username, String currentPassword, String code) {
        User user = findUserByUsername(username);
        verifyCurrentPassword(user, currentPassword);
        if (!user.isMfaEnabled() || !verifyMfa(user, code)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid MFA code");
        }
        user.setMfaEnabled(false);
        user.setMfaSecret(null);
        user.setPendingMfaSecret(null);
        user.setPendingMfaExpiresAt(null);
        user.setCredentialsVersion(user.getCredentialsVersion() + 1);
        userRepository.save(user);
        recoveryCodeRepository.deleteAllByUserId(user.getId());
        auditEventService.record("MFA_DISABLED", user, user.getUsername(), user.getId());
    }

    @Transactional
    public void resetMfaByAdministrator(long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
        user.setMfaEnabled(false);
        user.setMfaSecret(null);
        user.setPendingMfaSecret(null);
        user.setPendingMfaExpiresAt(null);
        user.setCredentialsVersion(user.getCredentialsVersion() + 1);
        userRepository.save(user);
        recoveryCodeRepository.deleteAllByUserId(user.getId());
        org.springframework.security.core.Authentication actor =
                org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
        auditEventService.record("MFA_RESET_BY_ADMIN", null,
                actor == null ? null : actor.getName(), user.getId());
    }

    private List<String> replaceRecoveryCodes(User user) {
        recoveryCodeRepository.deleteAllByUserId(user.getId());
        List<String> rawCodes = new ArrayList<>(RECOVERY_CODE_COUNT);
        for (int i = 0; i < RECOVERY_CODE_COUNT; i++) {
            String code = generateRecoveryCode();
            rawCodes.add(code);
            recoveryCodeRepository.save(new MfaRecoveryCode(user, TokenHash.sha256(normalizeRecoveryCode(code))));
        }
        return List.copyOf(rawCodes);
    }

    private boolean verifyMfa(User user, String code) {
        if (code == null || code.isBlank()) {
            return false;
        }
        String secret = mfaSecretCipher.decrypt(user.getMfaSecret());
        if (isValidTotp(secret, code)) {
            return true;
        }
        return recoveryCodeRepository.consumeIfUnused(
                user.getId(), TokenHash.sha256(normalizeRecoveryCode(code)), Instant.now()) == 1;
    }

    private boolean isValidTotp(String secret, String code) {
        if (code == null || !code.matches("\\d{6}")) {
            return false;
        }
        try {
            return mfaService.validateTotp(secret, Integer.parseInt(code));
        } catch (GeneralSecurityException | IllegalArgumentException exception) {
            return false;
        }
    }

    private void verifyCurrentPassword(User user, String currentPassword) {
        if (currentPassword == null || !passwordEncoder.matches(currentPassword, user.getPassword())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Current password is incorrect");
        }
    }

    private User findUserByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "User not found"));
    }

    private void issueToken(User user, String purpose, Duration lifetime, TokenEmailAction emailAction) {
        actionTokenRepository.deleteExpiredOrOldConsumed(Instant.now().minus(Duration.ofDays(30)));
        consumeOutstandingTokens(user, purpose);
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        String rawToken = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        actionTokenRepository.save(new AccountActionToken(user, TokenHash.sha256(rawToken), purpose,
                Instant.now().plus(lifetime)));
        emailAction.send(user.getEmail(), rawToken);
    }

    private AccountActionToken consumeToken(String rawToken, String purpose) {
        if (rawToken == null || rawToken.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired token");
        }
        AccountActionToken token = actionTokenRepository.findForUpdate(TokenHash.sha256(rawToken), purpose)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired token"));
        Instant now = Instant.now();
        if (token.getConsumedAt() != null || !token.getExpiresAt().isAfter(now)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid or expired token");
        }
        token.consume(now);
        return token;
    }

    private void consumeOutstandingTokens(User user, String purpose) {
        Instant now = Instant.now();
        actionTokenRepository.findAllByUserIdAndPurposeAndConsumedAtIsNull(user.getId(), purpose)
                .forEach(token -> token.consume(now));
    }

    private String generateRecoveryCode() {
        StringBuilder code = new StringBuilder(14);
        for (int i = 0; i < 12; i++) {
            if (i > 0 && i % 4 == 0) {
                code.append('-');
            }
            code.append(RECOVERY_ALPHABET[secureRandom.nextInt(RECOVERY_ALPHABET.length)]);
        }
        return code.toString();
    }

    private String normalizeRecoveryCode(String code) {
        return code.replace("-", "").trim().toUpperCase(Locale.ROOT);
    }

    private String normalizeEmail(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }

    @FunctionalInterface
    private interface TokenEmailAction {
        void send(String email, String rawToken);
    }
}
