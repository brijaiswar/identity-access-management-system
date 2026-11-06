package com.wisebrains.iam.api;

import com.wisebrains.iam.AccountLifecycleService;
import com.wisebrains.iam.MfaCodeRequest;
import com.wisebrains.iam.MfaDisableRequest;
import com.wisebrains.iam.MfaEnrollmentRequest;
import com.wisebrains.iam.MfaEnrollmentResponse;
import com.wisebrains.iam.PasswordChangeRequest;
import com.wisebrains.iam.PasswordResetRequest;
import com.wisebrains.iam.PasswordResetStartRequest;
import jakarta.validation.Valid;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
public class AccountLifecycleController {
    private final AccountLifecycleService accountLifecycleService;

    public AccountLifecycleController(AccountLifecycleService accountLifecycleService) {
        this.accountLifecycleService = accountLifecycleService;
    }

    @GetMapping("/email/verify")
    public ResponseEntity<Map<String, String>> verifyEmail(@RequestParam String token) {
        accountLifecycleService.verifyEmail(token);
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(Map.of("message", "Email address verified"));
    }

    @PostMapping("/password/forgot")
    public ResponseEntity<Map<String, String>> startPasswordReset(
            @Valid @RequestBody PasswordResetStartRequest request) {
        accountLifecycleService.startPasswordReset(request.getEmail());
        return ResponseEntity.accepted()
                .cacheControl(CacheControl.noStore())
                .body(Map.of("message", "If the account exists, password reset instructions will be sent"));
    }

    @PostMapping("/password/reset")
    public ResponseEntity<Map<String, String>> resetPassword(@Valid @RequestBody PasswordResetRequest request) {
        accountLifecycleService.resetPassword(request.getToken(), request.getNewPassword());
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(Map.of("message", "Password reset successfully"));
    }

    @PostMapping("/password/change")
    public ResponseEntity<Void> changePassword(Authentication authentication,
                                               @Valid @RequestBody PasswordChangeRequest request) {
        accountLifecycleService.changePassword(authentication.getName(), request.getCurrentPassword(),
                request.getNewPassword(), request.getMfaCode());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/mfa/enrollment")
    public ResponseEntity<MfaEnrollmentResponse> beginMfaEnrollment(
            Authentication authentication,
            @Valid @RequestBody MfaEnrollmentRequest request) {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(accountLifecycleService.beginMfaEnrollment(authentication.getName(), request.getCurrentPassword()));
    }

    @PostMapping("/mfa/enrollment/confirm")
    public ResponseEntity<List<String>> confirmMfaEnrollment(
            Authentication authentication,
            @Valid @RequestBody MfaCodeRequest request) {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(accountLifecycleService.confirmMfaEnrollment(authentication.getName(), request.getCode()));
    }

    @PostMapping("/mfa/recovery-codes")
    public ResponseEntity<List<String>> regenerateMfaRecoveryCodes(
            Authentication authentication,
            @Valid @RequestBody MfaCodeRequest request) {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(accountLifecycleService.regenerateMfaRecoveryCodes(authentication.getName(), request.getCode()));
    }

    @DeleteMapping("/mfa")
    public ResponseEntity<Void> disableMfa(Authentication authentication,
                                            @Valid @RequestBody MfaDisableRequest request) {
        accountLifecycleService.disableMfa(authentication.getName(), request.getCurrentPassword(), request.getCode());
        return ResponseEntity.noContent().build();
    }
}
