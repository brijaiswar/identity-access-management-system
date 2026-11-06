package com.wisebrains.iam.api;

import com.wisebrains.iam.account.AccountLifecycleService;
import com.wisebrains.iam.api.dto.MfaCodeRequest;
import com.wisebrains.iam.api.dto.MfaDisableRequest;
import com.wisebrains.iam.api.dto.MfaEnrollmentRequest;
import com.wisebrains.iam.api.dto.MfaEnrollmentResponse;
import com.wisebrains.iam.api.dto.MessageResponse;
import com.wisebrains.iam.api.dto.PasswordChangeRequest;
import com.wisebrains.iam.api.dto.PasswordResetRequest;
import com.wisebrains.iam.api.dto.PasswordResetStartRequest;
import com.wisebrains.iam.api.dto.EmailVerificationConfirmRequest;
import com.wisebrains.iam.security.ClientAddressResolver;
import com.wisebrains.iam.security.LoginAbuseControlService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;

import java.util.List;
import java.time.Duration;

@RestController
@RequestMapping({"/api/v1/auth", "/api/auth"})
@Tag(name = "Account lifecycle", description = "Email verification, password recovery, and MFA management")
public class AccountLifecycleController {
    private final AccountLifecycleService accountLifecycleService;
    private final LoginAbuseControlService loginAbuseControlService;
    private final ClientAddressResolver clientAddressResolver;

    public AccountLifecycleController(AccountLifecycleService accountLifecycleService,
                                      LoginAbuseControlService loginAbuseControlService,
                                      ClientAddressResolver clientAddressResolver) {
        this.accountLifecycleService = accountLifecycleService;
        this.loginAbuseControlService = loginAbuseControlService;
        this.clientAddressResolver = clientAddressResolver;
    }

    @GetMapping("/email/verify")
    @Operation(summary = "Show a confirmation page for an email-verification link")
    @ApiResponse(responseCode = "200", description = "Confirmation page; no token is consumed by this GET",
            content = @Content(mediaType = "text/html", schema = @Schema(implementation = String.class)))
    @ApiResponse(responseCode = "default", description = "RFC 9457 problem response",
            content = @Content(mediaType = "application/problem+json",
                    schema = @Schema(implementation = org.springframework.http.ProblemDetail.class)))
    public ResponseEntity<String> emailVerificationPage() {
        String html = """
                <!doctype html>
                <html lang="en">
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>Verify your email</title>
                <h1>Email verification</h1>
                <p id="status">Confirm to verify your email address.</p>
                <button id="confirm" type="button">Confirm email</button>
                <script>
                const button = document.getElementById('confirm');
                const status = document.getElementById('status');
                button.addEventListener('click', async () => {
                  const token = new URLSearchParams(location.hash.slice(1)).get('token');
                  if (!token) {
                    status.textContent = 'This verification link is invalid or expired.';
                    button.disabled = true;
                    return;
                  }
                  button.disabled = true;
                  try {
                    const response = await fetch(location.pathname, {
                      method: 'POST',
                      headers: {'Content-Type': 'application/json'},
                      body: JSON.stringify({token})
                    });
                    status.textContent = response.ok
                      ? 'Your email address is verified.'
                      : 'This verification link is invalid or expired.';
                  } catch (_) {
                    status.textContent = 'Verification could not be completed. Please try again later.';
                    button.disabled = false;
                  }
                });
                </script>
                </html>
                """;
        return ResponseEntity.ok()
                .contentType(MediaType.TEXT_HTML)
                .cacheControl(CacheControl.noStore())
                .header("Referrer-Policy", "no-referrer")
                .header("Content-Security-Policy",
                        "default-src 'none'; script-src 'unsafe-inline'; connect-src 'self'; " +
                                "base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
                .header("X-Content-Type-Options", "nosniff")
                .body(html);
    }

    @PostMapping("/email/verify")
    @Operation(summary = "Confirm an email address using its one-time token")
    @ApiResponse(responseCode = "200", description = "Email address verified",
            content = @Content(schema = @Schema(implementation = MessageResponse.class)))
    @ApiResponse(responseCode = "default", description = "RFC 9457 problem response",
            content = @Content(mediaType = "application/problem+json",
                    schema = @Schema(implementation = org.springframework.http.ProblemDetail.class)))
    public ResponseEntity<MessageResponse> verifyEmail(
            @Valid @RequestBody EmailVerificationConfirmRequest request) {
        accountLifecycleService.verifyEmail(request.getToken());
        return ResponseEntity.ok().cacheControl(CacheControl.noStore())
                .body(new MessageResponse("Email address verified"));
    }

    @PostMapping("/password/forgot")
    @Operation(summary = "Request password-reset instructions without disclosing account existence")
    @ApiResponse(responseCode = "202", description = "Accepted; account existence is not disclosed",
            content = @Content(schema = @Schema(implementation = MessageResponse.class)))
    @ApiResponse(responseCode = "429", description = "Email action limit exceeded",
            content = @Content(mediaType = "application/problem+json",
                    schema = @Schema(implementation = org.springframework.http.ProblemDetail.class)))
    @ApiResponse(responseCode = "default", description = "RFC 9457 problem response",
            content = @Content(mediaType = "application/problem+json",
                    schema = @Schema(implementation = org.springframework.http.ProblemDetail.class)))
    public ResponseEntity<?> startPasswordReset(
            @Valid @RequestBody PasswordResetStartRequest request, HttpServletRequest servletRequest) {
        Duration blockedFor = loginAbuseControlService.recordEmailAction(
                request.getEmail(), clientAddressResolver.resolve(servletRequest));
        if (!blockedFor.isZero()) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                    .header(HttpHeaders.RETRY_AFTER, Long.toString(Math.max(1, blockedFor.toSeconds())))
                    .cacheControl(CacheControl.noStore())
                    .body(ApiProblemResponses.problem(HttpStatus.TOO_MANY_REQUESTS,
                            "Too many email actions; try again later", servletRequest));
        }
        accountLifecycleService.startPasswordReset(request.getEmail());
        return ResponseEntity.accepted()
                .cacheControl(CacheControl.noStore())
                .body(new MessageResponse("If the account exists, password reset instructions will be sent"));
    }

    @PostMapping("/password/reset")
    @Operation(summary = "Set a new password using a one-time reset token")
    @ApiResponse(responseCode = "200", description = "Password reset completed",
            content = @Content(schema = @Schema(implementation = MessageResponse.class)))
    @ApiResponse(responseCode = "default", description = "RFC 9457 problem response",
            content = @Content(mediaType = "application/problem+json",
                    schema = @Schema(implementation = org.springframework.http.ProblemDetail.class)))
    public ResponseEntity<MessageResponse> resetPassword(
            @Valid @RequestBody PasswordResetRequest request) {
        accountLifecycleService.resetPassword(request.getToken(), request.getNewPassword());
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(new MessageResponse("Password reset successfully"));
    }

    @PostMapping("/password/change")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Change the authenticated user's password")
    @ApiResponse(responseCode = "default", description = "RFC 9457 problem response",
            content = @Content(mediaType = "application/problem+json",
                    schema = @Schema(implementation = org.springframework.http.ProblemDetail.class)))
    public ResponseEntity<Void> changePassword(Authentication authentication,
                                               @Valid @RequestBody PasswordChangeRequest request) {
        accountLifecycleService.changePassword(authentication.getName(), request.getCurrentPassword(),
                request.getNewPassword(), request.getMfaCode());
        return ResponseEntity.noContent().cacheControl(CacheControl.noStore()).build();
    }

    @PostMapping("/mfa/enrollment")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Begin MFA enrollment after password reauthentication")
    @ApiResponse(responseCode = "default", description = "RFC 9457 problem response",
            content = @Content(mediaType = "application/problem+json",
                    schema = @Schema(implementation = org.springframework.http.ProblemDetail.class)))
    public ResponseEntity<MfaEnrollmentResponse> beginMfaEnrollment(
            Authentication authentication,
            @Valid @RequestBody MfaEnrollmentRequest request) {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(accountLifecycleService.beginMfaEnrollment(authentication.getName(), request.getCurrentPassword()));
    }

    @PostMapping("/mfa/enrollment/confirm")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Confirm MFA enrollment and return one-time recovery codes")
    @ApiResponse(responseCode = "default", description = "RFC 9457 problem response",
            content = @Content(mediaType = "application/problem+json",
                    schema = @Schema(implementation = org.springframework.http.ProblemDetail.class)))
    public ResponseEntity<List<String>> confirmMfaEnrollment(
            Authentication authentication,
            @Valid @RequestBody MfaCodeRequest request) {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(accountLifecycleService.confirmMfaEnrollment(authentication.getName(), request.getCode()));
    }

    @PostMapping("/mfa/recovery-codes")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Rotate MFA recovery codes")
    @ApiResponse(responseCode = "default", description = "RFC 9457 problem response",
            content = @Content(mediaType = "application/problem+json",
                    schema = @Schema(implementation = org.springframework.http.ProblemDetail.class)))
    public ResponseEntity<List<String>> regenerateMfaRecoveryCodes(
            Authentication authentication,
            @Valid @RequestBody MfaCodeRequest request) {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(accountLifecycleService.regenerateMfaRecoveryCodes(authentication.getName(), request.getCode()));
    }

    @DeleteMapping("/mfa")
    @SecurityRequirement(name = "bearerAuth")
    @Operation(summary = "Disable MFA after password and MFA reauthentication")
    @ApiResponse(responseCode = "default", description = "RFC 9457 problem response",
            content = @Content(mediaType = "application/problem+json",
                    schema = @Schema(implementation = org.springframework.http.ProblemDetail.class)))
    public ResponseEntity<Void> disableMfa(Authentication authentication,
                                            @Valid @RequestBody MfaDisableRequest request) {
        accountLifecycleService.disableMfa(authentication.getName(), request.getCurrentPassword(), request.getCode());
        return ResponseEntity.noContent().build();
    }
}
