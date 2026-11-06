package com.wisebrains.iam.api;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wisebrains.iam.auth.MfaService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AccountLifecycleIntegrationTest {
    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private MfaService mfaService;

    @MockBean
    private JavaMailSender mailSender;

    @Test
    void emailVerificationAndPasswordResetUseExpiringSingleUseTokens() throws Exception {
        String username = "lifecycle-" + UUID.randomUUID().toString().substring(0, 8);
        String email = username + "@example.com";
        register(username, email);

        login(username, "Initial-Password-123!", null, 401);

        String verificationToken = sentToken("/api/auth/email/verify?token=");
        mockMvc.perform(get("/api/auth/email/verify").param("token", verificationToken))
                .andExpect(status().isOk());
        String accessToken = login(username, "Initial-Password-123!", null, 200).get("token").asText();

        String forgotBody = """
                {"email":"%s"}
                """.formatted(email);
        mockMvc.perform(post("/api/auth/password/forgot")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(forgotBody))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.message").value(
                        "If the account exists, password reset instructions will be sent"));
        String resetToken = sentToken("/reset-password?token=");

        mockMvc.perform(post("/api/auth/password/forgot")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"email":"absent@example.com"}
                                """))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.message").value(
                        "If the account exists, password reset instructions will be sent"));

        mockMvc.perform(post("/api/auth/password/reset")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"token":"%s","newPassword":"Replacement-Password-456!"}
                                """.formatted(resetToken)))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/auth/password/reset")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"token":"%s","newPassword":"Another-Password-789!"}
                                """.formatted(resetToken)))
                .andExpect(status().isBadRequest());
        login(username, "Initial-Password-123!", null, 401);
        login(username, "Replacement-Password-456!", null, 200);
        mockMvc.perform(get("/api/auth/me").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void passwordChangeRevokesExistingJwtAndMfaRecoveryCodesAreOneTime() throws Exception {
        String username = "mfa-" + UUID.randomUUID().toString().substring(0, 8);
        registerAndVerify(username, username + "@example.com");
        String accessToken = login(username, "Initial-Password-123!", null, 200).get("token").asText();

        MvcResult enrollment = mockMvc.perform(post("/api/auth/mfa/enrollment")
                        .header("Authorization", "Bearer " + accessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"currentPassword":"Initial-Password-123!"}
                                """))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode enrollmentBody = objectMapper.readTree(enrollment.getResponse().getContentAsString());
        String secret = enrollmentBody.get("secret").asText();
        assertTrue(enrollmentBody.get("otpauthUri").asText().startsWith("otpauth://totp/"));

        String totp = currentTotp(secret);
        MvcResult recoveryResponse = mockMvc.perform(post("/api/auth/mfa/enrollment/confirm")
                        .header("Authorization", "Bearer " + accessToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"code":"%s"}
                                """.formatted(totp)))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode codes = objectMapper.readTree(recoveryResponse.getResponse().getContentAsString());
        assertEquals(10, codes.size());
        String recoveryCode = codes.get(0).asText();

        String recoveryLoginToken = login(username, "Initial-Password-123!", recoveryCode, 200)
                .get("token").asText();
        login(username, "Initial-Password-123!", recoveryCode, 401);

        mockMvc.perform(post("/api/auth/password/change")
                        .header("Authorization", "Bearer " + recoveryLoginToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "currentPassword":"Initial-Password-123!",
                                  "newPassword":"Changed-Password-789!",
                                  "mfaCode":"%s"
                                }
                                """.formatted(currentTotp(secret))))
                .andExpect(status().isNoContent());
        mockMvc.perform(get("/api/auth/me").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isUnauthorized());
        login(username, "Changed-Password-789!", currentTotp(secret), 200);
    }

    private void registerAndVerify(String username, String email) throws Exception {
        register(username, email);
        String verificationToken = sentToken("/api/auth/email/verify?token=");
        mockMvc.perform(get("/api/auth/email/verify").param("token", verificationToken))
                .andExpect(status().isOk());
    }

    private void register(String username, String email) throws Exception {
        reset(mailSender);
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "username":"%s",
                                  "email":"%s",
                                  "password":"Initial-Password-123!"
                                }
                                """.formatted(username, email)))
                .andExpect(status().isAccepted());
        verify(mailSender).send(any(SimpleMailMessage.class));
    }

    private String sentToken(String linkSuffix) throws Exception {
        org.mockito.ArgumentCaptor<SimpleMailMessage> message =
                org.mockito.ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(mailSender).send(message.capture());
        String text = message.getValue().getText();
        Matcher matcher = Pattern.compile(Pattern.quote(linkSuffix) + "([A-Za-z0-9_-]+)").matcher(text);
        assertTrue(matcher.find(), "The email should contain its opaque action token");
        org.mockito.Mockito.clearInvocations(mailSender);
        return matcher.group(1);
    }

    private JsonNode login(String username, String password, String mfaCode, int expectedStatus) throws Exception {
        String body = """
                {"username":"%s","password":"%s","mfaCode":%s}
                """.formatted(username, password, mfaCode == null ? "null" : "\"" + mfaCode + "\"");
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().is(expectedStatus))
                .andReturn();
        if (result.getResponse().getContentAsString().isBlank()) {
            return objectMapper.createObjectNode();
        }
        return objectMapper.readTree(result.getResponse().getContentAsString());
    }

    private String currentTotp(String secret) throws Exception {
        long epochSeconds = System.currentTimeMillis() / 1000L;
        return "%06d".formatted(mfaService.generateTotp(secret, epochSeconds));
    }
}
