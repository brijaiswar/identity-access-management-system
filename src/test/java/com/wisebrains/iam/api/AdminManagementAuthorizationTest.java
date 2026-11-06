package com.wisebrains.iam.api;

import com.wisebrains.iam.model.User;
import com.wisebrains.iam.model.AuditEvent;
import com.wisebrains.iam.audit.AuditEventRepository;
import com.wisebrains.iam.security.MfaSecretCipher;
import com.wisebrains.iam.user.UserRepository;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.mail.javamail.JavaMailSender;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import java.time.Instant;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AdminManagementAuthorizationTest {
    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuditEventRepository auditEventRepository;

    @Autowired
    private MfaSecretCipher mfaSecretCipher;

    @MockBean
    private JavaMailSender mailSender;

    @Test
    @WithMockUser(authorities = "READ_USER")
    void userPermissionCannotReadTheAdministrativeUserDirectory() throws Exception {
        mockMvc.perform(get("/api/admin/users"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(authorities = "READ_USER")
    void userPermissionCannotReadTheAuditTrail() throws Exception {
        mockMvc.perform(get("/api/admin/audit-events"))
                .andExpect(status().isForbidden())
                .andExpect(content().contentTypeCompatibleWith("application/problem+json"))
                .andExpect(jsonPath("$.status").value(403));
    }

    @Test
    @WithMockUser(authorities = "AUDIT_READ")
    void auditTrailRequiresItsSpecificPermission() throws Exception {
        mockMvc.perform(get("/api/admin/audit-events"))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(authorities = "AUDIT_READ")
    void auditTrailUsesTheExplicitVersionedResponseDto() throws Exception {
        String actorName = "audit-dto-" + java.util.UUID.randomUUID();
        auditEventRepository.save(new AuditEvent(Instant.now(), "DTO_CONTRACT_TEST",
                null, actorName, null, "127.0.0.1", "test-agent"));

        mockMvc.perform(get("/api/v1/admin/audit-events"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content[0].actorUsername").value(actorName))
                .andExpect(jsonPath("$.content[0].eventType").value("DTO_CONTRACT_TEST"))
                .andExpect(jsonPath("$.content[0].userAgent").value("test-agent"))
                .andExpect(jsonPath("$.size").isNumber())
                .andExpect(jsonPath("$.totalElements").isNumber())
                .andExpect(jsonPath("$.content[0].password").doesNotExist())
                .andExpect(jsonPath("$.content[0].credentialsVersion").doesNotExist());
    }

    @Test
    @WithMockUser(authorities = "USER_READ_ALL")
    void userDirectoryRequiresAndAcceptsItsSpecificPermission() throws Exception {
        mockMvc.perform(get("/api/admin/users"))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(authorities = "ROLE_MANAGE")
    void roleManagementCanCreateARoleFromKnownPermissions() throws Exception {
        mockMvc.perform(post("/api/admin/roles")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"name":"AUDITOR","permissions":["READ_USER"]}
                                """))
                .andExpect(status().isCreated());
    }

    @Test
    @WithMockUser(authorities = "USER_CREATE")
    void managedUsersAreCreatedWithOnlyTheDefaultUserRole() throws Exception {
        mockMvc.perform(post("/api/admin/users")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "username":"managed-user",
                                  "email":"managed-user@example.com",
                                  "password":"Strong-Password-123!"
                                }
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.roles[0]").value("USER"))
                .andExpect(jsonPath("$.password").doesNotExist());
    }

    @Test
    @WithMockUser(authorities = "USER_UPDATE")
    void lastEnabledAdministratorCannotBeDisabled() throws Exception {
        User administrator = userRepository.findByUsername("admin").orElseThrow();

        mockMvc.perform(patch("/api/admin/users/{id}/enabled", administrator.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"enabled":false}
                                """))
                .andExpect(status().isConflict());
    }

    @Test
    @WithMockUser(authorities = "USER_ASSIGN_ROLES")
    void lastEnabledAdministratorCannotLoseTheAdminRole() throws Exception {
        User administrator = userRepository.findByUsername("admin").orElseThrow();

        mockMvc.perform(put("/api/admin/users/{id}/roles", administrator.getId())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"roles":["USER"]}
                                """))
                .andExpect(status().isConflict());
    }

    @Test
    @WithMockUser(authorities = "USER_MFA_RESET")
    void administratorCanResetMfaAndRevokeExistingTokens() throws Exception {
        User administrator = userRepository.findByUsername("admin").orElseThrow();
        administrator.setMfaEnabled(true);
        administrator.setMfaSecret(mfaSecretCipher.encrypt("JBSWY3DPEHPK3PXP"));
        long credentialsVersion = administrator.getCredentialsVersion();
        userRepository.save(administrator);

        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .delete("/api/admin/users/{id}/mfa", administrator.getId()))
                .andExpect(status().isNoContent());

        User updated = userRepository.findById(administrator.getId()).orElseThrow();
        org.junit.jupiter.api.Assertions.assertFalse(updated.isMfaEnabled());
        org.junit.jupiter.api.Assertions.assertEquals(credentialsVersion + 1, updated.getCredentialsVersion());
    }

    @Test
    void administrativeEndpointsRequireAuthentication() throws Exception {
        mockMvc.perform(get("/api/admin/roles"))
                .andExpect(status().isUnauthorized());
    }
}
