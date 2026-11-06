package com.wisebrains;

import org.junit.jupiter.api.Test;
import jakarta.servlet.RequestDispatcher;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@ActiveProfiles("test")
class IdentityAccessManagementSystemTest {
    @Autowired
    private MockMvc mockMvc;

    @Test
    void applicationContextLoads() {
        assertTrue(true);
    }

    @Test
    void servesGeneratedOpenApiDocument() throws Exception {
        mockMvc.perform(get("/v3/api-docs"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.info.title").value("Identity Access Management API"))
                .andExpect(jsonPath("$.info.version").value("1.0.0"))
                .andExpect(jsonPath("$.components.securitySchemes.bearerAuth.scheme").value("bearer"))
                .andExpect(jsonPath("$.paths['/api/v1/auth/me'].get.security[0].bearerAuth").exists())
                .andExpect(jsonPath("$.paths['/api/v1/auth/me'].get.summary")
                        .value("Get the authenticated user's profile"))
                .andExpect(jsonPath("$.paths['/api/v1/auth/me'].get.responses.default.content"
                        + "['application/problem+json'].schema").exists())
                .andExpect(jsonPath("$.paths['/api/v1/admin/audit-events'].get.summary")
                        .value("List audit events with pagination"))
                .andExpect(jsonPath("$.paths['/api/v1/admin/users'].get").exists())
                .andExpect(jsonPath("$.paths['/api/v1/admin/roles'].get").exists())
                .andExpect(jsonPath("$.components.schemas.AuditEventPageResponse").exists())
                .andExpect(jsonPath("$.components.schemas.AuditEventResponse").exists())
                .andExpect(jsonPath("$.paths['/api/auth/me']").doesNotExist());
    }

    @Test
    void servesCanonicalVersionedEmailVerificationPage() throws Exception {
        mockMvc.perform(get("/api/v1/auth/email/verify"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith("text/html"))
                .andExpect(header().string("Referrer-Policy", "no-referrer"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("Confirm email")));
    }

    @Test
    void returnsProblemDetailsForUnknownApiRoute() throws Exception {
        mockMvc.perform(get("/error")
                        .requestAttr(RequestDispatcher.ERROR_STATUS_CODE, 404)
                        .requestAttr(RequestDispatcher.ERROR_REQUEST_URI, "/api/v1/unknown"))
                .andExpect(status().isNotFound())
                .andExpect(content().contentTypeCompatibleWith("application/problem+json"))
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.detail").value("Resource not found"))
                .andExpect(jsonPath("$.instance").value("/api/v1/unknown"));
    }

    @Test
    void returnsProblemDetailsForUnauthenticatedProtectedRequest() throws Exception {
        mockMvc.perform(get("/api/v1/auth/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentTypeCompatibleWith("application/problem+json"))
                .andExpect(jsonPath("$.status").value(401))
                .andExpect(jsonPath("$.detail").value("Authentication is required"));
    }
}
