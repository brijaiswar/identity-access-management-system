package com.wisebrains.iam.api;

import com.wisebrains.iam.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK, properties = {
        "iam.security.email.max-requests=2",
        "iam.security.email.window=PT1H",
        "iam.security.email.block-duration=PT1H"
})
@AutoConfigureMockMvc
@ActiveProfiles("test")
class EmailActionRateLimitIntegrationTest {
    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @MockBean
    private JavaMailSender mailSender;

    @Test
    void sharesPersistentLimitAcrossPublicEmailActions() throws Exception {
        String email = "limit-" + UUID.randomUUID().toString().substring(0, 8) + "@example.com";
        String body = """
                {"email":"%s"}
                """.formatted(email);

        mockMvc.perform(post("/api/v1/auth/password/forgot")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isAccepted());
        mockMvc.perform(post("/api/v1/auth/email/verification/resend")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isAccepted());
        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "username":"%s",
                                  "email":"%s",
                                  "password":"Initial-Password-123!"
                                }
                                """.formatted("limit-" + UUID.randomUUID().toString().substring(0, 8), email)))
                .andExpect(status().isTooManyRequests())
                .andExpect(content().contentTypeCompatibleWith("application/problem+json"))
                .andExpect(jsonPath("$.status").value(429))
                .andExpect(header().exists("Retry-After"));

        org.junit.jupiter.api.Assertions.assertFalse(userRepository.existsByEmail(email));
        org.mockito.Mockito.verifyNoInteractions(mailSender);
    }
}
