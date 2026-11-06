package com.wisebrains.iam;

import com.wisebrains.iam.model.Role;
import com.wisebrains.iam.model.User;
import com.wisebrains.iam.role.RoleRepository;
import com.wisebrains.iam.user.UserRepository;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Testcontainers(disabledWithoutDocker = true)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK, properties = {
        "spring.main.web-application-type=servlet",
        "spring.jpa.hibernate.ddl-auto=validate",
        "spring.flyway.enabled=true",
        "jwt.secret=postgres-integration-test-signing-key-that-is-at-least-32-bytes",
        "iam.mfa.encryption-key=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
        "iam.public-base-url=http://localhost:8080",
        "iam.email.from=no-reply@example.com",
        "spring.mail.host=localhost",
        "spring.mail.username=test",
        "spring.mail.password=test"
})
@AutoConfigureMockMvc
@ActiveProfiles({"postgres", "prod"})
class PostgresMigrationIntegrationTest {
    @Container
    private static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("iam_integration")
                    .withUsername("iam_test")
                    .withPassword("iam_test_password");

    @DynamicPropertySource
    static void configureDatasource(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
    }

    @Autowired
    private Flyway flyway;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @MockBean
    private JavaMailSender mailSender;

    @Test
    void appliesAllMigrationsAndSupportsPostgresAuthAndSessionLifecycle() throws Exception {
        try (var connection = jdbcTemplate.getDataSource().getConnection()) {
            assertEquals("PostgreSQL", connection.getMetaData().getDatabaseProductName());
        }
        assertEquals(4, flyway.info().applied().length);
        assertEquals(1, jdbcTemplate.queryForObject(
                "select count(*) from information_schema.columns " +
                        "where table_name = 'login_sessions' and column_name = 'expires_at' " +
                        "and data_type = 'timestamp with time zone'", Integer.class));
        assertEquals(1, jdbcTemplate.queryForObject(
                "select count(*) from permissions where name = 'AUDIT_READ'", Integer.class));
        assertEquals(1, jdbcTemplate.queryForObject(
                "select count(*) from role_permissions rp join roles r on r.id = rp.role_id " +
                        "join permissions p on p.id = rp.permission_id " +
                        "where r.name = 'ADMIN' and p.name = 'AUDIT_READ'", Integer.class));

        String username = "postgres-" + UUID.randomUUID().toString().substring(0, 8);
        Role userRole = roleRepository.findByName("USER").orElseThrow();
        User user = new User(username, passwordEncoder.encode("Postgres-Integration-Password-123!"),
                username + "@example.com");
        user.setEmailVerified(true);
        user.setRoles(Set.of(userRole));
        userRepository.saveAndFlush(user);

        var loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"%s","password":"Postgres-Integration-Password-123!"}
                                """.formatted(username)))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode login = objectMapper.readTree(loginResult.getResponse().getContentAsString());
        String accessToken = login.get("token").asText();
        String firstRefreshToken = login.get("refreshToken").asText();
        String sessionId = login.get("sessionId").asText();
        assertTrue(jdbcTemplate.queryForObject(
                "select count(*) from login_sessions where id = ?", Integer.class, sessionId) == 1);
        assertTrue(jdbcTemplate.queryForObject(
                "select count(*) from audit_events where actor_username = ? and event_type = 'LOGIN_SUCCEEDED'",
                Integer.class, username) == 1);

        var refreshResult = mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"refreshToken":"%s"}
                                """.formatted(firstRefreshToken)))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode refreshed = objectMapper.readTree(refreshResult.getResponse().getContentAsString());
        assertEquals(sessionId, refreshed.get("sessionId").asText());
        assertTrue(jdbcTemplate.queryForObject(
                "select count(*) from session_refresh_tokens where session_id = ? and consumed_at is not null",
                Integer.class, sessionId) == 1);

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"refreshToken":"%s"}
                                """.formatted(firstRefreshToken)))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/auth/me").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isUnauthorized());
        assertTrue(jdbcTemplate.queryForObject(
                "select count(*) from audit_events where actor_username = ? " +
                        "and event_type = 'SESSION_REFRESH_REUSE_DETECTED'", Integer.class, username) == 1);
    }
}
