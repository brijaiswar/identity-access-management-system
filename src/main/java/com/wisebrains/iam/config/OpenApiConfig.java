package com.wisebrains.iam.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springdoc.core.customizers.OpenApiCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {
    @Bean
    public OpenAPI iamOpenApi() {
        return new OpenAPI()
                .info(new Info()
                        .title("Identity Access Management API")
                        .description("Versioned IAM API for authentication, account lifecycle, session management, and RBAC administration.")
                        .version("1.0.0")
                        .contact(new Contact().name("IAM Operations")))
                .components(new Components().addSecuritySchemes("bearerAuth",
                        new SecurityScheme().type(SecurityScheme.Type.HTTP).scheme("bearer").bearerFormat("JWT")));
    }

    @Bean
    public OpenApiCustomizer versionedPathsOnly() {
        return openApi -> {
            if (openApi.getPaths() != null) {
                openApi.getPaths().entrySet().removeIf(entry ->
                        entry.getKey().startsWith("/api/auth/")
                                || entry.getKey().startsWith("/api/admin/"));
            }
        };
    }
}
