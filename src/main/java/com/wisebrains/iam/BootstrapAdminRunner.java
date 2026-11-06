package com.wisebrains.iam;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component
@Profile("bootstrap-admin")
public class BootstrapAdminRunner implements CommandLineRunner {
    private static final Logger logger = LoggerFactory.getLogger(BootstrapAdminRunner.class);

    private final BootstrapAdminService bootstrapAdminService;
    private final String username;
    private final String email;
    private final String password;

    public BootstrapAdminRunner(BootstrapAdminService bootstrapAdminService,
                                @Value("${iam.bootstrap.admin.username:}") String username,
                                @Value("${iam.bootstrap.admin.email:}") String email,
                                @Value("${iam.bootstrap.admin.password:}") String password) {
        this.bootstrapAdminService = bootstrapAdminService;
        this.username = username;
        this.email = email;
        this.password = password;
    }

    @Override
    public void run(String... args) {
        bootstrapAdminService.bootstrap(username, email, password);
        logger.info("Initial administrator was provisioned successfully");
    }
}
