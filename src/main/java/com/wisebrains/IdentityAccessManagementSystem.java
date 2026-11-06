package com.wisebrains;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class IdentityAccessManagementSystem {
    public static void main(String[] args) {
        SpringApplication.run(IdentityAccessManagementSystem.class, args);
    }
}