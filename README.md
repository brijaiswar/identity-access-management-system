# Identity & Access Management System
This project delivers a secure, Java-based IAM platform built with Spring Boot, Spring Security, JPA, and JWT. It provides enterprise-ready authentication, authorization, MFA-aware login flows, and role-based access control for internal applications and custom identity workflows.

## Included functionality
- User registration and login endpoints
- JWT-based authentication
- Spring Security filter chain and stateless session handling
- Role and permission model for RBAC
- MFA support via TOTP validation
- H2 default database configuration for local runs
- PostgreSQL profile for production or on-prem deployment
- Docker Compose setup for local containerized deployment

## Tech stack
- Java 17
- Spring Boot 3.1.2
- Spring Web / Security / Data JPA / Validation
- PostgreSQL / H2
- JJWT for token generation

## Quick start
1. Start the application locally:
   ./gradlew bootRun
2. Default seeded admin user:
   - Username: admin
   - Password: admin123
3. Open the H2 console:
   http://localhost:8080/h2-console
4. For PostgreSQL-based deployment, run:
   docker-compose up --build

## Key API endpoints
- POST /api/auth/register
- POST /api/auth/login
- GET /api/auth/me
- POST /api/auth/validate

## Default roles and permissions
- ADMIN
- USER
- Permissions: READ_USER, WRITE_USER, DELETE_USER

## Notes
This implementation is intentionally production-friendly without requiring external identity providers. You can extend it with OAuth2/OIDC, LDAP, SAML, or federation adapters depending on the target enterprise environment.
