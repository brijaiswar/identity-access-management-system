# Identity & Access Management System

This project delivers a secure, Java-based IAM platform built with Spring Boot, Spring Security, JPA, and JWT. It
provides enterprise-ready authentication, authorization, MFA-aware login flows, and role-based access control for
internal applications and custom identity workflows.

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
- Flyway database migrations
- JaCoCo test coverage reports

## Quick start

1. Start the application locally with the H2 database:
   `./gradlew bootRun`
2. In the default development profile, the seeded admin user is:
   - Username: `admin`
   - Password: `admin123`
3. Run the complete test suite and generate coverage:
   `./gradlew clean check`
4. Open the JaCoCo report at `build/reports/jacoco/test/html/index.html`.

## Production deployment

Production runs with the `postgres,prod` profiles, validates the schema against Flyway migrations, disables
development seed data and the H2 console, and requires secrets from the environment:

```text
POSTGRES_PASSWORD=<strong database password>
JWT_SECRET=<at least 32 characters>
```

Start the production compose stack with:
`docker compose up --build`

Do not use the development admin credentials in production. Provision the first administrator through a controlled
deployment or database bootstrap process.

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

This implementation is intentionally production-friendly without requiring external identity providers. You can extend
it with OAuth2/OIDC, LDAP, SAML, or federation adapters depending on the target enterprise environment.
