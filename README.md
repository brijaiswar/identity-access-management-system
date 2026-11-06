# Identity & Access Management System

This project delivers a secure, Java-based IAM platform built with Spring Boot, Spring Security, JPA, and JWT. It
provides enterprise-ready authentication, authorization, MFA-aware login flows, and role-based access control for
internal applications and custom identity workflows.

## Included functionality

- User registration and login endpoints
- JWT-based authentication
- Spring Security filter chain and stateless session handling
- Permission-enforced user and role administration
- One-time, operator-run production administrator bootstrap
- Email verification and password change/reset flows with expiring, one-time tokens
- TOTP MFA enrollment, verification, and single-use recovery codes
- Encrypted-at-rest MFA secrets and credential-change JWT revocation
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
development seed data, public registration, and the H2 console, and requires secrets from the environment:

```text
POSTGRES_PASSWORD=<strong database password>
JWT_SECRET=<at least 32 characters>
MFA_ENCRYPTION_KEY=<base64-encoded 32-byte key>
IAM_PUBLIC_BASE_URL=<https://your-identity-host>
MAIL_FROM=<verified sender address>
SMTP_HOST=<mail relay hostname>
SMTP_USERNAME=<mail relay account>
SMTP_PASSWORD=<mail relay credential>
```

Start the production compose stack with:
`docker compose up --build`

Do not use the development admin credentials in production. Start PostgreSQL, then run the one-time bootstrap profile
as an operator-controlled job. Supply these environment variables from your secret manager (never put the password in
shell history or a committed file):

```text
SPRING_PROFILES_ACTIVE=postgres,prod,bootstrap-admin
IAM_BOOTSTRAP_ADMIN_USERNAME=<initial administrator username>
IAM_BOOTSTRAP_ADMIN_EMAIL=<initial administrator email>
IAM_BOOTSTRAP_ADMIN_PASSWORD=<unique password of at least 12 characters>
```

Run the app service once with those variables available in the operator shell:

```sh
docker compose run --rm --no-deps \
  -e SPRING_PROFILES_ACTIVE=postgres,prod,bootstrap-admin \
  -e IAM_BOOTSTRAP_ADMIN_USERNAME \
  -e IAM_BOOTSTRAP_ADMIN_EMAIL \
  -e IAM_BOOTSTRAP_ADMIN_PASSWORD \
  app
```

The bootstrap uses a database lock and refuses to create an administrator if any user already exists. The bootstrap
profile does not start the HTTP server. Unset the bootstrap credentials after the command completes; normal service
instances should run only with `postgres,prod`.

The SMTP relay sends registration/admin-created-user verification messages and password reset links. Configure
`IAM_PUBLIC_BASE_URL` to the public API origin; the password-reset message links to a client page at
`/reset-password?token=...`, which should call `POST /api/auth/password/reset` with the token and a new password.
Do not log or persist raw action tokens. `MFA_ENCRYPTION_KEY` is a stable AES-256 key; back it up and keep it outside
the database, since changing it makes existing MFA secrets unreadable.

## Key API endpoints

- POST /api/auth/register
- POST /api/auth/login
- GET /api/auth/me
- POST /api/auth/validate
- GET /api/auth/email/verify?token=...
- POST /api/auth/email/verification/resend
- POST /api/auth/password/forgot and /api/auth/password/reset
- POST /api/auth/password/change
- POST /api/auth/mfa/enrollment and /api/auth/mfa/enrollment/confirm
- POST /api/auth/mfa/recovery-codes and DELETE /api/auth/mfa
- GET /api/admin/users (requires `USER_READ_ALL`)
- POST /api/admin/users (requires `USER_CREATE`; new users receive `USER`)
- PUT /api/admin/users/{id}/roles (requires `USER_ASSIGN_ROLES`)
- PATCH /api/admin/users/{id}/enabled (requires `USER_UPDATE`)
- GET /api/admin/roles and /api/admin/permissions (requires `ROLE_READ`)
- POST /api/admin/roles and PUT /api/admin/roles/{id} (requires `ROLE_MANAGE`)
- DELETE /api/admin/users/{id}/mfa (requires `USER_MFA_RESET`)

## Default roles and permissions

- ADMIN
- USER
- Built-in `ADMIN` and `USER` roles are protected from modification.
- The production `ADMIN` role receives the user/role administration permissions through Flyway migration.
- User and role administration endpoints enforce named authorities, not merely authentication.
- MFA recovery codes are shown once at enrollment or rotation; an administrator can reset a user's MFA enrollment.

## Notes

This implementation is intentionally production-friendly without requiring external identity providers. You can extend
it with OAuth2/OIDC, LDAP, SAML, or federation adapters depending on the target enterprise environment.
