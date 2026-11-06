# Identity & Access Management System

This project delivers a secure, Java-based IAM platform built with Spring Boot, Spring Security, JPA, and JWT. It
provides enterprise-ready authentication, authorization, MFA-aware login flows, and role-based access control for
internal applications and custom identity workflows.

## Included functionality

- User registration and login endpoints
- JWT-based authentication
- Spring Security stateless bearer requests with persisted refresh-token sessions
- Permission-enforced user and role administration
- One-time, operator-run production administrator bootstrap
- Email verification and password change/reset flows with expiring, one-time tokens
- TOTP MFA enrollment, verification, and single-use recovery codes
- Encrypted-at-rest MFA secrets and credential-change JWT revocation
- Persisted audit events for authentication, account security changes, sessions, and administration
- Per-username and per-client-IP login throttling with configurable lockout windows
- Shared per-email and per-client-IP throttling for registration and public email actions
- Versioned `/api/v1` routes with RFC 9457 error responses and OpenAPI documentation
- Rotating, one-time refresh tokens with device/session listing, logout, and revocation
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

PostgreSQL migration and integration tests use Testcontainers. They run in CI and are skipped locally
when Docker is unavailable; see [OPERATIONS.md](OPERATIONS.md) for running the dedicated suite.

Production procedures, migration/backup guidance, health checks, and operational security controls are
documented in [OPERATIONS.md](OPERATIONS.md).

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
IAM_LOGIN_MAX_FAILURES=5
IAM_LOGIN_WINDOW=PT15M
IAM_LOGIN_LOCK_DURATION=PT15M
IAM_EMAIL_ACTION_MAX_REQUESTS=5
IAM_EMAIL_ACTION_WINDOW=PT1H
IAM_EMAIL_ACTION_BLOCK_DURATION=PT1H
IAM_REFRESH_TOKEN_LIFETIME=PT720H
IAM_TRUSTED_PROXIES=<comma-separated exact proxy peer IPs>
IAM_API_DOCS_ENABLED=false
DB_POOL_MAX_SIZE=20
DB_POOL_MIN_IDLE=5
```

Start the production compose stack with:
`docker compose up --build`

Compose binds the API and PostgreSQL ports to loopback by default. Put a TLS-terminating reverse proxy
in front of the API and configure its trusted IPs in `IAM_TRUSTED_PROXIES`; configure the proxy to
overwrite forwarded headers rather than append untrusted client-supplied values. To publish the API
directly, deliberately change the API port binding and enforce TLS/network restrictions at the host
firewall. The application container runs as a non-root user with a read-only root filesystem, dropped
Linux capabilities, a readiness health check, and graceful shutdown. PostgreSQL data is persisted in
the `postgres_data` volume; restrict access to that volume and database backups.

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
`/reset-password?token=...`, which should call `POST /api/v1/auth/password/reset` with the token and a new password.
Email verification links put the token in a URL fragment and require the user to confirm on the
`/api/v1/auth/email/verify` page; the initial GET does not consume the token.
Do not log or persist raw action tokens. `MFA_ENCRYPTION_KEY` is a stable AES-256 key; back it up and keep it outside
the database, since changing it makes existing MFA secrets unreadable.

## Key API endpoints

Detailed endpoint contracts, payloads, permissions, and response semantics are in [API.md](API.md).
The interactive OpenAPI UI is available at `/swagger-ui.html` when enabled; production keeps API docs
disabled by default (`IAM_API_DOCS_ENABLED=false`).

- POST /api/v1/auth/register
- POST /api/v1/auth/login
- POST /api/v1/auth/refresh (rotates the one-time refresh token)
- POST /api/v1/auth/logout
- GET /api/v1/auth/sessions; DELETE /api/v1/auth/sessions/{id}; DELETE /api/v1/auth/sessions/others
- GET /api/v1/auth/me
- POST /api/v1/auth/validate
- GET /api/v1/auth/email/verify (confirmation page); POST the token to the same path
- POST /api/v1/auth/email/verification/resend
- POST /api/v1/auth/password/forgot and /api/v1/auth/password/reset
- POST /api/v1/auth/password/change
- POST /api/v1/auth/mfa/enrollment and /api/v1/auth/mfa/enrollment/confirm
- POST /api/v1/auth/mfa/recovery-codes and DELETE /api/v1/auth/mfa
- GET /api/v1/admin/users (requires `USER_READ_ALL`)
- POST /api/v1/admin/users (requires `USER_CREATE`; new users receive `USER`)
- PUT /api/v1/admin/users/{id}/roles (requires `USER_ASSIGN_ROLES`)
- PATCH /api/v1/admin/users/{id}/enabled (requires `USER_UPDATE`)
- GET /api/v1/admin/roles and /api/v1/admin/permissions (requires `ROLE_READ`)
- POST /api/v1/admin/roles and PUT /api/v1/admin/roles/{id} (requires `ROLE_MANAGE`)
- DELETE /api/v1/admin/users/{id}/mfa (requires `USER_MFA_RESET`)
- GET /api/v1/admin/audit-events (requires `AUDIT_READ`)

Unversioned `/api/auth/**` and `/api/admin/**` routes remain as v1 compatibility aliases and return
headers identifying v1 and linking to the equivalent `/api/v1` route. New clients should use
`/api/v1`; no alias retirement is scheduled. Breaking changes require a new major URL prefix and
published migration guidance. Error responses use `application/problem+json`.

## Default roles and permissions

- ADMIN
- USER
- Built-in `ADMIN` and `USER` roles are protected from modification.
- The production `ADMIN` role receives the user/role administration permissions through Flyway migration.
- User and role administration endpoints enforce named authorities, not merely authentication.
- MFA recovery codes are shown once at enrollment or rotation; an administrator can reset a user's MFA enrollment.
- Access tokens are short-lived JWTs (configured by `JWT_EXPIRATION_MS`); refresh tokens are random, rotating opaque
  tokens stored only as SHA-256 hashes. Reuse of a consumed refresh token revokes its whole session. Password or MFA
  changes invalidate all existing access and refresh sessions via the credential version.
- Login failures are counted in the database by pseudonymous username and IP buckets, so throttling is shared across
  app instances. Defaults block after five failures in 15 minutes for 15 minutes. Set `IAM_TRUSTED_PROXIES` to a
  comma-separated list of exact proxy peer IPs only when those proxies overwrite `X-Forwarded-For`; the application
  ignores forwarded headers from all other peers. Keep the audit endpoint permission-restricted and define an
  organization-specific retention policy for audit records.

## Notes

This implementation is intentionally production-friendly without requiring external identity providers. You can extend
it with OAuth2/OIDC, LDAP, SAML, or federation adapters depending on the target enterprise environment.
