# Deployment and operations

## Deployment prerequisites

- Use PostgreSQL 16 or a supported managed PostgreSQL service, and run the service with `postgres,prod`.
- Supply database, JWT-signing, MFA-encryption, public-base-URL, sender, and SMTP settings from a secret
  manager. Never commit production secrets or pass them in shell command arguments.
- Keep `JWT_SECRET` and `MFA_ENCRYPTION_KEY` stable across replicas. The MFA key must decode to 32 bytes.
  Changing the JWT signing key invalidates every access token; changing the MFA key makes stored MFA
  secrets unreadable.
- Keep `IAM_API_DOCS_ENABLED=false` in production unless documentation publication has been approved.
- Put the API behind TLS termination and a trusted proxy. Compose binds ports to loopback; configure
  proxy/firewall rules deliberately if changing those bindings. Set `IAM_TRUSTED_PROXIES` to exact proxy
  peer IPs and ensure the proxy removes inbound forwarded headers before setting its own values.
- Use a unique database password, restrict database network access, and use encrypted storage and
  encrypted backups. Compose's database port is only published on loopback for local operator access.

## Startup and health

The container readiness check calls `/actuator/health/readiness`, which includes database health.
Liveness is available at `/actuator/health/liveness`. Only `health` and `info` actuator endpoints are
exposed. A readiness failure should remove an instance from traffic; a liveness failure should restart
it. The app uses graceful shutdown with a 30-second phase timeout; allow at least 40 seconds in the
orchestrator termination grace period.

Monitor HTTP 5xx and 429 rates, authentication failures, database pool saturation, migration failures,
SMTP delivery errors, process restarts, disk capacity, and backup age. Audit events are persisted in
the application database. Ship operational logs to a protected centralized sink, but never include
authorization headers, passwords, refresh/action tokens, MFA secrets, or recovery codes. Audit records
include source IP and user agent; restrict access and apply the organization's privacy and retention
policy. No automatic audit-event purge is enabled.

## Database migrations and recovery

Flyway applies versioned schema changes at startup. Production uses Hibernate schema validation rather
than automatic schema mutation. Before every upgrade:

1. Verify a recent encrypted PostgreSQL backup by restoring it to a separate staging database.
2. Deploy the candidate against a staging clone and run the PostgreSQL migration/integration suite:
   `./gradlew test --tests com.wisebrains.iam.PostgresMigrationIntegrationTest`.
3. Schedule a production migration window, confirm the database has sufficient disk space, and capture
   the Flyway schema history and application version.
4. Deploy the new version and verify readiness, login, refresh, SMTP, and administrative audit access.

Do not roll back by editing `flyway_schema_history` or running Hibernate DDL. For an incompatible
database change, restore the verified backup or deploy a forward corrective migration. Keep database
backup encryption keys separate from application keys.

## Identity and security operations

- Bootstrap the first production administrator using the `bootstrap-admin` profile as a one-off job.
  Remove the bootstrap credentials immediately afterward. Never run the development seed profile in
  production.
- Default login throttling is five failures per username or source IP during a 15-minute window,
  followed by a 15-minute block. Tune with `IAM_LOGIN_MAX_FAILURES`, `IAM_LOGIN_WINDOW`, and
  `IAM_LOGIN_LOCK_DURATION`. Registration, password reset, and email-verification sends share a
  database-backed limit of five requests per normalized email and source IP per hour, followed by a
  one-hour block. Tune with `IAM_EMAIL_ACTION_MAX_REQUESTS`, `IAM_EMAIL_ACTION_WINDOW`, and
  `IAM_EMAIL_ACTION_BLOCK_DURATION`; ensure upstream ingress protections also cover public endpoints.
- Use the versioned `/api/v1` routes for new clients. Responses identify the contract with
  `API-Version: 1`. Existing `/api/auth/**` and `/api/admin/**` routes are retained as v1
  compatibility aliases and return a `Link` header pointing to the equivalent canonical route.
  Breaking API changes require a new major route prefix and published migration guidance; announce
  a sunset date before retiring any compatibility alias.
- Refresh tokens are one-time rotating secrets. Clients must atomically replace them on refresh and
  discard the prior value. A detected replay revokes the affected session. Password or MFA changes
  invalidate sessions through the credential version.
- Set a session lifetime that matches policy with `IAM_REFRESH_TOKEN_LIFETIME`; access-token lifetime
  is controlled by `JWT_EXPIRATION_MS`. Shorten access-token lifetime for higher-risk environments.
- Audit reads require `AUDIT_READ`; grant it only to operators with a business need. Investigate
  `LOGIN_RATE_LIMITED`, `SESSION_REFRESH_REUSE_DETECTED`, and unexpected administrative changes.
- Confirm SMTP relay delivery and alert on mail failures. The application sends account lifecycle
  mail synchronously; mail outages can prevent those operations from completing.

## PostgreSQL integration tests

The Testcontainers suite runs the complete Flyway chain against a disposable PostgreSQL 16 instance,
validates PostgreSQL-specific schema types and seed data, and exercises persisted login/session/audit
flows. It skips automatically when Docker is unavailable. CI runs on a Docker-enabled runner and must
execute the PostgreSQL test rather than relying only on H2 tests.
