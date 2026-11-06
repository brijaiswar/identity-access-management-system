# IAM HTTP API

The canonical API base is `/api/v1`. The version in the URL identifies the contract's major version;
backward-incompatible changes require a new version. Existing `/api/auth/**` and `/api/admin/**`
routes remain as compatibility aliases for v1, but are omitted from OpenAPI and new integrations
should use `/api/v1`. No removal date is set for the aliases.

JSON request bodies use `Content-Type: application/json`. Authenticated endpoints require
`Authorization: Bearer <access-token>`. Access tokens are short-lived; keep the returned refresh
token private and send it only to `POST /api/v1/auth/refresh`.

When enabled, the generated OpenAPI document is available at `/v3/api-docs` and Swagger UI at
`/swagger-ui.html`. Production disables these endpoints by default; enable them with
`IAM_API_DOCS_ENABLED=true` only when intentionally publishing API documentation.

## Authentication and account lifecycle

| Method and path | Access | Purpose |
|---|---|---|
| `POST /api/v1/auth/register` | Public, when registration is enabled; rate limited | Register an unverified user; returns `202 Accepted` |
| `POST /api/v1/auth/login` | Public, throttled | Authenticate with username/password and optional MFA/recovery code |
| `POST /api/v1/auth/refresh` | Public, refresh token in body | Rotate refresh token and issue an access token |
| `POST /api/v1/auth/logout` | Bearer token | Revoke the current session |
| `GET /api/v1/auth/sessions` | Bearer token | List the caller's active sessions |
| `DELETE /api/v1/auth/sessions/{id}` | Bearer token | Revoke one of the caller's sessions |
| `DELETE /api/v1/auth/sessions/others` | Bearer token | Revoke all sessions except the caller's current session |
| `GET /api/v1/auth/me` | Bearer token | Return current user information |
| `POST /api/v1/auth/validate` | Public, bearer token in `Authorization` | Return whether an access token is currently active |
| `GET /api/v1/auth/email/verify` | Public | Show a confirmation page; does not consume the token |
| `POST /api/v1/auth/email/verify` | Public, one-time token in body | Verify an email address |
| `POST /api/v1/auth/email/verification/resend` | Public, rate limited | Resend verification; response does not disclose account state |
| `POST /api/v1/auth/password/forgot` | Public, rate limited | Start password reset; response does not disclose account state |
| `POST /api/v1/auth/password/reset` | Public, one-time token | Set a new password |
| `POST /api/v1/auth/password/change` | Bearer token | Change password using current password and optional MFA |
| `POST /api/v1/auth/mfa/enrollment` | Bearer token | Begin MFA enrollment; request contains `currentPassword` |
| `POST /api/v1/auth/mfa/enrollment/confirm` | Bearer token | Confirm enrollment using `{ "code": "123456" }`; returns recovery codes once |
| `POST /api/v1/auth/mfa/recovery-codes` | Bearer token | Rotate recovery codes after validating an MFA/recovery code |
| `DELETE /api/v1/auth/mfa` | Bearer token | Disable MFA with `currentPassword` and `code` |

### Email verification

The verification email links to `/api/v1/auth/email/verify#token=<opaque-token>`. The token is in the
URL fragment, which browsers do not send to the server in the GET request. The page requires an
explicit user click, then submits `POST /api/v1/auth/email/verify` with
`{"token":"<opaque-token>"}`. GET requests and automated link previews do not consume the token.

### Login and token response

```json
{
  "token": "<JWT access token>",
  "refreshToken": "<opaque one-time token>",
  "expiresIn": 3600,
  "refreshExpiresAt": "2026-12-06T10:00:00Z",
  "sessionId": "<session id>",
  "username": "alice",
  "email": "alice@example.com",
  "roles": ["USER"]
}
```

The login request is `{"username":"alice","password":"...","mfaCode":"123456"}`; omit `mfaCode` if MFA
is not enabled. Recovery codes can be supplied in the same field. On successful refresh, replace and
discard the old refresh token immediately. A consumed token replay revokes the associated session.
Use `Cache-Control: no-store` responses for authentication and secret-bearing lifecycle operations.

Registration requires a username (3-100 characters), email, and password (12-128 characters). The
password-reset request is `{"email":"alice@example.com"}`. Reset completion uses
`{"token":"...","newPassword":"..."}`.

Public registration, password-reset, and email-verification requests share a database-backed limit
keyed by normalized email and client IP. The default allows five requests per hour and blocks further
requests for one hour. Login has its separate username/IP failure threshold. Rate-limited responses
use `429 Too Many Requests`, `Retry-After`, and an RFC 9457 error body. Tune the email-action policy
with `IAM_EMAIL_ACTION_MAX_REQUESTS`, `IAM_EMAIL_ACTION_WINDOW`, and
`IAM_EMAIL_ACTION_BLOCK_DURATION`.

## Administration

| Method and path | Required authority |
|---|---|
| `GET /api/v1/admin/users`, `GET /api/v1/admin/users/{id}` | `USER_READ_ALL` |
| `POST /api/v1/admin/users` | `USER_CREATE` |
| `PATCH /api/v1/admin/users/{id}/enabled` | `USER_UPDATE` |
| `PUT /api/v1/admin/users/{id}/roles` | `USER_ASSIGN_ROLES` |
| `DELETE /api/v1/admin/users/{id}/mfa` | `USER_MFA_RESET` |
| `GET /api/v1/admin/roles`, `GET /api/v1/admin/permissions` | `ROLE_READ` |
| `POST /api/v1/admin/roles`, `PUT /api/v1/admin/roles/{id}` | `ROLE_MANAGE` |
| `GET /api/v1/admin/audit-events` | `AUDIT_READ` |

Admin user creation uses `{"username":"alice","email":"alice@example.com","password":"..."}`.
Role assignment uses `{"roles":["USER"]}`. Role creation/update uses
`{"name":"AUDITOR","permissions":["READ_USER"]}`. User and audit collections are paginated using
Spring Data parameters such as `?page=0&size=50&sort=occurredAt,desc`; page sizes are capped at 100.
Collection bodies use a stable page shape: `content`, `number`, `size`, `totalElements`, and
`totalPages`. Audit events are returned through explicit response/page DTOs, not persistence entities.

## Error contract

API errors use `application/problem+json` and RFC 9457 Problem Details fields (`type`, `title`,
`status`, `detail`, and `instance`). Validation failures include an `errors` object keyed by field.

| Status | Meaning |
|---|---|
| `400 Bad Request` | Invalid input, malformed JSON, or expired/consumed action token |
| `401 Unauthorized` | Missing/invalid credentials, access token, or refresh token |
| `403 Forbidden` | Authenticated caller lacks a required authority |
| `404 Not Found` | Route or resource is unavailable |
| `409 Conflict` | Duplicate resource or operation blocked by an integrity safeguard |
| `429 Too Many Requests` | Login or email action limit is active; `Retry-After` is seconds |

Do not log bearer tokens, refresh tokens, passwords, MFA secrets, or recovery codes. Use HTTPS for all
non-local deployments.
