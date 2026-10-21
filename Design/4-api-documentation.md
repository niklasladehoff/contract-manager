# IBM Confidential Computing Contract Generator - API Documentation

> **Version:** 1.5 (implementation-aligned)
> **Date:** 2026-06-24
> **Status:** Production backend reference
> **Source of Truth:** `cmd/server/main.go` and `internal/*`

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Service Overview](#2-service-overview)
3. [Middleware & Security Pipeline](#3-middleware--security-pipeline)
4. [Authentication, Setup Guard, and Request Signing](#4-authentication-setup-guard-and-request-signing)
5. [Authorization Model](#5-authorization-model)
6. [Build Lifecycle and State Machine](#6-build-lifecycle-and-state-machine)
7. [Endpoint Reference](#7-endpoint-reference)
8. [Error Model](#8-error-model)
9. [Configuration (Environment Variables)](#9-configuration-environment-variables)
10. [Operational Notes](#10-operational-notes)

---

## 1. Introduction

This document describes the **actual current backend API behavior** for the IBM Confidential Computing Contract Generator.

It is implementation-first and is aligned with:
- route registration in `cmd/server/main.go`
- request middleware in `internal/middleware/*`
- handlers in `internal/handler/*`
- business rules in `internal/service/*`

Where implementation and older docs diverge, this document follows the implementation.

---

## 2. Service Overview

### Base URL

The backend is mounted without a version prefix.

Example:

```text
http://localhost:8080
https://<your-host>
```

### Content Type

- Requests: `application/json` for JSON endpoints.
- Responses: `application/json` except rate-limit plain-text responses from middleware.

### Authentication Token Model

- Tokens are opaque random values issued by `POST /auth/login`.
- The backend stores and validates only token hashes.
- Auth header format:

```text
Authorization: Bearer <token>
```

### Public Endpoints

- `GET /health`
- `GET /openapi.json`
- `GET /swagger`
- `GET /swagger/`
- `POST /auth/login`

All other routes require authentication.

---

## 3. Middleware & Security Pipeline

Global middleware order (outermost to innermost):

1. `Recoverer()`
2. `RequestID()`
3. `SecurityHeaders()`
4. `Logging()`
5. `CORS()`
6. `MaxBodyBytes()`
7. `RequestTimeout()`
8. `RateLimit()`

Authenticated group middleware order:

1. `Auth()`
2. `SetupGuard()`
3. `RequireRequestSignature()`

### 3.1 Recoverer

- Converts panics to:

```json
{"error":{"code":"INTERNAL_ERROR","message":"An unexpected error occurred."}}
```

- Returns `500`.

### 3.2 Request ID

- Uses inbound `X-Request-ID` if safe; otherwise generates UUID.
- Echoes `X-Request-ID` in response headers.

### 3.3 Security Headers

Always sets:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- `Permissions-Policy: camera=(), microphone=(), geolocation=()`

Sets HSTS only for TLS requests:

- `Strict-Transport-Security: max-age=31536000; includeSubDomains`

### 3.4 CORS

Default allowed origins:

- `http://localhost:5173`
- `http://127.0.0.1:5173`
- `null`

Configurable via `CORS_ALLOWED_ORIGINS` and `CORS_ALLOW_ALL`.

Allowed methods:

- `GET, POST, PUT, PATCH, DELETE, OPTIONS`

Allowed headers include:

- `Content-Type`
- `Authorization`
- `X-Request-ID`
- `X-Signature`
- `X-Signature-Hash`
- `X-Timestamp`
- `X-Key-Fingerprint`

### 3.5 Request Size and Timeout

- Global body cap (default): `50MB` (`MAX_PAYLOAD_SIZE`)
- Request timeout (default): `30s` (`REQUEST_TIMEOUT`)

Handler-level JSON behavior:

- Most handlers use `readJSON`:
  - default max `1MB`
  - `DisallowUnknownFields = true`
- `POST /builds/{id}/sections` uses `readJSONLarge(..., 50MB)`.

### 3.6 Rate Limiting

Global limiter (`RateLimit`):

- 10 requests/second per client IP
- burst 20

Login limiter (`AuthRateLimit`) on `POST /auth/login`:

- 5 requests/minute per IP
- burst 3

`/auth/login` is subject to both global and auth-specific limits.

Rate-limit response is plain text (`429`), not JSON:

```text
Rate limit exceeded. Please try again later.
```

### 3.7 Client IP Resolution

- Default: `RemoteAddr`
- If `TRUST_PROXY_HEADERS=true`, uses `X-Forwarded-For` / `X-Real-IP`

---

## 4. Authentication, Setup Guard, and Request Signing

### 4.1 Login

`POST /auth/login` returns:

- token + expiry
- user profile
- setup status (`requires_setup`, `setup_pending`)

`active_key_count` and `has_public_key` describe active keys only (not revoked and not expired). Legacy fingerprint/expiry fields show the newest active key, or `null`. The legacy `public_key_expired` renewal flag is true when history exists but no active key remains, including after revocation. A single expired device key does not block another active device.

Setup pending values:

- `password_change`
- `public_key_registration`

### 4.2 Setup Guard

If setup is incomplete, access is restricted to setup endpoints only.

Allowed while setup is pending:

- `POST /auth/logout`
- `PATCH /users/{id}/password` (own user only)
- `PUT /users/{id}/public-key` (own user only)

Everything else returns `403 ACCOUNT_SETUP_REQUIRED`:

```json
{
  "error": {
    "code": "ACCOUNT_SETUP_REQUIRED",
    "message": "Account setup incomplete. Complete required setup steps.",
    "details": {
      "setup_pending": ["password_change", "public_key_registration"]
    }
  }
}
```

### 4.3 Request Signature Enforcement

All authenticated mutating requests (`POST`, `PUT`, `PATCH`, `DELETE`) require signature headers unless exempt.

Required headers:

- `X-Signature`
- `X-Signature-Hash`
- `X-Timestamp` (Unix milliseconds)
- `X-Key-Fingerprint` (required with multiple active keys; omission is accepted only with exactly one active key)

Timestamp tolerance:

- ±5 minutes

Exempt endpoints:

- `POST /auth/logout`
- `PATCH /users/{id}/password`
- `PUT /users/{id}/public-key` only when the caller has zero active keys

Canonical hash payload used by backend:

```json
{"method":"POST","path":"/builds/<id>/sections","data":{...},"timestamp":1710000000000}
```

Where:

- `method` = uppercased HTTP method
- `path` = URL path only
- `data` = raw JSON body, or `null` when empty

`X-Signature-Hash` must equal SHA-256 hex of canonical payload.
`X-Signature` must verify against the authenticated user's selected active key. Fingerprints are lowercase SHA-256 hex; uppercase and colon separators are normalized. Unknown or foreign fingerprints return `403 INVALID_SIGNATURE`; revoked and expired keys return `403 SIGNATURE_KEY_REVOKED` and `403 SIGNATURE_KEY_EXPIRED`. An ambiguous missing fingerprint returns `403 SIGNATURE_KEY_FINGERPRINT_REQUIRED`.

---

## 5. Authorization Model

### 5.1 Persona Roles

System roles:

- `SOLUTION_PROVIDER`
- `DATA_OWNER`
- `AUDITOR`
- `ENV_OPERATOR`
- `ADMIN`
- `VIEWER`

### 5.2 Build Access and Stage Authorization

For build-related operations, the backend enforces two layers:

1. **Build visibility/access middleware (`RequireBuildAccess`)** on `/builds/{id}/...`:
   - `ADMIN` can access any build.
   - Non-admin users must be assigned to that build.
2. **Stage/service authorization**:
   - User must hold required global role.
   - User must be explicitly assigned to that build role.

Stage/service checks are enforced in section submission, state transitions, and export/download flows.

### 5.3 Endpoint-Level vs Service-Level Guards

Important implementation detail:

- Some routes are not role-guarded at router level but are restricted in services.
- Example: `GET /builds/{id}/export` has no role middleware, but service requires assigned `ENV_OPERATOR` and `FINALIZED` state.
- `GET /builds` is not role-gated but behavior differs:
  - `ADMIN`: global paginated build list.
  - non-admin: assignment-filtered build list.

### 5.4 Setup-Restricted Phase

Even valid authenticated users are blocked by `SetupGuard` until password/public key setup completes.

---

## 6. Build Lifecycle and State Machine

### 6.1 Status Values

- `CREATED`
- `SIGNING_KEY_REGISTERED`
- `WORKLOAD_SUBMITTED`
- `ENVIRONMENT_STAGED`
- `ATTESTATION_KEY_REGISTERED`
- `FINALIZED`
- `CONTRACT_DOWNLOADED`
- `CANCELLED`

### 6.2 Transition Rules

Normal forward transitions:

- `CREATED -> SIGNING_KEY_REGISTERED`
- `SIGNING_KEY_REGISTERED -> WORKLOAD_SUBMITTED`
- `WORKLOAD_SUBMITTED -> ENVIRONMENT_STAGED`
- `ENVIRONMENT_STAGED -> ATTESTATION_KEY_REGISTERED`
- `ATTESTATION_KEY_REGISTERED -> FINALIZED`
- `FINALIZED -> CONTRACT_DOWNLOADED`

Cancellation:

- `-> CANCELLED` allowed from any non-terminal, non-cancelled state.

Terminal states:

- `FINALIZED`
- `CONTRACT_DOWNLOADED`
- `CANCELLED`

Note:

- `FINALIZED` is immutable for normal workflow mutations.
- The only allowed post-finalization progression is `POST /builds/{id}/acknowledge-download` (`FINALIZED -> CONTRACT_DOWNLOADED`).

### 6.3 Role Required per Transition

- `SIGNING_KEY_REGISTERED`: `AUDITOR`
- `WORKLOAD_SUBMITTED`: `SOLUTION_PROVIDER`
- `ENVIRONMENT_STAGED`: `DATA_OWNER`
- `ATTESTATION_KEY_REGISTERED`: `AUDITOR`
- `FINALIZED`: `AUDITOR`
- `CONTRACT_DOWNLOADED`: `ENV_OPERATOR` (via acknowledge-download flow)

### 6.4 Important Transition Constraints

- `CONTRACT_DOWNLOADED` is set only by `POST /builds/{id}/acknowledge-download`.
- Download acknowledgement is one-time; repeated export/userdata/acknowledge requests are blocked.

### 6.5 Audit Event Types

- `BUILD_CREATED`
- `SIGNING_KEY_CREATED`
- `WORKLOAD_SUBMITTED`
- `ENVIRONMENT_STAGED`
- `ATTESTATION_KEY_REGISTERED`
- `BUILD_FINALIZED`
- `CONTRACT_DOWNLOADED`
- `BUILD_CANCELLED`
- `ROLE_ASSIGNED`
- `USER_CREATED`
- `TOKEN_CREATED`
- `TOKEN_REVOKED`
- `ATTESTATION_EVIDENCE_UPLOADED`
- `ATTESTATION_VERIFIED`

### 6.6 Signature Expectations in Verification

Audit verification expects signatures for:

- `BUILD_CREATED`
- `SIGNING_KEY_CREATED`
- `WORKLOAD_SUBMITTED`
- `ENVIRONMENT_STAGED`
- `ATTESTATION_KEY_REGISTERED`
- `BUILD_FINALIZED`
- `CONTRACT_DOWNLOADED`
- `ATTESTATION_EVIDENCE_UPLOADED`
- `ATTESTATION_VERIFIED`

---

## 7. Endpoint Reference

All paths below are relative to backend root.

### 7.1 Public / Documentation

#### GET /health

- Auth: none
- Response `200`:

```json
{"status":"ok"}
```

#### GET /about

- Auth: none
- Response `200`: service name, version, and build metadata.

#### GET /openapi.json

- Auth: none
- Response `200`: embedded OpenAPI JSON (static in code).

#### GET /swagger and GET /swagger/

- Auth: none
- Response `200`: Swagger UI HTML.

---

### 7.2 Authentication

#### POST /auth/login

- Auth: none
- Rate limits: global + auth-specific
- Request:

```json
{
  "email": "user@example.com",
  "password": "password"
}
```

- Response `200`:

```json
{
  "token": "<opaque-token>",
  "expires_at": "2026-04-11T12:00:00Z",
  "requires_setup": false,
  "setup_pending": [],
  "user": {
    "id": "uuid",
    "name": "Jane Doe",
    "email": "user@example.com",
    "roles": ["SOLUTION_PROVIDER"],
    "is_active": true,
    "created_at": "2026-04-01T10:00:00Z",
    "has_public_key": true,
    "active_key_count": 2,
    "public_key_expired": false,
    "public_key_fingerprint": "hex-or-null",
    "public_key_expires_at": "2026-07-01T10:00:00Z",
    "must_change_password": false,
    "password_changed_at": "2026-04-01T10:30:00Z"
  }
}
```

- Error `401` (invalid credentials):

```json
{
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "Invalid email or password."
  }
}
```

#### POST /auth/logout

- Auth: required
- Signature headers: exempt
- Response: `204 No Content`

---

### 7.3 Roles

#### GET /roles

- Auth: required
- Setup must be complete
- Response `200`:

```json
{
  "roles": [
    {
      "id": "uuid",
      "name": "SOLUTION_PROVIDER",
      "description": "Provides workload definition and HPCR encryption certificate",
      "created_at": "...",
      "updated_at": "..."
    }
  ]
}
```

---

### 7.4 User Management

#### GET /users

- Auth: required
- Role: `ADMIN` or `AUDITOR`
- Response `200`:

```json
{
  "users": [
    {
      "id": "uuid",
      "name": "Alice",
      "email": "alice@example.com",
      "roles": ["AUDITOR"],
      "is_active": true,
      "created_at": "2026-04-10T08:00:00Z",
      "must_change_password": false,
      "active_key_count": 2,
      "public_key_fingerprint": "...",
      "public_key_expires_at": "2026-07-10T08:00:00Z"
    }
  ]
}
```

#### POST /users

- Auth: required
- Role: `ADMIN`
- Signature headers: required
- Request:

```json
{
  "name": "New User",
  "email": "new.user@example.com",
  "password": "StrongPass123!",
  "roles": ["DATA_OWNER"]
}
```

- Response `201`: created user summary
- Common errors:
  - `400 INVALID_REQUEST`
  - `409 DUPLICATE_EMAIL`

#### PATCH /users/{id}

- Auth: required
- Role: `ADMIN`
- Signature headers: required
- Request:

```json
{
  "name": "Updated Name",
  "email": "updated@example.com"
}
```

- Response `200`: updated user summary

#### PATCH /users/{id}/roles

- Auth: required
- Role: `ADMIN`
- Signature headers: required
- Request:

```json
{
  "roles": ["AUDITOR", "VIEWER"]
}
```

- Response `200`: updated user summary

#### DELETE /users/{id}

- Auth: required
- Role: `ADMIN`
- Signature headers: required
- Response `200`:

```json
{"message":"User deactivated successfully."}
```

#### PATCH /users/{id}/reactivate

- Auth: required
- Role: `ADMIN`
- Signature headers: required
- Response `200`:

```json
{"message":"User reactivated successfully."}
```

#### PATCH /users/{id}/reset-password

- Auth: required
- Role: `ADMIN`
- Signature headers: required
- Request:

```json
{"new_password":"NewStrongPass123!"}
```

- Response `200`:

```json
{"message":"Password reset successfully. User must change password on next login."}
```

#### PUT /users/{id}/public-key

- Auth: required
- Access: owner only; admins cannot add keys for other users
- Signature headers: required when any active key exists, otherwise exempt
- Adds a key instead of replacing earlier keys. At most five active RSA-4096 keys, valid for 90 days each.
- `password` is required whenever any key history exists, including after expiry or revocation. First registration needs no password.
- `label` is optional (trimmed, at most 100 characters); default is `Key YYYY-MM-DD` in UTC.
- Request:

```json
{"public_key":"-----BEGIN PUBLIC KEY-----...","label":"Office laptop","password":"current-password"}
```

- Response `200` includes fingerprint and setup state:

```json
{
  "fingerprint": "sha256-hex",
  "key_id": "uuid",
  "label": "Office laptop",
  "message": "Public key registered successfully",
  "created_at": "...",
  "expires_at": "...",
  "requires_setup": false,
  "setup_pending": [],
  "must_change_password": false
}
```

Errors include `403 PASSWORD_CONFIRMATION_FAILED`, `409 KEY_ALREADY_REGISTERED` (fingerprints remain globally unique after revocation), and `409 KEY_LIMIT_REACHED`. Invalid PEM or labels return `400 INVALID_REQUEST`.

#### GET /users/{id}/public-keys

- Auth: required; owner or `ADMIN`.
- Response `200`: `{"keys": [...]}`, including all expired and revoked keys. An empty history is `{"keys": []}`.
- Rows contain `id`, `user_id`, `label`, `public_key`, `fingerprint`, `registered_at`, `expires_at`, `last_used_at`, `revoked_at`, and `revoked_by`. The last three fields are nullable; `last_used_at` is reserved and currently not updated.
- Active status means `revoked_at == null` and `expires_at > now`.

#### DELETE /users/{id}/public-keys/{key_id}

- Auth: required; owner or `ADMIN`; signature required with an active key belonging to the caller.
- Records revocation and actor, preserving the row. Expired, unrevoked keys can also be revoked.
- Response `204`: no body. Unknown, foreign, or already revoked keys return `404 KEY_NOT_FOUND`.

#### POST /users/{id}/public-keys/revoke-all

- Auth: required; `ADMIN` only; signature required.
- Revokes all active keys for the target user. Response `200`: `{"revoked_count": 2}`. Repeating returns count zero.
- Zero active keys require setup again. Unknown users return `404 USER_NOT_FOUND` for all key-management endpoints.

#### GET /users/{id}/public-key

- Auth: required
- Access: owner or `ADMIN`
- Compatibility endpoint: newest active key. Without an active key: `400 INVALID_REQUEST`.
- Response `200`:

```json
{
  "public_key": "-----BEGIN PUBLIC KEY-----...",
  "fingerprint": "sha256-hex",
  "created_at": "...",
  "expires_at": "..."
}
```

#### PATCH /users/{id}/password

- Auth: required
- Access: owner or `ADMIN`
- Signature headers: exempt
- Request:

```json
{"new_password":"NewStrongPass123!"}
```

- Response `200`:

```json
{
  "message": "Password changed successfully",
  "requires_setup": false,
  "setup_pending": [],
  "must_change_password": false
}
```

#### GET /users/{id}/tokens

- Auth: required
- Access: owner or `ADMIN`
- Response `200`:

```json
{
  "tokens": [
    {
      "id": "uuid",
      "name": "login-20260411-120000",
      "last_used_at": "...",
      "revoked_at": null,
      "created_at": "..."
    }
  ]
}
```

#### POST /users/{id}/tokens

- Auth: required
- Access: owner or `ADMIN`
- Signature headers: required
- Request:

```json
{"name":"automation-token"}
```

- Response `201`:

```json
{
  "id": "uuid",
  "name": "automation-token",
  "token": "<raw-token-shown-once>"
}
```

#### DELETE /users/{id}/tokens/{token_id}

- Auth: required
- Access: owner or `ADMIN`
- Signature headers: required
- Response: `204 No Content`

#### GET /users/{id}/assignments

- Auth: required
- Access: owner or `ADMIN` (`RequireOwnerOrAdmin`)
- Response `200`: array of assignment rows:

```json
[
  {
    "id": "uuid",
    "build_id": "uuid",
    "role_id": "uuid",
    "user_id": "uuid",
    "assigned_by": "uuid",
    "assigned_at": "...",
    "role_name": "AUDITOR",
    "build_name": "Build A",
    "build_status": "ENVIRONMENT_STAGED"
  }
]
```

---

### 7.5 System Logs

#### GET /system-logs

- Auth: required
- Roles: `ADMIN` or `AUDITOR`
- Query params:
  - `limit` (default `100`)
  - `offset` (default `0`)
- Response `200`: array of logs

```json
[
  {
    "id": "uuid",
    "timestamp": "...",
    "actor_email": "user@example.com",
    "action": "USER_LOGIN",
    "resource": "Authentication System",
    "ip_address": "127.0.0.1",
    "status": "SUCCESS",
    "details": "User logged in successfully"
  }
]
```

---

### 7.6 Builds

#### GET /builds

- Auth: required
- Access behavior:
  - `ADMIN`: full paginated list.
  - Non-admin: only builds where caller is assigned.
- Query params:
  - `limit` default `50`, max `100`
  - `offset` default `0`
  - `status` optional exact status filter
- Response `200`:

```json
{
  "builds": [
    {
      "id": "uuid",
      "name": "Build A",
      "status": "CREATED",
      "created_by": "uuid",
      "created_at": "...",
      "finalized_at": null,
      "contract_hash": null,
      "is_immutable": false
    }
  ],
  "limit": 50,
  "offset": 0
}
```

#### POST /builds

- Auth: required
- Role: `ADMIN` or `AUDITOR`
- Signature headers: required
- Request:

```json
{"name":"Build A"}
```

- Response `201`: build object

#### GET /builds/{id}

- Auth: required
- Access: `ADMIN` or assigned user (`RequireBuildAccess`)
- Response `200`: build object

All `/builds/{id}/...` endpoints below inherit the same `RequireBuildAccess` middleware.

#### POST /builds/{id}/cancel

- Auth: required
- Role: `ADMIN` or `AUDITOR`
- Signature headers: required
- Response `200`:

```json
{"status":"CANCELLED"}
```

---

### 7.7 Build Assignments

#### GET /builds/{id}/assignments

- Auth: required
- Access: `ADMIN` or assigned user (`RequireBuildAccess`)
- Response `200`: array

```json
[
  {
    "id": "uuid",
    "build_id": "uuid",
    "role_id": "uuid",
    "user_id": "uuid",
    "assigned_by": "uuid",
    "assigned_at": "...",
    "role_name": "ENV_OPERATOR",
    "user_name": "Operator User",
    "user_email": "operator@example.com"
  }
]
```

#### POST /builds/{id}/assignments

- Auth: required
- Role: `ADMIN` or `AUDITOR`
- Signature headers: required
- Request:

```json
{
  "role_id": "uuid",
  "role_name": "ENV_OPERATOR",
  "user_id": "uuid"
}
```

Notes:

- `role_id` or `role_name` required.
- Build must not be terminal.
- One assignment per role per build (DB uniqueness on `build_id, role_id`).
- Assignable roles are limited to workflow roles: `SOLUTION_PROVIDER`, `DATA_OWNER`, `AUDITOR`, `ENV_OPERATOR`.
- Assignee must already hold the target role globally.

- Response `201`: assignment object

#### DELETE /builds/{id}/assignments

- Auth: required
- Role: `ADMIN`
- Signature headers: required
- Response: `204 No Content`

---

### 7.9 Audit Trail & Verification

#### GET /builds/{id}/audit
#### GET /builds/{id}/audit-trail

Both endpoints return identical payloads.

- Auth: required
- Response `200`:

```json
{
  "audit_events": [
    {
      "id": "uuid",
      "build_id": "uuid",
      "sequence_no": 1,
      "event_type": "BUILD_CREATED",
      "actor_user_id": "uuid",
      "actor_name": "System Admin",
      "actor_public_key": null,
      "actor_key_fingerprint": null,
      "ip_address": "127.0.0.1",
      "device_metadata": {},
      "event_data": {"build_name":"Build A"},
      "previous_event_hash": "...",
      "event_hash": "...",
      "signature": null,
      "created_at": "..."
    }
  ]
}
```

#### GET /builds/{id}/verify

- Auth: required
- Response `200`:

```json
{
  "is_valid": true,
  "total_events": 6,
  "verified_events": 6,
  "failed_events": [],
  "genesis_hash": "...",
  "chain_intact": true,
  "signatures_valid": true
}
```

#### GET /builds/{id}/verify-contract

- Auth: required
- Response `200`:

```json
{
  "build_id": "uuid",
  "is_valid": true,
  "is_finalized": true,
  "is_immutable": true,
  "contract_hash": "...",
  "computed_hash": "...",
  "hash_matches": true,
  "signature_valid": true,
  "details": "contract integrity verified"
}
```

Note:

- `is_finalized` is true for both `FINALIZED` and `CONTRACT_DOWNLOADED`.

---

### 7.10 Export & Download Acknowledgment

#### GET /builds/{id}/export

- Auth: required
- Effective authorization (service): assigned `ENV_OPERATOR` only
- Build must be `FINALIZED`
- Not allowed after download acknowledgment
- Response `200`:

```json
{
  "contract_yaml": "...",
  "contract_hash": "...",
  "build_id": "uuid",
  "build_name": "Build A",
  "finalized_at": "2026-04-11T12:34:56+05:30"
}
```

#### GET /builds/{id}/userdata

- Auth: required
- Effective authorization (service): assigned `ENV_OPERATOR` only
- Build must be `FINALIZED`
- Not allowed after download acknowledgment
- Response `200`:

```json
{
  "contract_yaml": "raw-yaml-or-decoded-from-base64",
  "contract_hash": "...",
  "build_id": "uuid"
}
```

#### POST /builds/{id}/acknowledge-download

- Auth: required
- Signature headers: required (request-level)
- Effective authorization: assigned `ENV_OPERATOR` only
- Build must be `FINALIZED`
- One-time operation

Request:

```json
{
  "contract_hash": "sha256-hex",
  "signature": "base64-rsa-pss-signature-of-contract-hash"
}
```

Verification performed:

1. Build contract hash matches request hash.
2. Caller is assigned `ENV_OPERATOR`.
3. Caller has registered public key.
4. Signature verifies against caller public key.

Success response:

- `204 No Content`

On success, backend also:

- logs `CONTRACT_DOWNLOADED` audit event
- transitions build status to `CONTRACT_DOWNLOADED`

---

### 7.11 Credential Rotation

All rotation endpoints require `ADMIN`. Mutating rotation endpoints require request signature headers.

Expired public keys are reported per key, excluding revoked keys. `users_without_active_key` separately lists active accounts needing key setup; `total_expired` counts expired passwords plus expired keys and excludes this separate list.

#### GET /rotation/expired

- Response `200`:

```json
{
  "expired_passwords": [
    {
      "user_id": "uuid",
      "user_name": "User A",
      "user_email": "a@example.com",
      "password_age": "2160h0m0s",
      "last_changed": "...",
      "must_change": true
    }
  ],
  "expired_public_keys": [
    {
      "key_id": "uuid",
      "label": "Office laptop",
      "fingerprint": "sha256-hex",
      "user_id": "uuid",
      "user_name": "User B",
      "user_email": "b@example.com",
      "key_age": "2160h0m0s",
      "registered_at": "...",
      "expires_at": "...",
      "days_overdue": 3
    }
  ],
  "users_without_active_key": [
    {"user_id": "uuid", "user_name": "User C", "user_email": "c@example.com"}
  ],
  "total_expired": 2,
  "checked_at": "..."
}
```

#### POST /rotation/force-password-change/{user_id}

- Response `200`:

```json
{"message":"Password change forced successfully"}
```

#### POST /rotation/revoke-key/{user_id}

- Revokes only expired, unrevoked keys and records the administrator as actor. Active keys remain usable; manual revocation uses the single-key or revoke-all endpoints.
- Response `200`:

```json
{"message":"Public key revoked successfully"}
```

---

### 7.12 V2: Key Management

All key management endpoints require `BuildAccess` middleware and are nested under `/builds/{id}/keys/...`.

For `contract-go` HPCR operations that require private keys, backend workers retrieve the AES-256-CBC encrypted PEM from `build_keys_private`, decrypt it in-memory using the caller-supplied passphrase, and zeroize memory after cryptographic operations. Private keys are never returned by API responses.

#### POST /builds/{id}/keys/signing

- Auth: required
- Role: `AUDITOR`
- Signature headers: required
- Request:

```json
{
  "mode": "generate"
}
```

- Response `201`:

```json
{
  "key_id": "uuid",
  "key_type": "SIGNING",
  "mode": "generate",
  "public_key": "-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----",
  "public_key_fingerprint": "sha256-hex",
  "created_at": "..."
}
```

- Transitions build to `SIGNING_KEY_REGISTERED`.

#### POST /builds/{id}/keys/attestation

- Auth: required
- Role: `AUDITOR`
- Signature headers: required
- Request (generate mode):

```json
{
  "mode": "generate"
}
```

- Request (upload mode):

```json
{
  "mode": "upload_public",
  "public_key": "-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----"
}
```

- Response `201`: key object (same shape as signing key response).
- Transitions build to `ATTESTATION_KEY_REGISTERED`.

#### GET /builds/{id}/keys/signing/public

- Auth: required
- Response `200`:

```json
{
  "key_id": "uuid",
  "public_key": "-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----",
  "public_key_fingerprint": "sha256-hex"
}
```

---

### 7.13 V2: Backend-Native Contract Operations

Template retrieval is global (not build-scoped). Section submission and finalization remain build-scoped.

#### GET /v2/encryption-certificates/versions

- Auth: required
- Response `200`: list of available HPCR encryption certificate versions that can be used as `certificate_pem` in section submission.

#### POST /v2/contract-template

- Auth: required
- Signature headers: required
- Request:

```json
{
  "type": "workload"
}
```

`type` must be either `workload` or `env`.

- Response `200`:

```json
{
  "template_type": "workload",
  "content": "..."
}
```

- Templates are common for all builds.

#### POST /builds/{id}/v2/sections/workload

- Auth: required
- Signature headers: required
- Uses large body parser (up to 50MB).
- Request:

```json
{
  "plaintext": "workload section YAML content",
  "certificate_pem": "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----"
}
```

- Response `201`: section object with `encrypted_payload`, `section_hash`.
- Backend encrypts plaintext using `contract-go` engine with the provided HPCR certificate.
- Transitions build to `WORKLOAD_SUBMITTED`.

#### POST /builds/{id}/v2/sections/environment

- Auth: required
- Signature headers: required
- Uses large body parser (up to 50MB).
- Request:

```json
{
  "plaintext": "environment section YAML content",
  "certificate_pem": "-----BEGIN CERTIFICATE-----...-----END CERTIFICATE-----"
}
```

- Response `201`: section object.
- Transitions build to `ENVIRONMENT_STAGED`.

#### POST /builds/{id}/v2/finalize

- Auth: required
- Role: `AUDITOR`
- Signature headers: required
- Request:

```json
{
  "signing_key_id": "uuid",
  "attestation_key_id": "uuid-or-null",
  "attestation_cert_pem": "PEM-or-empty"
}
```

- Response `200`:

```json
{
  "status": "FINALIZED",
  "contract_hash": "sha256-hex",
  "contract_yaml_length": 12345
}
```

- Backend loads encrypted sections, retrieves encrypted signing key PEM from `build_keys_private`, decrypts with passphrase, signs via `HpcrContractSign(...)`, assembles YAML.
- Transitions build to `FINALIZED`.

---

### 7.14 V2: Attestation Evidence

All attestation endpoints require `BuildAccess` middleware and are nested under `/builds/{id}/attestation/...`.

#### POST /builds/{id}/attestation/evidence

- Auth: required
- Role: assigned `DATA_OWNER` or assigned `ENV_OPERATOR`
- Signature headers: required
- Content-Type:
  - `application/json` (recommended for signed desktop clients)
  - `multipart/form-data` (max 10MB total)
- JSON body fields:
  - `records_file_name` (optional)
  - `records_content` or `records_content_base64` (required)
  - `signature_file_name` (optional)
  - `signature_content` or `signature_content_base64` (required)
  - `metadata` (optional object)
- Multipart form fields:
  - `records_file` (required): attestation records file
  - `signature_file` (required): signature file
  - Additional metadata fields (optional)
- JSON upload defaults:
  - `records_file_name` defaults to `attestation-records.txt` when omitted
  - `signature_file_name` defaults to `attestation-signature.sig` when omitted

- Response `201`:

```json
{
  "evidence_id": "uuid",
  "build_id": "uuid",
  "uploaded_by": "uuid",
  "records_file_name": "se-checksums.txt",
  "signature_file_name": "se-checksums.txt.sig",
  "created_at": "...",
  "state": "UPLOADED"
}
```

- Upload guardrails:
  - Build status must be `FINALIZED` or `CONTRACT_DOWNLOADED`
  - `attestation_state` must be `PENDING_UPLOAD` or `REJECTED`
- Updates `attestation_state` to `UPLOADED`.

#### POST /builds/{id}/attestation/evidence/{evidence_id}/verify

- Auth: required
- Role: assigned `AUDITOR`
- Signature headers: required
- Request body (optional JSON):

```json
{
  "attestation_key_passphrase": "optional-passphrase-for-encrypted-attestation-private-key"
}
```

- Verification uses stored evidence + attestation key material retrieved from `build_keys_private` and decrypted with the supplied passphrase.
- Verification guardrails:
  - Build status must be `FINALIZED` or `CONTRACT_DOWNLOADED`
  - `attestation_state` must be `UPLOADED`

- Response `200`:

```json
{
  "verification_id": "uuid",
  "evidence_id": "uuid",
  "verdict": "VERIFIED",
  "state": "VERIFIED",
  "details": {
    "records_decrypted": true,
    "records_hash": "sha256-hex",
    "signature_valid": true,
    "key_fingerprint": "sha256-hex"
  },
  "verified_at": "..."
}
```

- Verification flow: `HpcrGetAttestationRecords(...)` decrypts uploaded attestation records (using the supplied passphrase when the private key is encrypted), then `HpcrVerifySignatureAttestationRecords(...)` validates signature/certificate.
- On rejected outcomes, `details.reason` returns the contract-go/key-resolution failure reason used by the verifier.
- Updates `attestation_state` to `VERIFIED` or `REJECTED`.

#### GET /builds/{id}/attestation/status

- Auth: required
- Response `200`:

```json
{
  "build_id": "uuid",
  "attestation_state": "VERIFIED",
  "state": "VERIFIED",
  "evidence_count": 1,
  "latest_verdict": "VERIFIED",
  "verified_at": "...",
  "verified_by": "uuid",
  "last_result": {
    "verification_id": "uuid",
    "evidence_id": "uuid",
    "verdict": "VERIFIED",
    "details": {
      "records_decrypted": true,
      "signature_valid": true,
      "records_hash": "sha256-hex",
      "key_fingerprint": "sha256-hex"
    },
    "created_at": "..."
  }
}
```

---

## 8. Error Model

### 8.1 Standard Error Envelope

Most handler/service errors use:

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human readable message",
    "details": {}
  }
}
```

### 8.2 Common HTTP Statuses

- `200 OK`
- `201 Created`
- `204 No Content`
- `400 Bad Request`
- `401 Unauthorized`
- `403 Forbidden`
- `404 Not Found`
- `409 Conflict`
- `422 Unprocessable Entity`
- `429 Too Many Requests`
- `500 Internal Server Error`

### 8.3 Error Codes Used by Implementation

Common codes surfaced by handlers/services/middleware:

- `INVALID_REQUEST`
- `INVALID_CREDENTIALS`
- `UNAUTHORIZED`
- `FORBIDDEN`
- `NOT_FOUND`
- `BUILD_NOT_FOUND`
- `USER_NOT_FOUND`
- `DUPLICATE_EMAIL`
- `DUPLICATE_SECTION`
- `INVALID_STATE_TRANSITION`
- `BUILD_IMMUTABLE`
- `HASH_MISMATCH`
- `INVALID_SIGNATURE`
- `INVALID_SIGNATURE_HEADERS`
- `SIGNATURE_EXPIRED`
- `SIGNATURE_KEY_MISSING`
- `ACCOUNT_SETUP_REQUIRED`
- `INTERNAL_ERROR`

Note:

- Rate-limit middleware returns plain text (not `AppError` JSON).

---

## 9. Configuration (Environment Variables)

Core runtime values loaded in `internal/config/config.go`:

| Variable | Default | Purpose |
|---|---|---|
| `SERVER_HOST` | `0.0.0.0` | bind host |
| `SERVER_PORT` | `8080` | bind port |
| `DATABASE_URL` | required | Postgres connection string |
| `TOKEN_EXPIRY` | `24h` | bearer token TTL |
| `BCRYPT_COST` | `12` | password hash cost |
| `LOG_LEVEL` | `info` | logging level |
| `LOG_FORMAT` | `json` | `json` or `text` |
| `MAX_PAYLOAD_SIZE` | `52428800` | global max request body bytes |
| `CORS_ALLOWED_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173,null` | CORS allow list |
| `CORS_ALLOW_ALL` | `false` | allow wildcard CORS |
| `TRUST_PROXY_HEADERS` | `false` | trust forwarded IP headers |
| `REQUEST_TIMEOUT` | `30s` | per-request context timeout |

Additional startup seeding variables (read in `cmd/server/main.go` during initial-admin bootstrap):

| Variable | Default | Purpose |
|---|---|---|
| `ADMIN_EMAIL` | `admin@hpcr-builder.local` | seeded admin email if DB has no users |
| `ADMIN_PASSWORD` | `admin123` | seeded admin password fallback (development only) |
| `ADMIN_NAME` | `System Admin` | seeded admin display name |

> There is no `KEY_PROVIDER` env var or any Vault configuration. The PostgreSQL key provider is the sole active implementation, wired unconditionally in `cmd/server/main.go`.

---

## 10. Operational Notes

### 10.1 Swagger/OpenAPI Endpoint Scope

`/openapi.json` is currently a static embedded document. It is useful for exploration but may lag behind implementation details. This file (`4-api-documentation.md`) is the detailed implementation-aligned reference.

### 10.2 Contract Download Finalization Semantics

`CONTRACT_DOWNLOADED` indicates verified receipt and is terminal.

Effects:

- export/userdata/acknowledge endpoints reject further download actions
- build remains immutable
- audit chain includes `CONTRACT_DOWNLOADED` signed event

### 10.3 Audit Verification Summary

`GET /builds/{id}/verify` validates:

1. genesis hash linkage
2. previous hash continuity
3. per-event event hash recomputation
4. required signatures per event type

`GET /builds/{id}/verify-contract` validates:

1. build finalized/downloaded state
2. hash of stored contract content
3. signature in `BUILD_FINALIZED` event

### 10.4 Known Access-Behavior Detail

- `GET /users/{id}/assignments` is owner-or-admin only.
- `GET /builds` is assignment-filtered for non-admin users.
- `/builds/{id}` and all nested build routes require admin or build assignment.
