# Contract Manager — API Reference

**Base URL:** `http://localhost:8080`  
**Content-Type:** `application/json` (all requests and responses)  
**Rate limit:** 10 req/s (burst 20) per IP on all routes except `/health`  
**Auth rate limit:** 1 req/12s (burst 3) on `POST /auth/login`

---

## Global conventions

### Authentication

All authenticated routes require a `Bearer` token in the `Authorization` header obtained from `POST /auth/login`.

```
Authorization: Bearer <token>
```

### Signature headers

All authenticated **mutating** requests (`POST`, `PUT`, `PATCH`, `DELETE`) require signature headers. Logout and password change are exempt; public-key registration is exempt only when the caller has no active keys.

| Header | Description |
|---|---|
| `X-Signature` | RSA-PSS Base64 signature of the SHA-256 hex string in `X-Signature-Hash` |
| `X-Signature-Hash` | SHA-256 hex digest of the canonical payload below |
| `X-Timestamp` | Unix timestamp in milliseconds |
| `X-Key-Fingerprint` | SHA-256 fingerprint of the signing key: 64 lowercase hex characters. Required with multiple active keys; omission is accepted only with exactly one active key. Uppercase and colon-separated hex are normalized. |

Canonical signed payload:
```json
{ "method": "POST", "path": "/builds", "data": <body>, "timestamp": <ms> }
```

### Error response shape

```json
{ "error": { "code": "NOT_FOUND", "message": "Human-readable message." } }
```

### Roles

`ADMIN` · `AUDITOR` · `DATA_OWNER` · `ENV_OPERATOR`

---

## 1. Infrastructure

### `GET /health`

No auth. Not rate-limited.

**Response `200`**
```json
{ "status": "ok" }
```

---

### `GET /about`

No auth.

**Response `200`** — server version and build metadata.

---

### `GET /openapi.json`

No auth. Returns the OpenAPI 3 specification.

---

### `GET /swagger` · `GET /swagger/`

No auth. Swagger UI.

---

## 2. Authentication

### `POST /auth/login`

No auth. Strict rate limit (1 req/12s, burst 3). **Signature headers not required.**

**Request**
```json
{ "email": "user@example.com", "password": "secret" }
```

**Response `200`**
```json
{
  "token": "eyJ...",
  "expires_at": "2024-01-02T15:04:05Z",
  "requires_setup": false,
  "setup_pending": [],
  "user": {
    "id": "uuid", "name": "Alice", "email": "...", "roles": ["ADMIN"],
    "has_public_key": true, "public_key_expired": false, "active_key_count": 2,
    "public_key_fingerprint": "64-lowercase-hex-characters",
    "public_key_expires_at": "2026-12-01T00:00:00Z"
  }
}
```

`has_public_key` means at least one active key. The legacy fingerprint and expiry fields show the newest active key, or `null` when none exists. `public_key_expired` is a legacy renewal flag: it is true when key history exists but no key is active, including after revocation. Setup requires a key only when the active count is zero; another device's expired key does not block access. `GET /users` also returns `active_key_count` and the newest active key metadata.

**Errors:** `401 INVALID_CREDENTIALS`

---

### `GET /auth/oidc/login`

No auth. Returns `404` when SSO is not configured.

**Query:** `state` (optional) — passed unchanged to the provider URL. The backend does not verify it; the client must.

**Response `200`**
```json
{ "url": "https://<oauth-server>/authorize?client_id=...&state=..." }
```

---

### `POST /auth/oidc/callback`

No auth. Strict rate limit (1 req/12s, burst 3). **Signature headers not required.** The user must already exist and be active; no account is created.

**Request**
```json
{ "code": "authorization-code" }
```

**Response `200`** Same as `POST /auth/login`.

**Errors:** `400` missing `code` · `401 INVALID_CREDENTIALS` (any failure, reason not disclosed) · `404` SSO not configured

---

### `POST /auth/logout`

Auth required. **Signature headers not required (exempt).**

**Response `204`** No Content.

---

## 3. Roles

### `GET /roles`

Auth required.

**Response `200`**
```json
{ "roles": ["ADMIN", "AUDITOR", "DATA_OWNER", "ENV_OPERATOR"] }
```

---

## 4. Users

### `GET /users`

Auth required. Role: `ADMIN` or `AUDITOR`.

**Response `200`**
```json
{
  "users": [
    { "id": "uuid", "name": "Alice", "email": "...", "roles": ["ADMIN"], "is_active": true }
  ]
}
```

---

### `POST /users`

Auth required. Role: `ADMIN`. Signature headers required.

**Request**
```json
{
  "name": "Bob Smith",
  "email": "bob@example.com",
  "password": "minimum8chars",
  "roles": ["AUDITOR"]
}
```

At least one valid role is required.

**Response `201`** — full user object.  
**Errors:** `400 INVALID_REQUEST`, `409 DUPLICATE_EMAIL`

---

### `PATCH /users/{id}`

Auth required. Role: `ADMIN`. Signature headers required.

**Request**
```json
{ "name": "New Name", "email": "new@example.com" }
```

**Response `200`** — updated user object.  
**Errors:** `404 USER_NOT_FOUND`, `409 DUPLICATE_EMAIL`

---

### `PATCH /users/{id}/roles`

Auth required. Role: `ADMIN`. Signature headers required.

**Request**
```json
{ "roles": ["DATA_OWNER", "AUDITOR"] }
```

**Response `200`** — updated user object.

---

### `DELETE /users/{id}`

Auth required. Role: `ADMIN`. Signature headers required. Soft-deactivates the user.

**Response `200`**
```json
{ "message": "User deactivated successfully." }
```

---

### `PATCH /users/{id}/reactivate`

Auth required. Role: `ADMIN`. Signature headers required.

**Response `200`**
```json
{ "message": "User reactivated successfully." }
```

---

### `PATCH /users/{id}/password`

Auth required. Owner or `ADMIN`. **Signature headers not required (exempt).**

**Request**
```json
{ "new_password": "minimum8chars" }
```

**Response `200`**
```json
{
  "message": "Password changed successfully",
  "requires_setup": false,
  "setup_pending": [],
  "must_change_password": false
}
```

---

### `PATCH /users/{id}/reset-password`

Auth required. Role: `ADMIN`. Signature headers required. Forces next-login password change.

**Request**
```json
{ "new_password": "minimum8chars" }
```

**Response `200`**
```json
{ "message": "Password reset successfully. User must change password on next login." }
```

---

### `PUT /users/{id}/public-key`

Auth required. **Owner only**, including admins adding their own key. Adds one RSA-4096 client key; existing keys remain registered. Maximum **5 active keys**, each valid for **90 days**. Active means not revoked and `expires_at > now`.

Signature headers are required if an active key already exists. If none exists, registration is unsigned. `password` must confirm the account password whenever the user has ever registered a key, even if all earlier keys are expired or revoked. First registration needs no password. Registration is rate limited (2 requests/second, burst 5).

**Request**
```json
{
  "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "label": "Office laptop",
  "password": "current-account-password"
}
```

`label` is optional, trimmed, at most 100 characters; an empty label defaults to `Key YYYY-MM-DD` (UTC). Fingerprints are globally unique, including revoked keys.

**Response `200`**
```json
{
  "key_id": "uuid",
  "label": "Office laptop",
  "fingerprint": "64-lowercase-hex-characters",
  "message": "Public key registered successfully",
  "created_at": "2024-01-01T00:00:00Z",
  "expires_at": "2024-03-31T00:00:00Z",
  "requires_setup": false,
  "setup_pending": [],
  "must_change_password": false
}
```

**Errors:** `400 INVALID_REQUEST`, `403 PASSWORD_CONFIRMATION_FAILED`, `403 FORBIDDEN`, `409 KEY_ALREADY_REGISTERED`, `409 KEY_LIMIT_REACHED`. Signature errors include `400 INVALID_SIGNATURE_HEADERS`, `400 INVALID_SIGNATURE`, `403 SIGNATURE_KEY_FINGERPRINT_REQUIRED`, `403 SIGNATURE_KEY_REVOKED`, and `403 SIGNATURE_KEY_EXPIRED`. An unknown or foreign fingerprint returns `403 INVALID_SIGNATURE`.

---

### `GET /users/{id}/public-keys`

Auth required. Owner or `ADMIN`. Returns **all** registered keys, including expired and revoked ones; an empty history returns `{"keys": []}`. Each row contains `id`, `user_id`, `label`, `public_key`, `fingerprint`, `registered_at`, `expires_at`, `last_used_at`, `revoked_at`, and `revoked_by`. The last three fields are nullable; `last_used_at` is reserved and currently not updated. Derive active status from expiry and revocation fields. Unknown users return `404 USER_NOT_FOUND`.

### `DELETE /users/{id}/public-keys/{key_id}`

Auth required. Owner or `ADMIN`. Signature headers required, using an active key belonging to the **caller**. Records revocation time and actor; keys remain in history. Expired, unrevoked keys can also be revoked. The caller may revoke their own signing key.

**Response `204`** No Content. Unknown, foreign, or already revoked keys return `404 KEY_NOT_FOUND`; unknown owners return `404 USER_NOT_FOUND`.

### `POST /users/{id}/public-keys/revoke-all`

Auth required. `ADMIN` only. Signature headers required. Revokes all **active** keys for the target user; expired keys are handled by rotation. Unknown users return `404 USER_NOT_FOUND`.

**Response `200`** `{"revoked_count": 2}`. Repeating the operation returns `{"revoked_count": 0}`. With zero active keys, the target must register a new key before using regular routes.

---

### `GET /users/{id}/public-key`

Auth required. Owner or `ADMIN`. Compatibility endpoint: returns the **newest active** key. No active key returns `400 INVALID_REQUEST`; unknown users return `404 USER_NOT_FOUND`.

**Response `200`**
```json
{
  "public_key": "-----BEGIN PUBLIC KEY-----\n...",
  "fingerprint": "64-lowercase-hex-characters",
  "created_at": "2024-01-01T00:00:00Z",
  "expires_at": "2025-01-01T00:00:00Z"
}
```

---

### `GET /users/{id}/tokens`

Auth required. Owner or `ADMIN`.

**Response `200`**
```json
{ "tokens": [ { "id": "uuid", "name": "CI token", "created_at": "..." } ] }
```

---

### `POST /users/{id}/tokens`

Auth required. Owner or `ADMIN`. Signature headers required.

**Request**
```json
{ "name": "CI token" }
```

**Response `201`**
```json
{
  "id": "uuid",
  "token": "raw-token-only-shown-once",
  "name": "CI token",
  "created_at": "..."
}
```

> The raw token value is returned **only on creation** and cannot be retrieved again.

---

### `DELETE /users/{id}/tokens/{token_id}`

Auth required. Owner or `ADMIN`. Signature headers required.

**Response `204`** No Content.

---

### `GET /users/{id}/assignments`

Auth required. Owner or `ADMIN`.

**Response `200`** — list of build assignment objects the user belongs to.

---

## 5. Builds

### `GET /builds`

Auth required. Any authenticated user. Non-admins see only their assigned builds.

**Query params**

| Param | Default | Description |
|---|---|---|
| `limit` | `50` | Max results (1–100) |
| `offset` | `0` | Pagination offset |
| `status` | — | Filter by build status |

**Response `200`**
```json
{
  "builds": [ { "id": "uuid", "name": "...", "status": "CREATED", "created_at": "..." } ],
  "limit": 50,
  "offset": 0
}
```

---

### `POST /builds`

Auth required. Role: `ADMIN` or `AUDITOR`. Signature headers required.

**Request**
```json
{ "name": "My Contract Build" }
```

**Response `201`** — full build object with `status: "CREATED"`.

---

### `GET /builds/{id}`

Auth required. Build access required (assigned users or `ADMIN`).

**Response `200`** — full build object.

**Build status lifecycle:**
```
CREATED
  └─► SIGNING_KEY_REGISTERED
        └─► WORKLOAD_SUBMITTED
              └─► ENVIRONMENT_STAGED
                    └─► ATTESTATION_KEY_REGISTERED
                          └─► FINALIZED
                                └─► CONTRACT_DOWNLOADED

Any non-terminal state ──► CANCELLED
```

---

### `POST /builds/{id}/cancel`

Auth required. Role: `ADMIN` or `AUDITOR`. Build access required. Signature headers required.

**Response `200`**
```json
{ "status": "CANCELLED" }
```

---

## 6. Build assignments

### `GET /builds/{id}/assignments`

Auth required. Any authenticated user with build access.

**Response `200`**
```json
[
  { "user_id": "uuid", "user_name": "Alice", "role": "AUDITOR", "assigned_at": "..." }
]
```

---

### `POST /builds/{id}/assignments`

Auth required. Role: `ADMIN` or `AUDITOR`. Build access required. Signature headers required.

**Request** — use either `role_id` or `role_name`:
```json
{ "user_id": "uuid", "role_name": "DATA_OWNER" }
```

**Response `201`** — assignment object.

---

### `DELETE /builds/{id}/assignments`

Auth required. Role: `ADMIN`. Build access required. Signature headers required. Removes **all** assignments for the build.

**Response `204`** No Content.

---

## 7. Audit trail

### `GET /builds/{id}/audit` · `GET /builds/{id}/audit-trail`

Auth required. Build access required. Both paths are equivalent.

**Response `200`**
```json
{
  "audit_events": [
    {
      "id": "uuid",
      "event_type": "BUILD_CREATED",
      "actor_id": "uuid",
      "actor_name": "Alice",
      "ip_address": "10.0.0.1",
      "timestamp": "2024-01-01T00:00:00Z",
      "metadata": {}
    }
  ]
}
```

---

## 8. Key management

In `generate` mode, passphrases require at least 12 characters, an uppercase
letter, a lowercase letter, a digit and a special character. Missing or weak
passphrases return `400 INVALID_REQUEST` with the specific unmet rule before
keys or certificate pins are stored. `upload_public` does not require a passphrase.
Leading and trailing whitespace is trimmed consistently for registration, finalization and evidence verification. Internal whitespace remains significant.
Keep the signing-key passphrase for finalization and the attestation-key passphrase
for evidence verification; they are separate from the account login password.

### `POST /builds/{id}/keys/signing`

Auth required. Role: `AUDITOR`. Build access required. Signature headers required.

**Request — generate mode** (backend creates RSA-4096 key, encrypts private key with passphrase):
```json
{
  "mode": "generate",
  "passphrase": "Example!Signing2026"
}
```

**Request — upload_public mode** (caller provides their own public key):
```json
{
  "mode": "upload_public",
  "public_key": "-----BEGIN PUBLIC KEY-----\n..."
}
```

`mode` defaults to `generate` if omitted.

**Response `201`**
```json
{
  "signing_key_id": "uuid",
  "public_key": "-----BEGIN PUBLIC KEY-----\n...",
  "fingerprint": "SHA256:...",
  "mode": "generate"
}
```

Transitions build: `CREATED → SIGNING_KEY_REGISTERED`

---

### `POST /builds/{id}/keys/attestation`

Auth required. Role: `AUDITOR`. Build access required. Signature headers required.

**Request**
```json
{
  "mode": "generate",
  "passphrase": "Example!Attestation2026",
  "encryption_cert_pem": "-----BEGIN CERTIFICATE-----\n..."
}
```

`encryption_cert_pem` is required in both `generate` and `import` modes — the attestation public key is encrypted with the runtime encryption certificate before storage.

**Response `201`**
```json
{
  "attestation_key_id": "uuid",
  "public_key": "<encrypted-attestation-public-key>",
  "fingerprint": "SHA256:...",
  "mode": "generate"
}
```

Transitions build: `ENVIRONMENT_STAGED → ATTESTATION_KEY_REGISTERED`

---

### `GET /builds/{id}/keys/signing/public`

Auth required. Assigned `DATA_OWNER`, `AUDITOR`, or `ADMIN`. Build access required.

**Response `200`**
```json
{
  "signing_key_id": "uuid",
  "public_key": "-----BEGIN PUBLIC KEY-----\n...",
  "fingerprint": "SHA256:...",
  "mode": "generate"
}
```

---

## 9. V2 contract operations

### `POST /v2/contract-template`

Auth required. Signature headers required.

**Request**
```json
{ "type": "workload" }
```

`type` must be `workload` or `env`.

**Response `200`**
```json
{ "template_type": "workload", "content": "# YAML template content..." }
```

---

### `GET /v2/encryption-certificates/versions`

Auth and completed account setup required. Also available without `/v2`.

The pinned contract-go v2.37.0 library supplies four distinct identifiers: `ccrt`, `ccrv`, `ccco`, `hpvs`. Preserve their associations rather than treating IBM Cloud regions as platforms. Versions are sorted newest first; platform entries are ordered by identifier. The existing flat `versions` list remains available for older clients.

**Response `200`** (abbreviated example)
```json
{
  "versions": ["26.7.2", "26.5.0", "26.4.1", "26.4.0", "26.2.0", "25.12.0", "25.10.0", "25.8.1", "1.0.29", "1.0.28", "1.0.27"],
  "platforms": [
    { "id": "ccrt", "versions": ["26.7.2", "26.5.0", "26.2.0"], "contract_supported": true }
  ]
}
```

`contract_supported` describes this application's contract workflow, currently CCRT only. A library certificate catalog entry does not enable another platform's schema or export format. Current upstream v3 documentation treats HPVS as a CCRT alias; do not apply those semantics to this pinned v2 catalog.

The catalog includes the library's historical versions. A lookup rejects a certificate that is expired, not yet valid or unsuitable for encryption; users must select a usable certificate matching their actual installed runtime. This is a library snapshot, not a live IBM release feed.

### `GET /v2/encryption-certificates/certificate?platform=ccrt&version=26.7.2`

Auth and completed account setup required. Also available without `/v2`. Supply exactly one nonempty `platform` and `version`. Platform input is case-insensitive. Unknown pairs return `404`; incomplete/duplicate parameters and unusable certificates return `400` with a structured application error. No user-provided URL or filesystem path is accessed.

**Response `200`**
```json
{
  "platform": "ccrt",
  "version": "26.7.2",
  "certificate_pem": "-----BEGIN CERTIFICATE-----\n...",
  "fingerprint_sha256": "9e2a411b34f1917cc0ec8171b46da9f21985193610e6f065244cffe4036695ea",
  "not_before": "2026-07-06T18:16:20Z",
  "not_after": "2027-06-20T23:59:59Z",
  "contract_supported": true
}
```

The fingerprint is SHA-256 over the certificate's DER bytes. Both endpoints send `Cache-Control: no-store`; submission rechecks certificate validity and the build's pinned recipient.

---

### `POST /builds/{id}/v2/sections/workload`

Auth required. Build access required. Signature headers required. Max body: **50 MB**.

Backend encrypts `plaintext` using the CCRT contract engine with the provided certificate.

**Request**
```json
{
  "plaintext": "workload section YAML string",
  "certificate_pem": "-----BEGIN CERTIFICATE-----\n..."
}
```

**Response `201`** — section object with `encrypted_payload` and `section_hash`.

Transitions build: `SIGNING_KEY_REGISTERED → WORKLOAD_SUBMITTED`

---

### `POST /builds/{id}/v2/sections/environment`

Auth required. Build access required. Signature headers required. Max body: **50 MB**.

**Request**
```json
{
  "plaintext": "environment section YAML string",
  "certificate_pem": "-----BEGIN CERTIFICATE-----\n..."
}
```

**Response `201`** — section object with `encrypted_payload` and `section_hash`.

Transitions build: `WORKLOAD_SUBMITTED → ENVIRONMENT_STAGED`

---

### `POST /builds/{id}/v2/finalize`

Auth required. Role: `AUDITOR`. Build access required. Signature headers required.

**Request**
```json
{ "signing_key_passphrase": "passphrase-used-at-key-registration" }
```

**Response `200`**
```json
{
  "status": "FINALIZED",
  "contract_hash": "sha256hex...",
  "contract_yaml_length": 12345
}
```

Missing or incorrect signing-key passphrases return `400 INVALID_REQUEST` with
instructions to use the passphrase set at registration. These failures leave the
build editable so the request can be retried. Malformed or unavailable stored
private keys return a generic `500 INTERNAL_ERROR`, rather than being described
as an incorrect passphrase. Uploaded signing public keys have no stored private
key and cannot be used for backend finalization.

Likewise, missing or incorrect attestation-key passphrases return
`400 INVALID_REQUEST` before evidence verification is recorded; the evidence
stays `UPLOADED` for retry instead of being rejected.

Transitions build: `ATTESTATION_KEY_REGISTERED → FINALIZED`

---

## 10. Export & verification

### `GET /builds/{id}/export`

Auth required. Role: `AUDITOR` or `ENV_OPERATOR`. Build access required. Build must be `FINALIZED`.

**Response `200`** — export object containing `contract_yaml`, `contract_hash`, and metadata.

---

### `POST /builds/{id}/acknowledge-download`

Auth required. Role: `ENV_OPERATOR`. Build access required. Signature headers required.

Creates a cryptographic proof-of-receipt. The caller signs the contract hash with their registered private key.

**Request**
```json
{
  "contract_hash": "sha256hex...",
  "signature": "base64-rsa-pss-signature-of-contract-hash"
}
```

**Response `204`** No Content.

Transitions build: `FINALIZED → CONTRACT_DOWNLOADED`

---

### `GET /builds/{id}/userdata`

Auth required. Role: `ENV_OPERATOR`. Build access required. Build must be `FINALIZED` or `CONTRACT_DOWNLOADED`.

**Response `200`** — decoded contract YAML ready for deployment.

---

### `GET /builds/{id}/verify`

Auth required. Any authenticated user with build access.

Verifies the cryptographic hash chain across all audit events.

**Response `200`**
```json
{ "valid": true, "checked_events": 7, "message": "Audit chain integrity verified." }
```

---

### `GET /builds/{id}/verify-contract`

Auth required. Any authenticated user with build access.

Verifies the finalized contract YAML against its stored hash.

**Response `200`**
```json
{ "valid": true, "contract_hash": "sha256hex...", "message": "Contract integrity verified." }
```

---

## 11. Attestation

### `POST /builds/{id}/attestation/evidence`

Auth required. Any authenticated user with build access. Signature headers required.

Uploads attestation evidence (records file + signature file).

**Response `201`** — evidence object with `id`, `created_at`, and uploader metadata.

---

### `POST /builds/{id}/attestation/evidence/{evidence_id}/verify`

Auth required. Role: `AUDITOR`. Build access required. Signature headers required.

**Response `201`**
```json
{ "verdict": "VERIFIED", "details": {}, "created_at": "..." }
```

`verdict` is either `VERIFIED` or `REJECTED`.

---

### `GET /builds/{id}/attestation/status`

Auth required. Build access required.

**Response `200`**
```json
{
  "attestation_state": "VERIFIED",
  "attestation_verified_at": "2024-01-01T00:00:00Z",
  "attestation_verified_by": "uuid"
}
```

`attestation_state` values: `PENDING_UPLOAD` · `UPLOADED` · `VERIFIED` · `REJECTED`

---

## 12. System logs

### `GET /system-logs`

Auth required. Role: `ADMIN` or `AUDITOR`.

**Response `200`** — paginated list of system log entries covering all security and business events.

---

## 13. Credential rotation

### `GET /rotation/expired`

Auth required. Role: `ADMIN`.

**Response `200`** — `expired_passwords`, `expired_public_keys`, `users_without_active_key`, `total_expired`, and `checked_at`. Expired keys are reported per key with `key_id`, `label`, `fingerprint`, owner details, and registration/expiry timestamps. Revoked keys are excluded. `users_without_active_key` separately lists active accounts needing key setup. `total_expired` counts expired passwords plus expired keys; it excludes the separate missing-key list.

---

### `POST /rotation/force-password-change/{user_id}`

Auth required. Role: `ADMIN`. Signature headers required.

Forces the specified user to change their password on next login.

**Response `200`**

---

### `POST /rotation/revoke-key/{user_id}`

Auth required. Role: `ADMIN`. Signature headers required.

Revokes only expired, unrevoked public keys for the specified user and records the administrator as `revoked_by`. Active device keys remain usable. Use the separate single-key and revoke-all endpoints for manual revocation.

**Response `200`**

---

## Quick reference

| Method | Path | Auth | Role | Sig |
|---|---|---|---|---|
| GET | `/health` | ✗ | — | ✗ |
| GET | `/about` | ✗ | — | — |
| GET | `/openapi.json` | ✗ | — | — |
| GET | `/swagger` | ✗ | — | — |
| POST | `/auth/login` | ✗ | — | ✗ |
| GET | `/auth/oidc/login` | ✗ | — | — |
| POST | `/auth/oidc/callback` | ✗ | — | ✗ |
| POST | `/auth/logout` | ✓ | any | ✗ |
| GET | `/roles` | ✓ | any | — |
| GET | `/users` | ✓ | ADMIN/AUDITOR | — |
| POST | `/users` | ✓ | ADMIN | ✓ |
| PATCH | `/users/{id}` | ✓ | ADMIN | ✓ |
| PATCH | `/users/{id}/roles` | ✓ | ADMIN | ✓ |
| DELETE | `/users/{id}` | ✓ | ADMIN | ✓ |
| PATCH | `/users/{id}/reactivate` | ✓ | ADMIN | ✓ |
| PATCH | `/users/{id}/password` | ✓ | owner/ADMIN | ✗ |
| PATCH | `/users/{id}/reset-password` | ✓ | ADMIN | ✓ |
| PUT | `/users/{id}/public-key` | ✓ | owner | conditional |
| GET | `/users/{id}/public-key` | ✓ | owner/ADMIN | — |
| GET | `/users/{id}/public-keys` | ✓ | owner/ADMIN | — |
| DELETE | `/users/{id}/public-keys/{key_id}` | ✓ | owner/ADMIN | ✓ |
| POST | `/users/{id}/public-keys/revoke-all` | ✓ | ADMIN | ✓ |
| GET | `/users/{id}/tokens` | ✓ | owner/ADMIN | — |
| POST | `/users/{id}/tokens` | ✓ | owner/ADMIN | ✓ |
| DELETE | `/users/{id}/tokens/{token_id}` | ✓ | owner/ADMIN | ✓ |
| GET | `/users/{id}/assignments` | ✓ | owner/ADMIN | — |
| GET | `/system-logs` | ✓ | ADMIN/AUDITOR | — |
| GET | `/builds` | ✓ | any | — |
| POST | `/builds` | ✓ | ADMIN/AUDITOR | ✓ |
| GET | `/builds/{id}` | ✓ | assigned | — |
| POST | `/builds/{id}/cancel` | ✓ | ADMIN/AUDITOR | ✓ |
| GET | `/builds/{id}/audit` | ✓ | assigned | — |
| GET | `/builds/{id}/audit-trail` | ✓ | assigned | — |
| GET | `/builds/{id}/assignments` | ✓ | assigned | — |
| POST | `/builds/{id}/assignments` | ✓ | ADMIN/AUDITOR | ✓ |
| DELETE | `/builds/{id}/assignments` | ✓ | ADMIN | ✓ |
| POST | `/builds/{id}/keys/signing` | ✓ | AUDITOR | ✓ |
| POST | `/builds/{id}/keys/attestation` | ✓ | AUDITOR | ✓ |
| GET | `/builds/{id}/keys/signing/public` | ✓ | assigned | — |
| POST | `/v2/contract-template` | ✓ | any | ✓ |
| GET | `/v2/encryption-certificates/versions` | ✓ | any | — |
| GET | `/v2/encryption-certificates/certificate` | ✓ | any | — |
| POST | `/builds/{id}/v2/sections/workload` | ✓ | assigned | ✓ |
| POST | `/builds/{id}/v2/sections/environment` | ✓ | assigned | ✓ |
| POST | `/builds/{id}/v2/finalize` | ✓ | AUDITOR | ✓ |
| GET | `/builds/{id}/export` | ✓ | AUDITOR/ENV_OPERATOR | — |
| POST | `/builds/{id}/acknowledge-download` | ✓ | ENV_OPERATOR | ✓ |
| GET | `/builds/{id}/userdata` | ✓ | ENV_OPERATOR | — |
| GET | `/builds/{id}/verify` | ✓ | assigned | — |
| GET | `/builds/{id}/verify-contract` | ✓ | assigned | — |
| POST | `/builds/{id}/attestation/evidence` | ✓ | assigned | ✓ |
| POST | `/builds/{id}/attestation/evidence/{evidence_id}/verify` | ✓ | AUDITOR | ✓ |
| GET | `/builds/{id}/attestation/status` | ✓ | assigned | — |
| GET | `/rotation/expired` | ✓ | ADMIN | — |
| POST | `/rotation/force-password-change/{user_id}` | ✓ | ADMIN | ✓ |
| POST | `/rotation/revoke-key/{user_id}` | ✓ | ADMIN | ✓ |

**Auth** `✓` Bearer token required &nbsp;·&nbsp; **Sig** `✓` X-Signature headers required &nbsp;·&nbsp; `✗` explicitly exempt &nbsp;·&nbsp; `—` read-only / no mutation

## Plaintext contract validation

`POST /v2/contract-validate` (also `/contract-validate`) requires authentication and a signed request.

```json
{"section":"workload","plaintext":"type: workload\nplay:\n  resources: []\n"}
```

`section` is `workload`, `env`, or an empty string for both. Use raw section YAML for individual validation. Complete plaintext contracts must contain both `workload` and `env`, as mappings or YAML block scalars; both are validated even when requesting only one. The sample empty resources list is intentionally incomplete and is rejected. Successful responses contain `valid: true`, `platform: "ccrt"` and normalized `plaintext`. The helper does not store input. CCRT is the platform currently configured by this workflow; this endpoint does not claim validation for CCRV or CCCO.

Both submission endpoints repeat schema validation before encryption. Complete inputs also check shared volume declarations and seed availability. Separate submissions cannot compare plaintext against a previously encrypted counterpart without the runtime's private key; they are checked independently. Workload, environment and attestation encryption use the same certificate pinned to the build. Existing builds without a stored certificate pin the certificate on their next submission; the recipient of previously encrypted sections cannot be inferred retrospectively.

The environment signing key is inserted from the build's registered signing key. A supplied conflicting key is rejected. An attestation encryption certificate is required. Finalization checks all encrypted envelopes and signs the workload/environment pair. The wire identifiers `hyper-protect-basic` and `contract-basic`, legacy resource/database names and upstream `Hpcr*` library APIs remain compatible.

The current encryption format uses RSA PKCS#1 v1.5 to wrap a random password and OpenSSL AES-256-CBC/PBKDF2 for section data. Password randomness is Base64 encoded before OpenSSL's line-oriented input; binary ciphertext is never written through text helpers that trim whitespace. Temporary files are private and removed after the operation. The final workload/environment signature detects modifications; successful decryption alone does not authenticate a contract. UI submission sends plaintext to the backend, so production transport must use HTTPS.

`GET /builds/{id}/sections` returns encrypted sections under the same build-access guard as the other build resources.

### Build-key passphrase normalization

Signing/attestation key registration, contract finalization and attestation verification trim leading and trailing whitespace using the same rules as JavaScript `String.trim()`. Internal whitespace remains significant. Strength rules apply after trimming; padding cannot satisfy length or special-character requirements. Account passwords, identity-backup passwords and volume seeds are unchanged. Keys previously encrypted with significant leading/trailing whitespace are not rewritten; those build keys must be replaced through the supported build workflow before using this policy. There is no automatic retry with the untrimmed secret.
