# IBM Confidential Computing Contract Generator - Security Design

> **Version:** 1.2
> **Date:** 2026-06-23
> **Status:** Implementation-aligned security reference
> **Source of Truth:** `internal/*`, `cmd/server/main.go`, `app/main/index.js`, `app/index.html`, `compose/` configs

---

## 1. Purpose and Scope

This document defines the current security architecture, controls, and operational guardrails for:

- backend API (`internal/`, `cmd/`)
- desktop client (`app/`)
- reverse proxy and deployment runtime (`compose/docker-compose*.yaml`, `compose/config/nginx/*.conf`)

If this document conflicts with code, code is authoritative.

---

## 2. Security Objectives

The platform is designed to:

- preserve private-key confidentiality on client devices
- enforce least privilege via role + per-build assignment checks
- ensure tamper-evident workflow history with cryptographic audit linkage
- prevent unauthorized state transitions and replay of mutating requests
- provide secure-by-default deployment posture for on-prem/self-hosted environments

---

## 3. Threat Model and Trust Boundaries

### 3.1 Trust Boundaries

1. **Desktop (trusted for identity key operations):**
   - identity keys (RSA-4096) generated/stored locally
   - request signing runs in Electron main process
2. **Backend (trusted for contract cryptography and encrypted key custody):**
   - orchestrates workflow
   - performs section encryption via `contract-go` engine
   - validates signatures
   - stores encrypted payloads, hashes, and audit events
   - stores build signing/attestation private keys encrypted at rest in PostgreSQL (`build_keys_private`, AES-256-CBC)
   - decrypts key material transiently using caller-supplied passphrase for HPCR operations; zeroizes after use
3. **Network:**
   - traffic intended through nginx reverse proxy
   - TLS termination at proxy in production mode
   - PostgreSQL on internal `db_net` network (not internet-exposed)
4. **Database:**
   - stores user/auth/audit/build metadata and encrypted artifacts
   - stores build key public keys and AES-256-CBC encrypted private key PEM blobs (`build_keys_private`)
   - database access must be restricted to the backend service account only

### 3.2 Out-of-Scope Risks

- endpoint hardening of external identity providers (not used)
- host OS compromise on client or server
- PostgreSQL storage-engine-level data recovery (operator responsibility)

---

## 4. Identity and Authentication Controls

### 4.1 Bearer Token Model

- Login endpoint issues opaque random tokens.
- Backend stores token **hashes** only (`SHA-256`), never plaintext token values.
- Token validity is enforced by `created_at + TOKEN_EXPIRY`.
- Revoked tokens are rejected.

### 4.2 Setup Guard (First Login / Rotation Enforcement)

Authenticated users with incomplete setup are restricted to setup-safe endpoints only:

- `POST /auth/logout`
- `PATCH /users/{id}/password` (own account)
- `PUT /users/{id}/public-key` (own account)

All other routes return `403 ACCOUNT_SETUP_REQUIRED`.

Setup-required triggers include:

- `must_change_password = true`
- zero active identity keys (no key history, or all keys expired/revoked)

A key is active when not revoked and its expiry is in the future. One expired device key does not block another active device. Login exposes `active_key_count`; legacy fingerprint/expiry fields describe the newest active key or are `null`. The legacy `public_key_expired` flag means key history exists with zero active keys, including after revocation.

---

## 5. Authorization Controls

### 5.1 Role-Based Access Control

System roles:

- `ADMIN`
- `SOLUTION_PROVIDER`
- `DATA_OWNER`
- `AUDITOR`
- `ENV_OPERATOR`
- `VIEWER`

### 5.2 Assignment-Based Access Control

Build actions require both:

1. global role entitlement
2. explicit assignment on that specific build/role

### 5.3 Build Visibility Guard

`RequireBuildAccess` middleware enforces `/builds/{id}/...` access:

- admin can access any build
- non-admin must be assigned on that build

`GET /builds` behavior:

- admin: full paginated list
- non-admin: assignment-filtered list

### 5.4 Assignment Integrity Rules

Build-level assignments are restricted to workflow personas:

- `SOLUTION_PROVIDER`
- `DATA_OWNER`
- `AUDITOR`
- `ENV_OPERATOR`

Additional guard:

- assignee must already hold the target role globally

---

## 6. Request Integrity and Anti-Replay

### 6.1 Signed Mutating Requests

All authenticated mutating methods (`POST`, `PUT`, `PATCH`, `DELETE`) require:

- `X-Signature`
- `X-Signature-Hash`
- `X-Timestamp`
- `X-Key-Fingerprint` when multiple keys are active (permanent fallback only with exactly one active key)

Validation steps:

- timestamp freshness check (`+/-5 minutes`)
- select a key belonging to the authenticated user by normalized SHA-256 fingerprint
- reject unknown, revoked, or expired keys; reject an ambiguous missing fingerprint
- canonical hash recomputation from method/path/body/timestamp
- RSA signature verification against the selected active key; pass that verified key in the request context to audit and download receipt handling

### 6.2 Signature Exemptions

- `POST /auth/logout`
- `PATCH /users/{id}/password`
- `PUT /users/{id}/public-key` only when the caller has zero active keys

These exemptions enable account setup and logout flows before full key state is available.

---

## 7. Workflow and State-Machine Security

### 7.1 Controlled Lifecycle

V2 state progression:

`CREATED -> SIGNING_KEY_REGISTERED -> WORKLOAD_SUBMITTED -> ENVIRONMENT_STAGED -> ATTESTATION_KEY_REGISTERED -> FINALIZED -> CONTRACT_DOWNLOADED`

Post-finalization attestation lifecycle (tracked by `attestation_state`):

`PENDING_UPLOAD -> UPLOADED -> VERIFIED|REJECTED`

Cancellation:

- allowed from non-terminal pre-finalized states

### 7.2 Download Acknowledgment Control

`CONTRACT_DOWNLOADED` is set only via `POST /builds/{id}/acknowledge-download`.

Security checks include:

- build is `FINALIZED`
- caller is assigned env operator
- submitted `contract_hash` equals stored build hash
- signature verifies with caller registered public key

After acknowledgment:

- status becomes `CONTRACT_DOWNLOADED`
- re-download/export/userdata/acknowledge paths are blocked

### 7.3 Post-Finalization Attestation Controls

- Evidence upload and verification are controlled by `attestation_state` and do not mutate the build status machine.
- Desktop unlocks evidence upload only after `CONTRACT_DOWNLOADED`.
- Backend upload endpoint accepts both signed JSON and `multipart/form-data` payloads under the same authz/signature controls.
- Rejected verification responses surface contract-go error details for auditor diagnosis while still recording terminal `REJECTED` state.

---

## 8. Cryptographic Security Model

### 8.1 Algorithms

- RSA-4096 identity keys
- RSA-PSS signatures (`SHA-256`)
- AES-256-GCM for environment payload encryption
- RSA-OAEP wrapping for symmetric keys
- SHA-256 hashing for request/content/audit linkage

### 8.2 Key Ownership

- **Identity private keys** remain client-side (Electron). Never transmitted.
- **Build signing/attestation private keys** are stored encrypted at rest in PostgreSQL (`build_keys_private` table, AES-256-CBC PEM format). They are decrypted transiently in backend memory only when required for HPCR operations (`HpcrContractSign`, `HpcrGetAttestationRecords`), using the caller-supplied passphrase; private key bytes are zeroized after use and are never returned to clients or written to logs.
- Backend stores identity public keys + fingerprints + expiry metadata.
- Backend stores build key public keys (`build_keys`) and AES-256-CBC encrypted private key PEM blobs (`build_keys_private`).
- Backend verification always uses registered keys, never caller-supplied verification keys.

Identity key policy:

- Each client generates its own RSA-4096 identity pair. Private keys remain on that client; no identity private-key import/export flow is provided by the manager.
- New keys expire 90 days after registration; at most five keys per user may be active simultaneously. Revoked and expired keys do not consume active slots.
- Registration adds a key and is owner-only, including for admins. Password confirmation is required after any key history. If active keys exist, an existing active key must also sign registration.
- Registration and manual revocation lock the same user row. Registration rechecks active signing authority under that lock, preventing concurrent setup requests from bypassing signature enforcement or exceeding the limit.
- Owners and admins may revoke one key. Only admins may revoke all active keys. Rotation revokes only expired keys. Each revocation records time and actor.
- Revoked key rows remain in history and their fingerprints cannot be registered again. Historical audit verification uses the public key stored with the event, so later revocation does not invalidate an earlier event.

### 8.3 Build Key Security (PostgreSQL-Backed)

- Signing keys: RSA-4096. For `generate` mode, `keymgmt/db/provider.go` generates the key pair and encrypts the private key with the caller-supplied passphrase (AES-256-CBC, OpenSSL PEM format) before storing it in `build_keys_private`. For `upload_public` mode, only the public key is stored and no private key is available server-side.
- Attestation keys: RSA-4096, generated (stored encrypted in `build_keys_private`) or uploaded (public key only). Decryption paths that call `HpcrGetAttestationRecords(...)` require the passphrase to decrypt the private key at runtime.
- Passphrases are request-scoped, never persisted, and must be excluded from logs and error messages.
- Client-facing APIs never expose private key material. Backend key material handling is memory-only with post-operation zeroization.

### 8.4 Build Key At-Rest Protection (Compensating Controls)

Unlike a hardware-sealed key management system, PostgreSQL-backed key storage relies on the following compensating controls to protect private key material at rest:

- **Passphrase encryption:** Every generated private key is encrypted with a caller-supplied passphrase (AES-256-CBC) before storage. Without the passphrase, the stored blob is computationally infeasible to use.
- **Database access restriction:** PostgreSQL must be accessible only to the backend service account. Network-level isolation (`db_net: internal: true` in Docker Compose) enforces this by default.
- **Host disk encryption:** Production deployments must enable disk-level encryption on the host running PostgreSQL. This is the primary control protecting encrypted key blobs if the DB data directory is compromised.
- **Encrypted backups:** Database backups containing `build_keys_private` rows must themselves be encrypted. Passphrase inventory must be maintained in a secure credential store external to the database.
- **Known constraint:** AES-256-CBC does not provide authenticated encryption. AES-256-GCM is the recommended future upgrade.

### 8.5 Data Classification (Stored)

Backend stores:

- encrypted section payloads
- wrapped symmetric keys (legacy v1 rows only; nullable/absent in v2-first submissions)
- section hashes/signatures
- contract hash and finalized contract YAML (which contains encrypted contract data)
- audit events and hash chain metadata
- build key public keys (`build_keys`) and AES-256-CBC encrypted private key PEM blobs (`build_keys_private`)

---

## 9. Audit, Integrity, and Non-Repudiation

### 9.1 Audit Chain

- genesis: `SHA256("IBM_CC:" + build_id)`
- each event hash links to previous event hash
- tampering or reordering breaks verification

### 9.2 Signature Expectations in Audit Verification

Signed event types expected by verification logic:

- `BUILD_CREATED`
- `SIGNING_KEY_CREATED`
- `WORKLOAD_SUBMITTED`
- `ENVIRONMENT_STAGED`
- `ATTESTATION_KEY_REGISTERED`
- `BUILD_FINALIZED`
- `CONTRACT_DOWNLOADED`
- `ATTESTATION_EVIDENCE_UPLOADED`
- `ATTESTATION_VERIFIED`

### 9.3 Verification Endpoints

- `GET /builds/{id}/verify` for chain/signature integrity
- `GET /builds/{id}/verify-contract` for finalized contract integrity and signature checks

---

## 10. Backend Runtime Hardening

### 10.1 Middleware Security Pipeline

Global middleware order:

1. panic recoverer
2. request ID
3. security headers
4. structured request logging
5. CORS enforcement
6. max body size
7. request timeout
8. rate limiting

Authenticated group middleware:

1. auth
2. setup guard
3. request-signature enforcement

### 10.2 Security Headers

Backend sets:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- `Permissions-Policy: camera=(), microphone=(), geolocation=()`
- `Strict-Transport-Security` on TLS requests

### 10.3 Rate Limiting

- global: `10 req/sec`, burst `20`
- login: `5 req/min`, burst `3`

### 10.4 CORS

- explicit allow-list by default
- `CORS_ALLOW_ALL` supported (intended for non-production/dev scenarios only)

---

## 11. Desktop Application Security Controls

### 11.1 Electron Runtime Hardening

`BrowserWindow` security flags:

- `contextIsolation: true`
- `nodeIntegration: false`
- `sandbox: true`
- `webviewTag: false`
- `webSecurity: true`
- `allowRunningInsecureContent: false`

### 11.2 Navigation and External Link Controls

- strict allow-list for in-app navigation URLs
- all child windows denied (`setWindowOpenHandler`)
- blocked `webview` attachment
- external URLs only through safe protocol allow-list (`https`, `http`, `mailto`)

### 11.3 IPC Boundary Protection

- all IPC handlers registered via centralized wrapper
- sender URL trust check on every IPC call
- untrusted sender requests rejected

### 11.4 Session/Permission Controls

- deny-all permission request/check/device handlers
- session storage cleanup on window close and app shutdown
- TLS certificate errors are rejected (`callback(false)`)

### 11.5 Renderer CSP

`app/index.html` defines CSP with:

- `default-src 'self'`
- `object-src 'none'`
- restrictive script/style/font/image/connect directives

---

## 12. Deployment Security Baseline

### 12.1 Reverse Proxy and Network Segmentation

Compose baseline provides:

- `reverse_proxy` exposed to host
- `backend` and `postgres` on internal networks
- `db_net` marked `internal: true`

### 12.2 Container Runtime Hardening

Implemented in compose:

- read-only root filesystems where applicable
- `tmpfs` for writable transient paths
- `no-new-privileges`
- dropped Linux capabilities (minimal add-back for nginx bind)
- resource limits on backend (`mem_limit`, `cpus`, `pids_limit`)

### 12.3 TLS in Production Overlay

`docker-compose.prod.yaml` + `config/nginx/tls.conf` provide:

- HTTPS listener on port `443` (mapped default `8443`)
- HTTP-to-HTTPS redirect
- certificate/key mounted as read-only
- HSTS and secure proxy forwarding headers

---

## 13. Logging and Security Observability

### 13.1 Request and Security Event Logging

Backend produces:

- structured HTTP request logs (method/path/status/duration/request-id/ip)
- middleware-generated security/system events (auth failures, setup blocks, rate limits, signature validation failures, RBAC denials)

### 13.2 System Log API Surface

- `GET /system-logs` available to `ADMIN` and `AUDITOR`
- supports paging (`limit`, `offset`)

---

## 14. Operational Security Checklist (Production)

Before go-live:

- enforce TLS by using production overlay and valid cert/key files
- set strong `POSTGRES_PASSWORD` and `ADMIN_PASSWORD`
- set restrictive `CORS_ALLOWED_ORIGINS`; keep `CORS_ALLOW_ALL=false`
- ensure `TRUST_PROXY_HEADERS=true` only behind trusted proxy
- verify DB connectivity and migration success before exposing proxy
- **restrict PostgreSQL access** to backend service account only (`db_net: internal: true` enforces this in compose)
- **enable host disk encryption** on the server running PostgreSQL
- **encrypt all backups** that include `build_keys_private` table rows
- **maintain passphrase inventory** for all build keys in a secure credential store external to the database
- validate first-login setup flow for all seeded/provisioned users
- verify signature enforcement on mutating endpoints
- verify audit + contract integrity checks on a full test build
- sign desktop binaries for distribution trust

---

## 15. Known Gaps and Future Hardening

Current known areas to improve:

- private key at-rest protection currently uses app-local machine-derived strategy; OS keychain integration would strengthen client key protection
- static embedded OpenAPI may lag implementation details
- no mTLS between reverse proxy and backend by default
- AES-256-CBC used for build private key encryption; upgrade to AES-256-GCM (authenticated encryption) is the recommended future hardening item
- additional automated security tests (negative-path and replay-focused) should be expanded

---

## 16. Related Documents

- [High-Level Design](./1-high-level-design.md)
- [Low-Level Design](./2-low-level-design.md)
- [Desktop App Design](./3-desktop-app-design.md)
- [API Documentation](./4-api-documentation.md)
