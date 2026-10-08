# IBM Confidential Computing Contract Generator - Low-Level Design (LLD)

> **Version:** 0.6
> **Date:** 2026-06-24
> **Status:** Draft
> **Parent Document:** [1-high-level-design.md](./1-high-level-design.md)

---

## 1. Scope and Source of Truth

This document is implementation-aligned to the current codebase in:

- `internal/` + `cmd/` (Go + chi + sqlc + PostgreSQL)
- `app/` (Electron + React + Carbon)

If this document conflicts with code, code is authoritative.

---

## 2. Codebase Structure

### 2.1 Backend

```text
cmd/
  server/main.go
internal/
  config/config.go
  crypto/{hash.go,signature.go}
  contract/
    engine.go              # Engine interface
    contractgo/engine.go   # Go-native RSA-OAEP + AES-GCM implementation
  keymgmt/
    provider.go            # KeyProvider interface
    db/provider.go         # PostgreSQL-backed implementation (active production provider)
    mock/provider.go       # In-memory mock for dev/test
  middleware/
    auth.go
    context.go
    cors.go
    hardening.go
    logging.go
    ratelimit.go
    rbac.go
    setup_guard.go
    signature.go
    system_log_hook.go
  handler/
    about_handler.go
    auth_handler.go
    user_handler.go
    role_handler.go
    build_handler.go
    section_handler.go
    assignment_handler.go
    audit_handler.go
    export_handler.go
    rotation_handler.go
    system_log_handler.go
    swagger_handler.go
    key_handler.go              # V2: signing/attestation key management
    contract_v2_handler.go      # V2: backend-native section submit + finalize
    attestation_handler.go      # V2: evidence upload + verification
    response.go
    system_log_helpers.go
  model/
    user.go
    build.go
    key.go                      # BuildKeyType, BuildKeyMode, BuildKeyStatus, AttestationVerdict
    audit.go
    errors.go
  repository/
    queries/*.sql
    *.sql.go (sqlc generated)
    db.go, models.go, querier.go
  service/
    auth_service.go
    user_service.go
    role_service.go
    build_service.go
    section_service.go
    assignment_service.go
    audit_service.go
    verification_service.go
    export_service.go
    rotation_service.go
    system_log_service.go
    v2_store.go                 # V2: shared DB access layer for keys + attestation
    key_service.go              # V2: build-scoped key lifecycle
    contract_service.go         # V2: section encryption + finalization
    attestation_service.go      # V2: evidence upload + cryptographic verification
migrations/*.sql                # 001..019
```

### 2.2 Desktop App

```text
app/
  main/
    index.js
    preload.js
    crypto/
      contractCli.js         # DEPRECATED: will be removed in v2 switchover
      encryptor.js
      keyManager.js
      keyStorage.js
      signer.js
  src/
    App.jsx
    views/
      Login.jsx
      Home.jsx
      BuildManagement.jsx
      BuildDetails.jsx
      AccountSettings.jsx
      UserManagement.jsx
      AdminAnalytics.jsx
      SystemLogs.jsx
      NotFound.jsx
      ServerConfigSettings.jsx
    components/
      AppShell.jsx
      DesktopTitleBar.jsx
      BuildAssignments.jsx
      SectionSubmit.jsx
      AuditorSection.jsx
      FinaliseContract.jsx
      ContractExport.jsx
      AuditViewer.jsx
      PasswordManager.jsx
      PublicKeyManager.jsx
      CredentialRotation.jsx
      APITokenManager.jsx
      ToastManager.jsx
      ErrorBoundary.jsx
      ...
    services/
      apiClient.js
      signatureMiddleware.js
      authService.js
      userService.js
      roleService.js
      buildService.js
      assignmentService.js
      sectionService.js
      exportService.js
      verificationService.js
      rotationService.js
      systemLogService.js
      tokenService.js
      cryptoService.js
      keyService.js              # optional future split; v2 key APIs are currently implemented in buildService.js
      contractV2Service.js       # optional future split; v2 section/finalize APIs are currently implemented in buildService.js
      attestationService.js      # optional future split; attestation APIs are currently implemented in buildService.js
    store/
      authStore.js
      buildStore.js
      configStore.js
      userStore.js
      rotationStore.js
      uiStore.js
      themeStore.js
```

---

## 3. Backend Runtime Pipeline

Middleware order in `cmd/server/main.go`:

1. `Recoverer`
2. `RequestID`
3. `SecurityHeaders`
4. `Logging`
5. `CORS`
6. `MaxBodyBytes`
7. `RequestTimeout`
8. `RateLimit`

Authenticated group adds:

1. `Auth`
2. `SetupGuard`
3. `RequireRequestSignature`

### 3.1 Setup Guard

When setup is incomplete (`must_change_password` or missing/expired public key), only these endpoints are allowed:

- `POST /auth/logout`
- `PATCH /users/{id}/password` (owner only)
- `PUT /users/{id}/public-key` (owner only)

All other endpoints return `403 ACCOUNT_SETUP_REQUIRED`.

### 3.2 Request Signature Guard

All authenticated mutating requests (`POST`, `PUT`, `PATCH`, `DELETE`) require:

- `X-Signature`
- `X-Signature-Hash`
- `X-Timestamp`
- optional `X-Key-Fingerprint`

Exemptions:

- `POST /auth/logout`
- `PATCH /users/{id}/password`
- `PUT /users/{id}/public-key`

Verification is performed against the caller's registered public key.

---

## 4. Authorization Model

### 4.1 Roles

System roles:

- `ADMIN`
- `SOLUTION_PROVIDER`
- `DATA_OWNER`
- `AUDITOR`
- `ENV_OPERATOR`
- `VIEWER`

### 4.2 Two-Layer Build Access

Build operations are protected by both:

1. global role checks (RBAC)
2. per-build assignment checks

Implemented by:

- router-level role middleware (`RequireRole`, `RequireOwnerOrAdmin`)
- build-level middleware (`RequireBuildAccess`) on `/builds/{id}/...`
- service-level assignment checks (`AssignmentService`, `BuildService`, `ExportService`, `SectionService`)

### 4.3 Build Visibility Rules

- `GET /builds`
  - `ADMIN`: sees all builds
  - non-admin: sees only builds where user has at least one assignment
- `GET /builds/{id}` and all nested build routes
  - `ADMIN`: full access
  - non-admin: only if assigned to that build

### 4.4 Assignment Creation Rules

`POST /builds/{id}/assignments` (admin only) enforces:

- build is non-terminal
- role is workflow-assignable (`SOLUTION_PROVIDER`, `DATA_OWNER`, `AUDITOR`, `ENV_OPERATOR`)
- assignee exists
- assignee has the target global role
- role not already assigned for that build/user pair

---

## 5. Database Design

## 5.1 Migrations

Current migration chain (001..020) defines users, roles, tokens, builds, sections, assignments, audit events, system logs, downloaded terminal status, build keys, attestation tables, and DB key storage. Migration 020 removes deprecated V1 enum values from `build_status` and `audit_event_type`.

## 5.2 Enumerations

`build_status` (linear workflow order):

- `CREATED`
- `SIGNING_KEY_REGISTERED`
- `WORKLOAD_SUBMITTED`
- `ENVIRONMENT_STAGED`
- `ATTESTATION_KEY_REGISTERED`
- `FINALIZED`
- `CONTRACT_DOWNLOADED`
- `CANCELLED`

`persona_role` enum is used by `user_roles.role`.

`audit_event_type` includes:

- `BUILD_CREATED`
- `SIGNING_KEY_CREATED`
- `WORKLOAD_SUBMITTED`
- `ENVIRONMENT_STAGED`
- `ATTESTATION_KEY_REGISTERED`
- `BUILD_FINALIZED`
- `BUILD_CANCELLED`
- `CONTRACT_DOWNLOADED`
- `ATTESTATION_EVIDENCE_UPLOADED`
- `ATTESTATION_VERIFIED`
- plus system/user/token events

## 5.3 Core Tables

### users

Identity + credential-rotation fields:

- `must_change_password`
- `password_changed_at`
- `public_key`
- `public_key_fingerprint`
- `public_key_registered_at`
- `public_key_expires_at`

### user_roles

Global RBAC assignments; uses `persona_role` enum column `role`.

### roles

Reference table used by build assignments and build sections (`role_id`).

### api_tokens

- stores only `token_hash` (SHA-256)
- no `expires_at` column
- validity window enforced from `created_at + TOKEN_EXPIRY`
- supports `last_used_at`, `revoked_at`

### builds

- lifecycle state + final artifact fields
- `contract_yaml`, `contract_hash`, `is_immutable`, `finalized_at`
- `attestation_state`, `attestation_verified_at`, `attestation_verified_by` (v2)

### build_assignments

Per-build role binding (`build_id`, `role_id`, `user_id`), with admin assigner metadata.

### build_sections

Encrypted persona submissions with:

- `persona_role`
- `role_id`
- `encrypted_payload`
- `wrapped_symmetric_key` (legacy v1 data-owner flow; nullable in v2)
- `section_hash`
- `signature`

### build_keys (v2)

Build-scoped signing/attestation keys:

- `key_type` (`SIGNING`, `ATTESTATION`)
- `mode` (`generate`, `upload_public`)
- `status` (`ACTIVE`, `REVOKED`)
- `public_key`, `public_key_fingerprint`
- `created_by`

### attestation_evidence (v2)

Evidence uploaded by DO/EO:

- `records_file_name`, `records_content` (bytea)
- `signature_file_name`, `signature_content` (bytea)
- `metadata` (JSONB)
- `uploaded_by`, `uploader_role`

### attestation_verifications (v2)

Auditor verification results:

- `evidence_id` (unique FK)
- `verified_by`
- `verdict` (`VERIFIED`, `REJECTED`)
- `details` (JSONB)

### audit_events

Tamper-evident chain fields:

- `sequence_no`
- `previous_event_hash`
- `event_hash`
- `signature`
- `actor_public_key`
- `actor_key_fingerprint`

`build_id` is nullable to allow system-level events.

### system_logs

Operational log feed for admin/auditor views.

---

## 6. Build State Machine

Linear transitions (v2 workflow):

- `CREATED -> SIGNING_KEY_REGISTERED`
- `SIGNING_KEY_REGISTERED -> WORKLOAD_SUBMITTED`
- `WORKLOAD_SUBMITTED -> ENVIRONMENT_STAGED`
- `ENVIRONMENT_STAGED -> ATTESTATION_KEY_REGISTERED`
- `ATTESTATION_KEY_REGISTERED -> FINALIZED`
- `FINALIZED -> CONTRACT_DOWNLOADED`

Cancellation:

- `-> CANCELLED` from any pre-finalized, non-terminal state

Terminal statuses:

- `FINALIZED`
- `CONTRACT_DOWNLOADED`
- `CANCELLED`

Role + assignment required per transition:

- `SIGNING_KEY_REGISTERED`: `AUDITOR`
- `WORKLOAD_SUBMITTED`: `SOLUTION_PROVIDER`
- `ENVIRONMENT_STAGED`: `DATA_OWNER`
- `ATTESTATION_KEY_REGISTERED`: `AUDITOR`
- `FINALIZED`: `AUDITOR`
- `CONTRACT_DOWNLOADED`: `ENV_OPERATOR` (only via acknowledge-download flow)

Post-finalization attestation lifecycle (tracked by `attestation_state`, not build status):

- `PENDING_UPLOAD -> UPLOADED` (DO/EO uploads evidence)
- `UPLOADED -> VERIFIED` (Auditor verifies)
- `UPLOADED -> REJECTED` (Auditor rejects)
- `REJECTED -> UPLOADED` (DO/EO re-uploads)
- backend upload API allows finalized or downloaded builds; desktop UI unlocks upload at `CONTRACT_DOWNLOADED`

Additional rules:

- `PATCH /builds/{id}/status` cannot set `CONTRACT_DOWNLOADED`
- downloaded acknowledgement is one-time
- re-export/userdata/download acknowledgement blocked once downloaded

---

## 7. Service-Level Behavior

### 7.1 AuthService

- email/password validation with bcrypt
- issues random bearer token
- stores SHA-256 token hash
- returns token expiry timestamp as `now + TOKEN_EXPIRY`
- computes setup requirements from password/public-key state

### 7.2 UserService

- user CRUD and role updates (admin)
- token creation/revocation/list
- public key register/read
- password change and admin reset
- setup-state computation

### 7.3 BuildService

- build creation and retrieval
- assignment-aware list filtering (`ListBuildsForUser`)
- strict transition enforcement + transition-role checks
- assignment check for transition actor
- finalize requires assigned auditor

### 7.4 AssignmentService

- enforces workflow-role assignment constraints
- enforces assignee holds target global role
- emits assignment audit event

### 7.6 AuditService + VerificationService

- deterministic hash-chain append
- actor key fingerprint capture
- full-chain verification:
  - sequence continuity
  - previous-hash linkage
  - event-hash recomputation
  - required signature checks for signed stages

Signed-stage expectation in verification:

- `BUILD_CREATED`
- `SIGNING_KEY_CREATED`
- `WORKLOAD_SUBMITTED`
- `ENVIRONMENT_STAGED`
- `ATTESTATION_KEY_REGISTERED`
- `BUILD_FINALIZED`
- `CONTRACT_DOWNLOADED`
- `ATTESTATION_EVIDENCE_UPLOADED` (post-finalization)
- `ATTESTATION_VERIFIED` (post-finalization)

### 7.6 ExportService

- export/userdata only for assigned `ENV_OPERATOR` on finalized builds
- `acknowledge-download` verifies hash + signature + assignee
- writes `CONTRACT_DOWNLOADED` audit event
- moves build to `CONTRACT_DOWNLOADED`

### 7.7 KeyService

- build-scoped signing and attestation key lifecycle
- delegates key generation/storage to `KeyProvider` interface (DB or Mock)
- signing keys: RSA-4096. For `generate` mode, private key is encrypted with caller passphrase (AES-256-CBC) and stored in `build_keys_private`. For HPCR-required operations, `GetPrivateKey()` retrieves the encrypted PEM; contract-go decrypts it using the passphrase and zeroizes memory after use.
- attestation keys: mode `generate` (stored encrypted in `build_keys_private`) or `upload_public` (external PEM, no private key stored)
- emits `SIGNING_KEY_CREATED` and `ATTESTATION_KEY_REGISTERED` audit events

### 7.8 ContractService

- backend-native section encryption via `contract-go` engine (RSA-OAEP + AES-256-GCM)
- accepts plaintext + HPCR certificate PEM; returns encrypted payload + hash
- owns internal `submitSection()` helper: validates build state, checks for duplicate role submissions, inserts `build_sections` row, auto-transitions status
- finalization: loads encrypted sections, retrieves signing key encrypted PEM via `KeyProvider.GetPrivateKey()`, passes to `HpcrContractSign(...)` with caller passphrase, assembles deterministic YAML
- emits `BUILD_FINALIZED` audit event

### 7.9 AttestationService

- accepts evidence upload in either multipart form-data or signed JSON payload
- upload guardrails: build must be `FINALIZED` or `CONTRACT_DOWNLOADED`; `attestation_state` must be `PENDING_UPLOAD` or `REJECTED`
- verification guardrails: build must be `FINALIZED` or `CONTRACT_DOWNLOADED`; `attestation_state` must be `UPLOADED`
- verification: resolves attestation key material via `KeyProvider`, decrypts records via `HpcrGetAttestationRecords(...)` (with optional attestation key passphrase), verifies signature via `HpcrVerifySignatureAttestationRecords(...)`
- verification details include `records_decrypted`, `signature_valid`, and `records_hash`; rejected results include `details.reason` from engine/key operations
- returns verdict (`VERIFIED` or `REJECTED`) and state alias
- emits `ATTESTATION_EVIDENCE_UPLOADED` and `ATTESTATION_VERIFIED` audit events

### 7.10 RotationService

- expired credential reporting
- admin force-password-change
- admin public-key revocation
- background monitor (24h interval from server startup)

---

## 8. Route and Access Matrix (Current)

Legend:

- `Auth`: authenticated bearer token required
- `Sig`: request-signature headers required
- `BuildAccess`: admin OR assigned to that build

### 8.1 Public

- `GET /health`
- `GET /openapi.json`
- `GET /swagger`
- `GET /swagger/`
- `POST /auth/login`

### 8.2 User/Auth

- `POST /auth/logout` - Auth, signature exempt
- `GET /roles` - Auth

- `GET /users` - ADMIN
- `POST /users` - ADMIN
- `PATCH /users/{id}` - ADMIN
- `PATCH /users/{id}/roles` - ADMIN
- `DELETE /users/{id}` - ADMIN
- `PATCH /users/{id}/reactivate` - ADMIN
- `PATCH /users/{id}/reset-password` - ADMIN

- `PUT /users/{id}/public-key` - owner or ADMIN, signature exempt
- `GET /users/{id}/public-key` - owner or ADMIN
- `PATCH /users/{id}/password` - owner or ADMIN, signature exempt

- `GET /users/{id}/tokens` - owner or ADMIN
- `POST /users/{id}/tokens` - owner or ADMIN, Sig
- `DELETE /users/{id}/tokens/{token_id}` - owner or ADMIN, Sig

- `GET /users/{id}/assignments` - owner or ADMIN

### 8.3 System Logs

- `GET /system-logs` - ADMIN or AUDITOR

### 8.4 Builds

- `GET /builds` - Auth, assignment-filtered for non-admin
- `POST /builds` - ADMIN or AUDITOR, Sig

All `/builds/{id}/...` routes enforce BuildAccess middleware:

- `GET /builds/{id}`
- `POST /builds/{id}/cancel` - ADMIN or AUDITOR, Sig

- `GET /builds/{id}/audit`
- `GET /builds/{id}/audit-trail`

- `GET /builds/{id}/assignments`
- `POST /builds/{id}/assignments` - ADMIN or AUDITOR, Sig
- `DELETE /builds/{id}/assignments` - ADMIN, Sig

- `GET /builds/{id}/export`
- `GET /builds/{id}/userdata`
- `POST /builds/{id}/acknowledge-download` (Sig)
- `GET /builds/{id}/verify`
- `GET /builds/{id}/verify-contract`

### Key Management

- `POST /builds/{id}/keys/signing` - AUDITOR, Sig
- `POST /builds/{id}/keys/attestation` - AUDITOR, Sig
- `GET /builds/{id}/keys/signing/public`

### Contract Operations

- `POST /contract-template` - Auth
- `GET /encryption-certificates/versions` - Auth
- `POST /builds/{id}/sections/workload` - assigned SOLUTION_PROVIDER, Sig
- `POST /builds/{id}/sections/environment` - assigned DATA_OWNER, Sig
- `POST /builds/{id}/finalize` - AUDITOR, Sig

### Attestation Evidence

- `POST /builds/{id}/attestation/evidence` - assigned DATA_OWNER or assigned ENV_OPERATOR, Sig (multipart or JSON)
- `POST /builds/{id}/attestation/evidence/{evidence_id}/verify` - assigned AUDITOR, Sig (JSON body: required `attestation_certificate_pem`, optional `attestation_key_passphrase`)
- `GET /builds/{id}/attestation/status`

Export/userdata/acknowledge still enforce assigned ENV_OPERATOR at service level.

### 8.5 Rotation

- `GET /rotation/expired` - ADMIN
- `POST /rotation/force-password-change/{user_id}` - ADMIN, Sig
- `POST /rotation/revoke-key/{user_id}` - ADMIN, Sig

---

## 9. Frontend/Electron Implementation Notes

## 9.1 App Shell and Role Switching

- `App.jsx` restores role set from persisted auth state
- current role can be switched only among server-returned roles
- UI route availability changes on role switch
- backend still enforces access server-side

## 9.2 Build Management

- admin-only create-build flow
- role-specific assignee dropdowns
- assignee must be setup-ready and have target global role
- active/completed build tables with pagination

## 9.3 Build Details Tabs by Role

- ADMIN: Assignments, Audit
- SOLUTION_PROVIDER: Assignments, Add Workload, Audit
- DATA_OWNER: Assignments, Add Environment, Attestation Records, Audit
- AUDITOR: Assignments, Add Signing Key, Add Attestation Key, Finalise Contract, Verify Attestation, Audit
- ENV_OPERATOR: Assignments, Export Contract, Attestation Records, Audit
- VIEWER: Assignments, Audit

## 9.4 Local Crypto Boundary

Identity cryptographic operations stay local in Electron main process through preload IPC bridges:

- key generation/storage (identity RSA-4096 key pairs)
- hashing/signing (request signatures, audit event signatures)
- local file save/read for export flows

> **Deprecated (v2):** `contractCli.js` encryption/signing orchestration. In the v2 flow, contract cryptography is performed by the backend via API calls.

---

## 10. Security Controls

- token hashes only at rest (no raw token persistence in DB)
- request-signature verification bound to registered public keys
- setup-gated account activation before full API usage
- layered RBAC + assignment authorization
- audit hash chain tamper detection
- terminal build-state immutability semantics

---

## 11. Configuration (Backend)

From `internal/config/config.go`:

- `SERVER_HOST` (default `0.0.0.0`)
- `SERVER_PORT` (default `8080`)
- `DATABASE_URL` (required)
- `TOKEN_EXPIRY` (default `24h`)
- `BCRYPT_COST` (default `12`)
- `LOG_LEVEL` (default `info`)
- `LOG_FORMAT` (default `json`)
- `MAX_PAYLOAD_SIZE` (default `52428800`)
- `CORS_ALLOWED_ORIGINS` (default `http://localhost:5173,http://127.0.0.1:5173,null`)
- `CORS_ALLOW_ALL` (default `false`)
- `TRUST_PROXY_HEADERS` (default `false`)
- `REQUEST_TIMEOUT` (default `30s`)

Server startup seeding env vars:

- `ADMIN_EMAIL`
- `ADMIN_PASSWORD`
- `ADMIN_NAME`

> There is no `KEY_PROVIDER` env var. The PostgreSQL key provider (`keymgmt/db/`) is the sole active implementation and is wired unconditionally in `cmd/server/main.go`.

---

## 12. Known Constraints / Backlog

- Build listing for non-admin users currently performs assignment-first filtering then build fetches (functional but not the most query-efficient shape).
- Roles are modeled in both `persona_role` enum (`user_roles`) and `roles` table (`build_assignments`, `build_sections`) for backward compatibility and staged migration.
- OpenAPI endpoint is static and can lag runtime behavior.
- V1 build states (`AUDITOR_KEYS_REGISTERED`, `CONTRACT_ASSEMBLED`) are retained in the enum for backward compatibility but are not used by the v2 workflow.
- Frontend v2 API calls are currently consolidated in `buildService.js` (key registration, section/finalize orchestration, attestation evidence upload/verify); dedicated split service files remain optional refactor work.
- Private key encryption uses AES-256-CBC (OpenSSL PEM format). AES-256-GCM (authenticated encryption, no padding oracle risk) is the recommended upgrade path; deferred as a future hardening item.

---

> End of LLD v0.5
