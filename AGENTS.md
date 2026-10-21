# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Stack

- Go 1.26, module `github.com/ibm-hyper-protect/contract-manager`
- Chi v5 router, pgx/v5 (PostgreSQL), SQLC-generated repository layer
- No external test framework — standard `testing` package only
- Deployed via Docker Compose (`compose/docker-compose.yaml`)

## Build & Run Commands

```bash
# Build binary
go build -o server ./cmd/server

# Run all tests
go test ./...

# Run a single test
go test ./internal/service -run TestLogin

# Vet
go vet ./...

# Format
gofmt -w .

# Regenerate SQLC repository code (after editing SQL in internal/repository/queries/)
sqlc generate
```

> There is no Makefile. All commands are run from the repo root.

## Architecture

```
cmd/server/main.go      → wires all services; single binary
internal/config/        → env-var config only (no config files)
internal/model/         → domain types + AppError constructors
internal/repository/    → SQLC-generated code; DO NOT edit *.sql.go directly
internal/repository/queries/*.sql → only source of truth for DB queries
internal/service/       → business logic; wraps repository.Querier interface
internal/handler/       → HTTP handlers; use writeJSON / writeError helpers
internal/middleware/    → Chi middleware (auth, RBAC, signature, rate-limit)
internal/contract/      → Engine interface + contractgo implementation
internal/keymgmt/       → KeyProvider interface; db and mock implementations
```

## Critical Non-Obvious Patterns

### Database layer
- `internal/repository/*.sql.go` files are **SQLC-generated** — never edit them manually. Edit `.sql` files in `internal/repository/queries/` then run `sqlc generate`.
- `v2_store.go` contains **raw SQL** (not SQLC) for tables not yet in migrations that SQLC processes. New tables should prefer adding to queries/ and regenerating.
- `pgtype.Timestamptz` is used for nullable timestamps; convert to `*time.Time` before returning from service layer (see `auth_service.go` for the pattern).

### Error handling
- All HTTP errors **must** use `model.AppError` constructors from `internal/model/errors.go` — e.g. `model.ErrNotFound(...)`, `model.ErrForbidden(...)`. Do **not** return raw errors or ad-hoc JSON to the client.
- In handlers, call `writeError(w, model.ErrXxx(...))` — never `http.Error()`.
- In services, return `fmt.Errorf("context: %w", err)` for internal errors; return `*model.AppError` for domain errors that the handler should surface directly.

### Request body parsing
- Use `readJSON(r, &req)` for normal-sized JSON bodies (enforces 1 MB limit, `DisallowUnknownFields`).
- Use `readJSONLarge(r, &req, n)` for large encrypted payloads (skips unknown-fields check).
- Call `drainBody(r)` before returning on early-exit paths where the body was not fully consumed.

### Signature middleware
- Every authenticated **mutating** request (POST/PUT/PATCH/DELETE) requires `X-Signature`, `X-Signature-Hash`, and `X-Timestamp` headers — **except** `/auth/logout` and `PATCH .../password`. `PUT .../public-key` is exempt only when the caller has zero active keys.
- `X-Key-Fingerprint` selects an active identity key from `user_public_keys`. Without this header, verification succeeds only when exactly one key is active. Use the verified signing key from the request context for audit records and download receipts.
- Identity key changes go through `UserKeyService`; registration and revocation lock the user row. Registration requires password confirmation after any key history and allows at most five active keys. Do not read or update the deprecated `users.public_key*` columns.
- The signed payload is JSON: `{"method":"POST","path":"/builds","data":<body>,"timestamp":<ms>}`.

### RBAC middleware
- `middleware.RequireRole(...)` checks roles stored in JWT context — apply **before** the handler, not inside it.
- `middleware.RequireBuildAccess(queries, "id")` — non-ADMIN users can only access builds they are assigned to; this query hits the DB per request.

### Key management
- There is **no Vault** — private keys are stored as AES-256-CBC encrypted PEM blobs in PostgreSQL (`keymgmt/db/provider.go`). The comment in `config.go` is the canonical explanation.
- `keymgmt.KeyProvider` is the interface; use `keymgmt/mock` in unit tests.

### Build state machine
- Build lifecycle is a strict linear sequence defined in `model.BuildStatus` / `ValidTransitions`. Use `status.CanTransitionTo(next)` to validate — never do manual string comparison.
- `BuildStatus.IsTerminal()` returns true for FINALIZED, CONTRACT_DOWNLOADED, CANCELLED.

### Logging
- Use `log/slog` (standard library) everywhere — never `fmt.Println` or `log.Printf`.
- All business events are also written to the `system_logs` table via `service.SystemLogService.LogEvent(...)`.

### Import ordering (gofmt convention used throughout)
1. Standard library
2. Blank line
3. Third-party (`github.com/go-chi/...`, `github.com/google/uuid`, etc.)
4. Blank line
5. Internal (`github.com/ibm-hyper-protect/contract-manager/internal/...`)

### Naming conventions
- Handler structs: `XxxHandler`; constructor: `NewXxxHandler`
- Service structs: `XxxService`; constructor: `NewXxxService`
- Repository input params: SQLC-generated `XxxParams` structs
- Enum-style constants: typed string aliases (e.g. `BuildStatus`, `PersonaRole`)

## Environment Variables Required at Runtime
- `DATABASE_URL` — required, no default
- `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `ADMIN_NAME` — seed admin on first start if no users exist
- `TOKEN_EXPIRY` (default `24h`), `BCRYPT_COST` (default `12`)
- `LOG_FORMAT` — `json` (default) or `text`
