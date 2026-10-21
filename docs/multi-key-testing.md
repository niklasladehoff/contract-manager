# Multi-key verification

Run from the `contract-manager` root:

```bash
sqlc generate
go build ./...
go vet ./...
go test ./...
```

Database tests skip unless `TEST_DATABASE_URL` is set. Use a disposable PostgreSQL database with migrations through 021; these tests insert users, keys, builds, roles, tokens, audit events, and system logs. They clean up their fixtures, but must not run against production.

Example (requires a running Podman machine and a free port):

```bash
podman run -d --rm --name contract-key-tests \
  -e POSTGRES_PASSWORD=test -e POSTGRES_DB=contract \
  -p 127.0.0.1:54379:5432 postgres:16-alpine

# Wait until PostgreSQL accepts connections before migrating.
podman exec contract-key-tests pg_isready -U postgres
export TEST_DATABASE_URL='postgres://postgres:test@127.0.0.1:54379/contract?sslmode=disable'
migrate -path migrations -database "$TEST_DATABASE_URL" up
go test -race ./...

podman stop contract-key-tests
unset TEST_DATABASE_URL
```

Coverage:

- Fingerprint normalization, active-key selection, missing/ambiguous headers, foreign, expired, and revoked keys.
- RSA-PSS request verification, conditional registration exemption, and database failures.
- Setup state, login compatibility metadata, and user-list active counts.
- Real database registration: first key without password, later keys with confirmation, duplicates, five-key limit, revocation, and concurrent registration for the last slot.
- Expiry after transaction start: locked operations recheck the current key state, and new registrations receive their own registration/expiry timestamps.
- Complete HTTP lifecycle using real authentication, authorization, services, and PostgreSQL: two clients, owner/admin boundaries, expired-key recovery, single/all revocation, rotation preserving active devices, and historical audit verification after revocation. Download receipts use the actual request-signing key, including an older active key; a receipt signed with another device's key is rejected.
- Per-key rotation reports and the separate list of accounts without active keys.
- OpenAPI JSON parsing and resolution of every local schema reference.

For focused runs:

```bash
go test ./internal/middleware -run Signature -v
go test ./internal/service -run UserKey -v
go test ./internal/handler -run UserKeysHTTP -v
```

Migration 021 also needs a rollback check on a separate disposable database: migrate to 020, seed legacy `users.public_key*` values, then apply 021, down one, and up one. Verify preserved timestamps, fallback dates, normalized fingerprints, newest unrevoked-key selection (including expired keys), and empty legacy fields when every key was revoked. Rollback discards additional keys and revocation history; it is not a lossless downgrade.

The desktop UI integration is a separate step: registration must supply password confirmation after any history and sign with an existing active key when one exists. Every signed request should send the local key's fingerprint; the login fingerprint only describes the newest active key and must not select another device's key.
