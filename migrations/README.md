# Database Migrations

This directory contains PostgreSQL migration files for the IBM Confidential Computing Contract Generator backend.

## Migration Order

Migrations must be applied in numerical order:

1. **001_create_users** - Creates users table
2. **002_create_enums** - Creates ENUM types (build_status, persona_role, audit_event_type)
3. **003_create_user_roles** - Creates user_roles junction table
4. **004_create_api_tokens** - Creates API tokens table
5. **005_create_builds** - Creates builds table
6. **006_create_build_sections** - Creates build_sections table
7. **007_create_audit_events** - Creates audit_events table
8. **008_add_user_security_fields** - Adds public key and password rotation fields to users
9. **009_create_roles_table** - Creates roles reference table and seeds persona roles
10. **010_create_build_assignments** - Creates build_assignments table for explicit user-to-role assignments
11. **011_update_builds_table** - Adds encryption_certificate field to builds
12. **012_update_build_sections_table** - Adds role_id and renames wrapped_symmetric_key
13. **013_update_audit_events_table** - Adds actor_key_fingerprint and makes build_id nullable

## Phase 1 Migrations (008-013)

These migrations implement the security and assignment features required by the design:

### 008: User Security Fields
- **Public Key Management**: Adds fields for RSA-4096 public key storage, fingerprint, registration timestamp, and expiry
- **Password Rotation**: Adds must_change_password flag and password_changed_at timestamp
- **Purpose**: Enables cryptographic identity binding and credential rotation policy

### 009: Roles Reference Table
- **Creates**: First-class roles table to replace ENUM-only approach
- **Seeds**: Six persona roles (SOLUTION_PROVIDER, DATA_OWNER, AUDITOR, ENV_OPERATOR, ADMIN, VIEWER)
- **Purpose**: Enables foreign key references from user_roles and build_assignments

### 010: Build Assignments
- **Creates**: build_assignments table for explicit user-to-role assignments per build
- **Constraint**: Each role can only be assigned once per build (UNIQUE on build_id, role_id)
- **Purpose**: Enforces that only assigned users can contribute to specific builds

### 011: Builds Table Update
- **Adds**: encryption_certificate field to store HPCR encryption certificate
- **Purpose**: Solution Provider uploads this certificate; Auditor retrieves it for final contract assembly

### 012: Build Sections Table Update
- **Adds**: role_id foreign key reference to roles table
- **Renames**: encrypted_symmetric_key → wrapped_symmetric_key (for clarity)
- **Purpose**: Links sections to roles and clarifies that the key is RSA-OAEP wrapped

### 013: Audit Events Table Update
- **Adds**: actor_key_fingerprint for efficient public key lookups
- **Modifies**: Makes build_id nullable to support system-level events (user creation, role assignment)
- **Purpose**: Enables identity-bound signature verification in audit chain

## 021: Multiple User Public Keys

- **Creates**: `user_public_keys` with one row per registered client key (label, PEM, fingerprint, per-key expiry, `last_used_at`, `revoked_at`)
- **Backfill**: copies each user's existing `users.public_key*` into the new table with the label "Migrated key". Preserves the original registration and expiry timestamps. Missing registration falls back to migration time; missing expiry falls back to registration + 90 days.
- **Fingerprint**: lowercase hex, 64 characters, unique across all users. The migration aborts if two users share one key
- **Down**: first clears deprecated key fields, then restores each user's newest non-revoked key (including expired keys) into `users`; additional keys and revocation history are lost. Users with only revoked keys retain empty fields, so rollback cannot revive their old key.
- **Old columns**: `users.public_key*` stay for now and are marked deprecated; application services use only `user_public_keys`. A later migration removes the old columns.
- **Application policy**: `UserKeyService` enforces a maximum of five active keys, 90-day validity for new keys, and password confirmation after any registration history. These limits are not database constraints.

## Applying Migrations

### Using golang-migrate

```bash
# Install golang-migrate
go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest

# Apply all migrations
migrate -path backend/migrations -database "postgresql://user:pass@localhost:5432/dbname?sslmode=disable" up

# Apply specific number of migrations
migrate -path backend/migrations -database "postgresql://user:pass@localhost:5432/dbname?sslmode=disable" up 13

# Rollback last migration
migrate -path backend/migrations -database "postgresql://user:pass@localhost:5432/dbname?sslmode=disable" down 1

# Check migration version
migrate -path backend/migrations -database "postgresql://user:pass@localhost:5432/dbname?sslmode=disable" version
```

### Using psql directly

```bash
# Apply up migration
psql -U user -d dbname -f backend/migrations/008_add_user_security_fields.up.sql

# Rollback (down migration)
psql -U user -d dbname -f backend/migrations/008_add_user_security_fields.down.sql
```

## Migration Verification

After applying migrations, verify the schema:

```sql
-- Check users table has new columns
\d users

-- Check roles table exists and is seeded
SELECT * FROM roles ORDER BY name;

-- Check build_assignments table exists
\d build_assignments

-- Check builds table has encryption_certificate
\d builds

-- Check build_sections has role_id
\d build_sections

-- Check audit_events has actor_key_fingerprint
\d audit_events
```

## Next Steps

After applying Phase 1 migrations:

1. **Update sqlc queries** - Regenerate Go code with `sqlc generate`
2. **Update repository layer** - Add queries for new tables and fields
3. **Implement Phase 2** - Core security features (signature verification, audit hash chain)
4. **Implement Phase 3** - Build assignments logic and validation
5. **Implement Phase 4** - Export and verification endpoints
6. **Implement Phase 5** - Security hardening (rate limiting, credential rotation)
7. **Implement Phase 6** - Comprehensive testing

## Rollback Strategy

If issues occur, rollback migrations in reverse order:

```bash
# Rollback Phase 1 migrations (013 down to 008)
for i in {13..8}; do
  migrate -path backend/migrations -database "$DATABASE_URL" down 1
done
```

## Notes

- All migrations are idempotent (use `IF NOT EXISTS` / `IF EXISTS`)
- Down migrations are provided for all up migrations
- Foreign key constraints ensure referential integrity
- Indexes are created for frequently queried columns
- Comments are added to document column purposes
