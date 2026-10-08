-- 020_remove_v1_enum_values.up.sql
-- Removes the V1-only enum values AUDITOR_KEYS_REGISTERED and CONTRACT_ASSEMBLED
-- from build_status and audit_event_type.
--
-- PostgreSQL does not support DROP VALUE on an existing enum type.
-- The standard workaround is:
--   1. Create a replacement enum type without the removed values.
--   2. Change all columns to use the new type (with explicit USING cast).
--   3. Drop the old type and rename the new one.
--
-- These values are safe to remove because:
--   - No rows using AUDITOR_KEYS_REGISTERED or CONTRACT_ASSEMBLED exist
--     in a V2-only deployment (the V2 workflow never transitions through them).
--   - The corresponding Go constants have been removed from the application.

BEGIN;

-- ── build_status ──────────────────────────────────────────────────────────────

CREATE TYPE build_status_new AS ENUM (
    'CREATED',
    'SIGNING_KEY_REGISTERED',
    'WORKLOAD_SUBMITTED',
    'ENVIRONMENT_STAGED',
    'ATTESTATION_KEY_REGISTERED',
    'FINALIZED',
    'CONTRACT_DOWNLOADED',
    'CANCELLED'
);

-- Migrate the builds.status column.
-- Drop the default first; it references the old enum and blocks the type change.
ALTER TABLE builds ALTER COLUMN status DROP DEFAULT;
ALTER TABLE builds
    ALTER COLUMN status TYPE build_status_new
    USING status::text::build_status_new;

DROP TYPE build_status;
ALTER TYPE build_status_new RENAME TO build_status;
ALTER TABLE builds ALTER COLUMN status SET DEFAULT 'CREATED';

-- Restore the default using the renamed type.
ALTER TABLE builds ALTER COLUMN status SET DEFAULT 'CREATED';


-- ── audit_event_type ──────────────────────────────────────────────────────────

CREATE TYPE audit_event_type_new AS ENUM (
    'BUILD_CREATED',
    'WORKLOAD_SUBMITTED',
    'ENVIRONMENT_STAGED',
    'BUILD_FINALIZED',
    'BUILD_CANCELLED',
    'SIGNING_KEY_CREATED',
    'ATTESTATION_KEY_REGISTERED',
    'ATTESTATION_EVIDENCE_UPLOADED',
    'ATTESTATION_VERIFIED',
    'USER_CREATED',
    'ROLE_ASSIGNED',
    'TOKEN_CREATED',
    'TOKEN_REVOKED',
    'CONTRACT_DOWNLOADED'
);

-- Migrate the audit_events.event_type column.
ALTER TABLE audit_events
    ALTER COLUMN event_type TYPE audit_event_type_new
    USING event_type::text::audit_event_type_new;

DROP TYPE audit_event_type;
ALTER TYPE audit_event_type_new RENAME TO audit_event_type;

COMMIT;
