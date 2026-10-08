-- 020_remove_v1_enum_values.down.sql
-- Restores the V1 enum values AUDITOR_KEYS_REGISTERED and CONTRACT_ASSEMBLED.
-- Note: This rollback cannot recover any rows that used these values
-- (none exist in a V2-only deployment).

BEGIN;

-- ── build_status ──────────────────────────────────────────────────────────────

CREATE TYPE build_status_with_v1 AS ENUM (
    'CREATED',
    'SIGNING_KEY_REGISTERED',
    'WORKLOAD_SUBMITTED',
    'ENVIRONMENT_STAGED',
    'AUDITOR_KEYS_REGISTERED',
    'CONTRACT_ASSEMBLED',
    'ATTESTATION_KEY_REGISTERED',
    'FINALIZED',
    'CONTRACT_DOWNLOADED',
    'CANCELLED'
);

ALTER TABLE builds ALTER COLUMN status DROP DEFAULT;
ALTER TABLE builds
    ALTER COLUMN status TYPE build_status_with_v1
    USING status::text::build_status_with_v1;

DROP TYPE build_status;
ALTER TYPE build_status_with_v1 RENAME TO build_status;
ALTER TABLE builds ALTER COLUMN status SET DEFAULT 'CREATED';


-- ── audit_event_type ──────────────────────────────────────────────────────────

CREATE TYPE audit_event_type_with_v1 AS ENUM (
    'BUILD_CREATED',
    'WORKLOAD_SUBMITTED',
    'ENVIRONMENT_STAGED',
    'AUDITOR_KEYS_REGISTERED',
    'CONTRACT_ASSEMBLED',
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

ALTER TABLE audit_events
    ALTER COLUMN event_type TYPE audit_event_type_with_v1
    USING event_type::text::audit_event_type_with_v1;

DROP TYPE audit_event_type;
ALTER TYPE audit_event_type_with_v1 RENAME TO audit_event_type;

COMMIT;
