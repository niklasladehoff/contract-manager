-- 021_create_user_public_keys.up.sql
-- Moves identity public keys out of users into user_public_keys so a user can register
-- one key per client (desktop app, CLI, scripts). Existing keys are copied over.
-- The users.public_key* columns stay for now; nothing reads or writes them after this migration.

-- Fail early if two users share a key. The fingerprint is unique in the new table, and silently
-- dropping one owner would hide a problem that needs a decision.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM users
        WHERE public_key IS NOT NULL AND public_key_fingerprint IS NOT NULL
        GROUP BY lower(replace(public_key_fingerprint, ':', ''))
        HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION 'migration 021: several users share one public key fingerprint; resolve before migrating';
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS user_public_keys (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label         VARCHAR(100) NOT NULL,
    public_key    TEXT         NOT NULL,
    fingerprint   VARCHAR(64)  NOT NULL UNIQUE CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    registered_at TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at    TIMESTAMPTZ  NOT NULL,
    last_used_at  TIMESTAMPTZ,
    revoked_at    TIMESTAMPTZ,
    revoked_by    UUID REFERENCES users(id) ON DELETE SET NULL
);

-- Lookups by owner only care about keys that can still sign.
CREATE INDEX IF NOT EXISTS idx_user_public_keys_user_active
    ON user_public_keys (user_id)
    WHERE revoked_at IS NULL;

-- Copy the single key every user has today. Expiry falls back to 90 days after registration.
INSERT INTO user_public_keys (user_id, label, public_key, fingerprint, registered_at, expires_at)
SELECT u.id,
       'Migrated key',
       u.public_key,
       lower(replace(u.public_key_fingerprint, ':', '')),
       COALESCE(u.public_key_registered_at, now()),
       COALESCE(u.public_key_expires_at, COALESCE(u.public_key_registered_at, now()) + INTERVAL '90 days')
FROM users u
WHERE u.public_key IS NOT NULL
  AND u.public_key_fingerprint IS NOT NULL
ON CONFLICT (fingerprint) DO NOTHING;

COMMENT ON TABLE user_public_keys IS 'RSA-4096 identity public keys, several per user (one per client)';
COMMENT ON COLUMN user_public_keys.fingerprint IS 'SHA-256 of the DER-encoded public key, lowercase hex without separators';
COMMENT ON COLUMN user_public_keys.expires_at IS 'Per-key expiry (90 days from registration)';
COMMENT ON COLUMN user_public_keys.revoked_at IS 'Set when the owner or an admin revokes the key; revoked keys never verify again';

COMMENT ON COLUMN users.public_key IS 'Deprecated: superseded by user_public_keys (migration 021)';
COMMENT ON COLUMN users.public_key_fingerprint IS 'Deprecated: superseded by user_public_keys (migration 021)';
COMMENT ON COLUMN users.public_key_registered_at IS 'Deprecated: superseded by user_public_keys (migration 021)';
COMMENT ON COLUMN users.public_key_expires_at IS 'Deprecated: superseded by user_public_keys (migration 021)';
