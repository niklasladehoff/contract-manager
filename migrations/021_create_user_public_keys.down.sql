-- 021_create_user_public_keys.down.sql
-- Restores the single-key columns on users from user_public_keys, then drops the table.
-- Each user gets back the newest key that was not revoked. Further keys are lost.

-- The old columns were not maintained while the table was in use; clear them so a key that was
-- revoked after migration 021 cannot come back.
UPDATE users
SET public_key = NULL,
    public_key_fingerprint = NULL,
    public_key_registered_at = NULL,
    public_key_expires_at = NULL;

UPDATE users u
SET public_key = k.public_key,
    public_key_fingerprint = k.fingerprint,
    public_key_registered_at = k.registered_at,
    public_key_expires_at = k.expires_at
FROM (
    SELECT DISTINCT ON (user_id) user_id, public_key, fingerprint, registered_at, expires_at
    FROM user_public_keys
    WHERE revoked_at IS NULL
    ORDER BY user_id, registered_at DESC, id DESC
) k
WHERE u.id = k.user_id;

DROP INDEX IF EXISTS idx_user_public_keys_user_active;
DROP TABLE IF EXISTS user_public_keys;

COMMENT ON COLUMN users.public_key IS 'RSA-4096 public key in PEM format for signature verification';
COMMENT ON COLUMN users.public_key_fingerprint IS 'SHA-256 fingerprint of the public key';
COMMENT ON COLUMN users.public_key_registered_at IS NULL;
COMMENT ON COLUMN users.public_key_expires_at IS 'Public key expiry timestamp (default 90 days from registration)';
