-- name: GetUserByEmail :one
SELECT u.id, u.name, u.email, u.password_hash, u.is_active, u.created_at,
       k.public_key, k.fingerprint AS public_key_fingerprint,
       k.registered_at AS public_key_registered_at, k.expires_at AS public_key_expires_at,
       u.must_change_password, u.password_changed_at,
       (SELECT COUNT(*) FROM user_public_keys k
        WHERE k.user_id = u.id AND k.revoked_at IS NULL AND k.expires_at > statement_timestamp()) AS active_key_count,
       (SELECT COUNT(*) FROM user_public_keys k WHERE k.user_id = u.id) AS total_key_count
FROM users u
LEFT JOIN user_public_keys k ON k.id = (
    SELECT x.id FROM user_public_keys x
    WHERE x.user_id = u.id AND x.revoked_at IS NULL AND x.expires_at > statement_timestamp()
    ORDER BY x.registered_at DESC, x.id DESC LIMIT 1
)
WHERE u.email = $1;

-- name: GetUserByID :one
SELECT u.id, u.name, u.email, u.password_hash, u.is_active, u.created_at,
       k.public_key, k.fingerprint AS public_key_fingerprint,
       k.registered_at AS public_key_registered_at, k.expires_at AS public_key_expires_at,
       u.must_change_password, u.password_changed_at,
       (SELECT COUNT(*) FROM user_public_keys k
        WHERE k.user_id = u.id AND k.revoked_at IS NULL AND k.expires_at > statement_timestamp()) AS active_key_count,
       (SELECT COUNT(*) FROM user_public_keys k WHERE k.user_id = u.id) AS total_key_count
FROM users u
LEFT JOIN user_public_keys k ON k.id = (
    SELECT x.id FROM user_public_keys x
    WHERE x.user_id = u.id AND x.revoked_at IS NULL AND x.expires_at > statement_timestamp()
    ORDER BY x.registered_at DESC, x.id DESC LIMIT 1
)
WHERE u.id = $1;

-- name: ListUsers :many
SELECT u.id, u.name, u.email, u.is_active, u.created_at,
       k.fingerprint AS public_key_fingerprint, k.expires_at AS public_key_expires_at,
       u.must_change_password,
       (SELECT COUNT(*) FROM user_public_keys x
        WHERE x.user_id = u.id AND x.revoked_at IS NULL AND x.expires_at > statement_timestamp()) AS active_key_count
FROM users u
LEFT JOIN user_public_keys k ON k.id = (
    SELECT x.id FROM user_public_keys x
    WHERE x.user_id = u.id AND x.revoked_at IS NULL AND x.expires_at > statement_timestamp()
    ORDER BY x.registered_at DESC, x.id DESC LIMIT 1
)
ORDER BY u.created_at DESC;

-- name: CreateUser :one
INSERT INTO users (name, email, password_hash)
VALUES ($1, $2, $3)
RETURNING id, name, email, is_active, created_at, must_change_password, password_changed_at;

-- name: DeactivateUser :exec
UPDATE users SET is_active = false WHERE id = $1;

-- name: UpdatePassword :exec
UPDATE users
SET password_hash = $2,
    must_change_password = false,
    password_changed_at = NOW()
WHERE id = $1;

-- name: ForcePasswordChange :exec
UPDATE users
SET must_change_password = true
WHERE id = $1;

-- name: GetUsersWithExpiredPasswords :many
SELECT id, name, email, password_changed_at, must_change_password, created_at
FROM users
WHERE is_active = true
  AND (
    must_change_password = true
    OR password_changed_at < NOW() - INTERVAL '90 days'
  );

-- name: UpdateUser :one
UPDATE users
SET name = $2, email = $3
WHERE id = $1
RETURNING id, name, email, is_active, created_at, must_change_password, password_changed_at;

-- name: ReactivateUser :exec
UPDATE users SET is_active = true WHERE id = $1;

-- name: AdminResetPassword :exec
UPDATE users
SET password_hash = $2,
    must_change_password = true,
    password_changed_at = NOW()
WHERE id = $1;
