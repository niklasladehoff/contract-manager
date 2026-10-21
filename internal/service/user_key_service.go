package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/crypto/bcrypt"

	"github.com/ibm-hyper-protect/contract-manager/internal/crypto"
	"github.com/ibm-hyper-protect/contract-manager/internal/model"
	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
)

var (
	// ErrSigningKeyMissing means the user has no active identity key.
	ErrSigningKeyMissing = errors.New("no active signing key")
	// ErrSigningKeyRequired means several active keys need a fingerprint selector.
	ErrSigningKeyRequired = errors.New("key fingerprint header required")
	// ErrSigningKeyUnknown means the fingerprint does not belong to the user.
	ErrSigningKeyUnknown = errors.New("unknown signing key")
	// ErrSigningKeyRevoked means the selected identity key was revoked.
	ErrSigningKeyRevoked = errors.New("signing key revoked")
	// ErrSigningKeyExpired means the selected identity key has expired.
	ErrSigningKeyExpired = errors.New("signing key expired")
)

// txBeginner is implemented by *pgxpool.Pool and pgx.Tx.
type txBeginner interface {
	Begin(context.Context) (pgx.Tx, error)
}

// UserKeyService manages each user's client identity keys.
type UserKeyService struct {
	db      txBeginner
	queries repository.Querier
}

// NewUserKeyService creates a service with transaction support for key changes.
func NewUserKeyService(db txBeginner, queries repository.Querier) *UserKeyService {
	return &UserKeyService{db: db, queries: queries}
}

// AddKeyInput contains an RSA-4096 public key and optional registration metadata.
// Password is required if the user has ever registered a key.
type AddKeyInput struct {
	UserID       uuid.UUID
	PublicKeyPEM string
	Label        string
	Password     string
}

// AddKey serializes registration with other changes to this user's keys.
func (s *UserKeyService) AddKey(ctx context.Context, input AddKeyInput) (repository.UserPublicKey, error) {
	var empty repository.UserPublicKey
	if err := crypto.ValidatePublicKey(input.PublicKeyPEM); err != nil {
		return empty, model.ErrInvalidRequest("Invalid public key: " + err.Error())
	}
	fingerprint, err := crypto.ComputePublicKeyFingerprint(input.PublicKeyPEM)
	if err != nil {
		return empty, fmt.Errorf("compute key fingerprint: %w", err)
	}
	label := strings.TrimSpace(input.Label)
	if label == "" {
		label = "Key " + time.Now().UTC().Format("2006-01-02")
	}
	if utf8.RuneCountInString(label) > 100 || strings.ContainsRune(label, '\x00') {
		return empty, model.ErrInvalidRequest("Key label must be at most 100 characters and contain no null characters.")
	}
	tx, q, err := s.lockUser(ctx, input.UserID)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback(ctx)

	total, err := q.CountAllUserPublicKeys(ctx, input.UserID)
	if err != nil {
		return empty, fmt.Errorf("count all user keys: %w", err)
	}
	if total > 0 {
		user, err := q.GetUserByID(ctx, input.UserID)
		if err != nil {
			return empty, fmt.Errorf("load key owner: %w", err)
		}
		if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(input.Password)) != nil {
			return empty, model.ErrPasswordConfirmation()
		}
	}
	active, err := q.ListActiveUserPublicKeys(ctx, input.UserID)
	if err != nil {
		return empty, fmt.Errorf("list active user keys: %w", err)
	}
	// Recheck under the lock: a concurrent setup registration may have added
	// the first active key after the middleware allowed an unsigned request.
	if len(active) > 0 {
		signingKey, ok := SigningKeyFromContext(ctx)
		validSigner := false
		for _, key := range active {
			if ok && key.ID == signingKey.ID {
				validSigner = true
				break
			}
		}
		if !validSigner {
			return empty, model.ErrForbidden("Registration requires a request signed with an active key.")
		}
	}
	if len(active) >= 5 {
		return empty, model.ErrKeyLimitReached()
	}
	key, err := q.CreateUserPublicKey(ctx, repository.CreateUserPublicKeyParams{
		UserID: input.UserID, Label: label, PublicKey: input.PublicKeyPEM,
		Fingerprint: crypto.NormalizeFingerprint(fingerprint),
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return empty, model.ErrKeyAlreadyRegistered()
		}
		return empty, fmt.Errorf("create user public key: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return empty, fmt.Errorf("commit public key registration: %w", err)
	}
	return key, nil
}

func (s *UserKeyService) lockUser(ctx context.Context, userID uuid.UUID) (pgx.Tx, *repository.Queries, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("begin user key change: %w", err)
	}
	q := repository.New(tx)
	if _, err := q.LockUserForKeyChange(ctx, userID); err != nil {
		tx.Rollback(ctx)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, model.ErrUserNotFound(userID.String())
		}
		return nil, nil, fmt.Errorf("lock key owner: %w", err)
	}
	return tx, q, nil
}

// ListKeys includes expired and revoked keys for the owner's key history.
func (s *UserKeyService) ListKeys(ctx context.Context, userID uuid.UUID) ([]repository.UserPublicKey, error) {
	if _, err := s.queries.GetUserByID(ctx, userID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, model.ErrUserNotFound(userID.String())
		}
		return nil, fmt.Errorf("load key owner: %w", err)
	}
	keys, err := s.queries.ListUserPublicKeys(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list user public keys: %w", err)
	}
	return keys, nil
}

// GetLatestActiveKey supports the legacy single-key endpoint with the newest active key.
func (s *UserKeyService) GetLatestActiveKey(ctx context.Context, userID uuid.UUID) (repository.UserPublicKey, error) {
	if _, err := s.queries.GetUserByID(ctx, userID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.UserPublicKey{}, model.ErrUserNotFound(userID.String())
		}
		return repository.UserPublicKey{}, fmt.Errorf("load key owner: %w", err)
	}
	keys, err := s.queries.ListActiveUserPublicKeys(ctx, userID)
	if err != nil {
		return repository.UserPublicKey{}, fmt.Errorf("list active user public keys: %w", err)
	}
	if len(keys) == 0 {
		return repository.UserPublicKey{}, model.ErrInvalidRequest("User has no active public key.")
	}
	return keys[0], nil
}

// RevokeKey revokes one key belonging to userID and records who revoked it.
func (s *UserKeyService) RevokeKey(ctx context.Context, userID, keyID, actorID uuid.UUID) error {
	tx, q, err := s.lockUser(ctx, userID)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	count, err := q.RevokeUserPublicKey(ctx, repository.RevokeUserPublicKeyParams{
		ID: keyID, UserID: userID, RevokedBy: pgtype.UUID{Bytes: actorID, Valid: true},
	})
	if err != nil {
		return fmt.Errorf("revoke user public key: %w", err)
	}
	if count == 0 {
		return model.ErrKeyNotFound()
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit public key revocation: %w", err)
	}
	return nil
}

// RevokeAllKeys revokes all currently active keys and returns the affected count.
func (s *UserKeyService) RevokeAllKeys(ctx context.Context, userID, actorID uuid.UUID) (int64, error) {
	tx, q, err := s.lockUser(ctx, userID)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	count, err := q.RevokeAllUserPublicKeys(ctx, repository.RevokeAllUserPublicKeysParams{
		UserID: userID, RevokedBy: pgtype.UUID{Bytes: actorID, Valid: true},
	})
	if err != nil {
		return 0, fmt.Errorf("revoke all user public keys: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit public key revocations: %w", err)
	}
	return count, nil
}

// ResolveSigningKey selects the owner's key named by X-Key-Fingerprint.
// Without the header, selection succeeds only when exactly one key is active.
func (s *UserKeyService) ResolveSigningKey(ctx context.Context, userID uuid.UUID, header string) (repository.UserPublicKey, error) {
	keys, err := s.queries.ListUserPublicKeys(ctx, userID)
	if err != nil {
		return repository.UserPublicKey{}, fmt.Errorf("load signing keys: %w", err)
	}
	return pickSigningKey(keys, header, time.Now())
}

func pickSigningKey(keys []repository.UserPublicKey, header string, now time.Time) (repository.UserPublicKey, error) {
	fp := crypto.NormalizeFingerprint(header)
	if strings.TrimSpace(header) != "" {
		for _, key := range keys {
			if crypto.NormalizeFingerprint(key.Fingerprint) != fp {
				continue
			}
			if key.RevokedAt.Valid {
				return repository.UserPublicKey{}, ErrSigningKeyRevoked
			}
			if !key.ExpiresAt.After(now) {
				return repository.UserPublicKey{}, ErrSigningKeyExpired
			}
			return key, nil
		}
		return repository.UserPublicKey{}, ErrSigningKeyUnknown
	}
	var selected repository.UserPublicKey
	count := 0
	for _, key := range keys {
		if !key.RevokedAt.Valid && key.ExpiresAt.After(now) {
			selected = key
			count++
		}
	}
	if count == 0 {
		return repository.UserPublicKey{}, ErrSigningKeyMissing
	}
	if count > 1 {
		return repository.UserPublicKey{}, ErrSigningKeyRequired
	}
	return selected, nil
}
