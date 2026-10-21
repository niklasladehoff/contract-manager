package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/ibm-hyper-protect/contract-manager/internal/crypto"
	"github.com/ibm-hyper-protect/contract-manager/internal/model"
	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
)

func TestUserKeyPickSigningKey(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	active := repository.UserPublicKey{ID: uuid.New(), Fingerprint: "abcd", ExpiresAt: now.Add(time.Hour)}
	second := repository.UserPublicKey{ID: uuid.New(), Fingerprint: "ef01", ExpiresAt: now.Add(time.Hour)}
	expired := repository.UserPublicKey{ID: uuid.New(), Fingerprint: "1234", ExpiresAt: now}
	revoked := repository.UserPublicKey{
		ID: uuid.New(), Fingerprint: "5678", ExpiresAt: now.Add(time.Hour),
		RevokedAt: pgtype.Timestamptz{Time: now.Add(-time.Hour), Valid: true},
	}
	tests := []struct {
		name    string
		keys    []repository.UserPublicKey
		header  string
		wantID  uuid.UUID
		wantErr error
	}{
		{name: "no keys", wantErr: ErrSigningKeyMissing},
		{name: "one active key", keys: []repository.UserPublicKey{active}, wantID: active.ID},
		{name: "multiple active keys require header", keys: []repository.UserPublicKey{active, second}, wantErr: ErrSigningKeyRequired},
		{name: "inactive keys do not make fallback ambiguous", keys: []repository.UserPublicKey{expired, active, revoked}, wantID: active.ID},
		{name: "only inactive keys", keys: []repository.UserPublicKey{expired, revoked}, wantErr: ErrSigningKeyMissing},
		{name: "normalized header", keys: []repository.UserPublicKey{active, second}, header: " AB:CD ", wantID: active.ID},
		{name: "second key", keys: []repository.UserPublicKey{active, second}, header: "ef01", wantID: second.ID},
		{name: "unknown key", keys: []repository.UserPublicKey{active}, header: "ffff", wantErr: ErrSigningKeyUnknown},
		{name: "explicit key with no keys", header: "abcd", wantErr: ErrSigningKeyUnknown},
		{name: "malformed header does not use fallback", keys: []repository.UserPublicKey{active}, header: ":", wantErr: ErrSigningKeyUnknown},
		{name: "expiry boundary", keys: []repository.UserPublicKey{expired}, header: expired.Fingerprint, wantErr: ErrSigningKeyExpired},
		{name: "revoked key", keys: []repository.UserPublicKey{revoked}, header: revoked.Fingerprint, wantErr: ErrSigningKeyRevoked},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pickSigningKey(tt.keys, tt.header, now)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
			if got.ID != tt.wantID {
				t.Errorf("key ID = %s, want %s", got.ID, tt.wantID)
			}
		})
	}
}

var userKeyFixtureOnce sync.Once
var userKeyFixturePEMs []string
var userKeyFixtureErr error

func userKeyPublicKeys(t *testing.T) []string {
	t.Helper()
	userKeyFixtureOnce.Do(func() {
		for range 6 {
			key, err := rsa.GenerateKey(rand.Reader, 4096)
			if err != nil {
				userKeyFixtureErr = err
				return
			}
			der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
			if err != nil {
				userKeyFixtureErr = err
				return
			}
			userKeyFixturePEMs = append(userKeyFixturePEMs, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})))
		}
	})
	if userKeyFixtureErr != nil {
		t.Fatal(userKeyFixtureErr)
	}
	return userKeyFixturePEMs
}

func requireUserKeyError(t *testing.T, err error, code string) {
	t.Helper()
	var appErr *model.AppError
	if !errors.As(err, &appErr) || appErr.Code != code {
		t.Fatalf("error = %v, want %s", err, code)
	}
}

func TestUserKeyLifecycle(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	// All fixtures live in a rollback-only transaction. The service uses nested
	// transactions (savepoints), so its real commit/rollback paths still run.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tx.Rollback(ctx) })
	q := repository.New(tx)
	svc := NewUserKeyService(tx, q)
	password := "test-password"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	user, err := q.CreateUser(ctx, repository.CreateUserParams{
		Name: "User key test", Email: uuid.NewString() + "@example.test", PasswordHash: string(hash),
	})
	if err != nil {
		t.Fatal(err)
	}
	publicKeys := userKeyPublicKeys(t)
	first, err := svc.AddKey(ctx, AddKeyInput{UserID: user.ID, PublicKeyPEM: publicKeys[0]})
	if err != nil {
		t.Fatalf("first key without password: %v", err)
	}
	if !strings.HasPrefix(first.Label, "Key ") {
		t.Errorf("default label = %q", first.Label)
	}
	if first.ExpiresAt.Sub(first.RegisteredAt) != 90*24*time.Hour {
		t.Errorf("key validity = %s", first.ExpiresAt.Sub(first.RegisteredAt))
	}
	fingerprint, err := crypto.ComputePublicKeyFingerprint(publicKeys[0])
	if err != nil {
		t.Fatal(err)
	}
	if first.Fingerprint != fingerprint {
		t.Errorf("fingerprint = %q, want %q", first.Fingerprint, fingerprint)
	}
	signedCtx := WithSigningKey(ctx, first)
	_, err = svc.AddKey(signedCtx, AddKeyInput{UserID: user.ID, PublicKeyPEM: publicKeys[1], Password: "wrong"})
	requireUserKeyError(t, err, "PASSWORD_CONFIRMATION_FAILED")
	_, err = svc.AddKey(ctx, AddKeyInput{UserID: user.ID, PublicKeyPEM: publicKeys[1], Password: password})
	requireUserKeyError(t, err, "FORBIDDEN")
	_, err = svc.AddKey(signedCtx, AddKeyInput{UserID: user.ID, PublicKeyPEM: publicKeys[0], Password: password})
	requireUserKeyError(t, err, "KEY_ALREADY_REGISTERED")
	var second repository.UserPublicKey
	for i := 1; i < 5; i++ {
		key, err := svc.AddKey(signedCtx, AddKeyInput{UserID: user.ID, PublicKeyPEM: publicKeys[i], Password: password, Label: "Client"})
		if err != nil {
			t.Fatalf("add key %d: %v", i+1, err)
		}
		if i == 1 {
			second = key
		}
	}
	_, err = svc.AddKey(signedCtx, AddKeyInput{UserID: user.ID, PublicKeyPEM: publicKeys[5], Password: password})
	requireUserKeyError(t, err, "KEY_LIMIT_REACHED")
	resolved, err := svc.ResolveSigningKey(ctx, user.ID, second.Fingerprint)
	if err != nil || resolved.ID != second.ID {
		t.Fatalf("resolve second key = %v, %v", resolved.ID, err)
	}
	_, err = svc.ResolveSigningKey(ctx, user.ID, "")
	if !errors.Is(err, ErrSigningKeyRequired) {
		t.Fatalf("resolve without fingerprint = %v", err)
	}
	if err := svc.RevokeKey(ctx, user.ID, second.ID, user.ID); err != nil {
		t.Fatal(err)
	}
	if err := svc.RevokeKey(ctx, user.ID, second.ID, user.ID); err == nil {
		t.Fatal("revoking twice succeeded")
	} else {
		requireUserKeyError(t, err, "KEY_NOT_FOUND")
	}
	_, err = svc.ResolveSigningKey(ctx, user.ID, second.Fingerprint)
	if !errors.Is(err, ErrSigningKeyRevoked) {
		t.Fatalf("resolve revoked key = %v", err)
	}
	_, err = svc.AddKey(WithSigningKey(ctx, second), AddKeyInput{UserID: user.ID, PublicKeyPEM: publicKeys[5], Password: password})
	requireUserKeyError(t, err, "FORBIDDEN")
	_, err = svc.AddKey(signedCtx, AddKeyInput{UserID: user.ID, PublicKeyPEM: publicKeys[5], Password: password})
	if err != nil {
		t.Fatalf("revoked key must not count toward limit: %v", err)
	}
	keys, err := svc.ListKeys(ctx, user.ID)
	if err != nil || len(keys) != 6 {
		t.Fatalf("list keys = %d keys, %v", len(keys), err)
	}
	count, err := svc.RevokeAllKeys(ctx, user.ID, user.ID)
	if err != nil || count != 5 {
		t.Fatalf("revoke all = %d, %v; want 5", count, err)
	}
	_, err = svc.ResolveSigningKey(ctx, user.ID, "")
	if !errors.Is(err, ErrSigningKeyMissing) {
		t.Fatalf("resolve after revoke all = %v", err)
	}
	_, err = svc.AddKey(ctx, AddKeyInput{UserID: user.ID, PublicKeyPEM: publicKeys[0]})
	requireUserKeyError(t, err, "PASSWORD_CONFIRMATION_FAILED")
	_, err = svc.ListKeys(ctx, uuid.New())
	requireUserKeyError(t, err, "USER_NOT_FOUND")
	_, err = svc.AddKey(ctx, AddKeyInput{UserID: uuid.New(), PublicKeyPEM: publicKeys[0]})
	requireUserKeyError(t, err, "USER_NOT_FOUND")
}

func TestUserKeyExpiryAfterTransactionStart(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tx.Rollback(ctx) })
	q := repository.New(tx)
	svc := NewUserKeyService(tx, q)
	password := "expiry-test-password"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	user, err := q.CreateUser(ctx, repository.CreateUserParams{Name: "Key expiry test", Email: uuid.NewString() + "@example.test", PasswordHash: string(hash)})
	if err != nil {
		t.Fatal(err)
	}
	publicKeys := userKeyPublicKeys(t)
	first, err := svc.AddKey(ctx, AddKeyInput{UserID: user.ID, PublicKeyPEM: publicKeys[0]})
	if err != nil {
		t.Fatal(err)
	}
	// Expire after the transaction began, as can happen while registration
	// waits for the user lock. No sleep or host/database clock agreement needed.
	if _, err := tx.Exec(ctx, "UPDATE user_public_keys SET expires_at = statement_timestamp() WHERE id = $1", first.ID); err != nil {
		t.Fatal(err)
	}
	active, err := q.ListActiveUserPublicKeys(ctx, user.ID)
	if err != nil || len(active) != 0 {
		t.Fatalf("expired key still active after transaction start: %v %v", active, err)
	}
	owner, err := q.GetUserByID(ctx, user.ID)
	if err != nil || owner.ActiveKeyCount != 0 || owner.PublicKeyFingerprint != nil {
		t.Fatalf("expired key leaked into account state: %+v %v", owner, err)
	}
	if count, err := svc.RevokeAllKeys(ctx, user.ID, user.ID); err != nil || count != 0 {
		t.Fatalf("expired key counted as active during revoke-all: %d %v", count, err)
	}
	// Recovery needs password confirmation but no signature when no key remains active.
	second, err := svc.AddKey(ctx, AddKeyInput{UserID: user.ID, PublicKeyPEM: publicKeys[1], Password: password})
	if err != nil {
		t.Fatal(err)
	}
	if !second.RegisteredAt.After(first.RegisteredAt) || second.ExpiresAt.Sub(second.RegisteredAt) != 90*24*time.Hour {
		t.Fatalf("registration timestamps reused transaction start: %+v", second)
	}
}

func TestUserKeyConcurrentRegistrationLimit(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	q := repository.New(pool)
	password := "concurrent-key-test"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	user, err := q.CreateUser(ctx, repository.CreateUserParams{Name: "Concurrent key test", Email: uuid.NewString() + "@example.test", PasswordHash: string(hash)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), "DELETE FROM users WHERE id = $1", user.ID); err != nil {
			t.Error(err)
		}
	})
	svc := NewUserKeyService(pool, q)
	publicKeys := userKeyPublicKeys(t)
	first, err := svc.AddKey(ctx, AddKeyInput{UserID: user.ID, PublicKeyPEM: publicKeys[0]})
	if err != nil {
		t.Fatal(err)
	}
	signedCtx := WithSigningKey(ctx, first)
	for i := 1; i < 4; i++ {
		if _, err := svc.AddKey(signedCtx, AddKeyInput{UserID: user.ID, PublicKeyPEM: publicKeys[i], Password: password}); err != nil {
			t.Fatal(err)
		}
	}
	// Two independent transactions compete for the last available slot.
	start := make(chan struct{})
	results := make(chan error, 2)
	for i := 4; i < 6; i++ {
		go func(pem string) {
			<-start
			_, err := svc.AddKey(signedCtx, AddKeyInput{UserID: user.ID, PublicKeyPEM: pem, Password: password})
			results <- err
		}(publicKeys[i])
	}
	close(start)
	successes := 0
	for range 2 {
		if err := <-results; err == nil {
			successes++
		} else {
			requireUserKeyError(t, err, "KEY_LIMIT_REACHED")
		}
	}
	count, err := q.CountActiveUserPublicKeys(ctx, user.ID)
	if err != nil || count != 5 || successes != 1 {
		t.Fatalf("active=%d successful=%d error=%v; want 5 active, 1 successful registration", count, successes, err)
	}
}
