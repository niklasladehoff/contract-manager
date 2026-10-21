package service

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/ibm-hyper-protect/contract-manager/internal/crypto"
	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
)

type auditKeyQueries struct {
	repository.Querier
	activeKeys []repository.UserPublicKey
	listErr    error
	listedUser uuid.UUID
	created    bool
}

func (q *auditKeyQueries) GetLatestAuditEvent(context.Context, pgtype.UUID) (repository.GetLatestAuditEventRow, error) {
	return repository.GetLatestAuditEventRow{}, pgx.ErrNoRows
}

func (q *auditKeyQueries) ListActiveUserPublicKeys(_ context.Context, userID uuid.UUID) ([]repository.UserPublicKey, error) {
	q.listedUser = userID
	return q.activeKeys, q.listErr
}

func (q *auditKeyQueries) CreateAuditEvent(_ context.Context, p repository.CreateAuditEventParams) (repository.CreateAuditEventRow, error) {
	q.created = true
	return repository.CreateAuditEventRow{
		ActorPublicKey:      p.ActorPublicKey,
		ActorKeyFingerprint: p.ActorKeyFingerprint,
	}, nil
}

func TestAuditSigningKey(t *testing.T) {
	userID := uuid.New()
	keyA := repository.UserPublicKey{ID: uuid.New(), UserID: userID, PublicKey: "key A", Fingerprint: "fingerprint A"}
	keyB := repository.UserPublicKey{ID: uuid.New(), UserID: userID, PublicKey: "key B", Fingerprint: "fingerprint B"}
	foreignKey := repository.UserPublicKey{ID: uuid.New(), UserID: uuid.New(), PublicKey: "foreign key", Fingerprint: "foreign fingerprint"}
	tests := []struct {
		name        string
		contextKey  *repository.UserPublicKey
		explicitKey *repository.UserPublicKey
		activeKeys  []repository.UserPublicKey
		wantKey     *repository.UserPublicKey
		wantLookup  bool
	}{
		{name: "context key B overrides newest key A", contextKey: &keyB, activeKeys: []repository.UserPublicKey{keyA}, wantKey: &keyB},
		{name: "background event uses newest active key", activeKeys: []repository.UserPublicKey{keyA, keyB}, wantKey: &keyA, wantLookup: true},
		{name: "foreign context key is not attributed to actor", contextKey: &foreignKey, activeKeys: []repository.UserPublicKey{keyA}, wantKey: &keyA, wantLookup: true},
		{name: "explicit receipt key is preserved", contextKey: &keyA, explicitKey: &keyB, wantKey: &keyB},
		{name: "background event without active keys", wantLookup: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := &auditKeyQueries{activeKeys: tt.activeKeys}
			ctx := context.Background()
			if tt.contextKey != nil {
				ctx = WithSigningKey(ctx, *tt.contextKey)
			}
			input := LogEventInput{BuildID: uuid.New(), ActorUserID: userID, EventData: map[string]string{"action": "test"}}
			if tt.explicitKey != nil {
				input.ActorPublicKey = &tt.explicitKey.PublicKey
				input.ActorKeyFingerprint = &tt.explicitKey.Fingerprint
			}
			event, err := NewAuditService(q).LogEvent(ctx, input)
			if err != nil {
				t.Fatal(err)
			}
			if !q.created {
				t.Fatal("audit event was not created")
			}
			if tt.wantLookup {
				if q.listedUser != userID {
					t.Error("fallback did not query the actor's keys")
				}
			} else if q.listedUser != uuid.Nil {
				t.Error("key lookup should not replace a supplied signing key")
			}
			if tt.wantKey == nil {
				if event.ActorPublicKey != nil || event.ActorKeyFingerprint != nil {
					t.Error("event without an active key unexpectedly has key metadata")
				}
				return
			}
			if event.ActorPublicKey == nil || *event.ActorPublicKey != tt.wantKey.PublicKey {
				t.Error("audit event stored the wrong public key")
			}
			if event.ActorKeyFingerprint == nil || *event.ActorKeyFingerprint != tt.wantKey.Fingerprint {
				t.Error("audit event stored the wrong key fingerprint")
			}
		})
	}
}

func TestAuditSigningKeyLookupFailure(t *testing.T) {
	wantErr := errors.New("database unavailable")
	q := &auditKeyQueries{listErr: wantErr}
	_, err := NewAuditService(q).LogEvent(context.Background(), LogEventInput{BuildID: uuid.New(), ActorUserID: uuid.New()})
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want wrapped lookup error", err)
	}
	if q.created {
		t.Error("audit event created after key lookup failed")
	}
}

func TestAuditExplicitKeyMissingFingerprint(t *testing.T) {
	// Fingerprinting hashes the PEM's DER bytes; no key generation is needed.
	publicKey := "-----BEGIN PUBLIC KEY-----\nAQID\n-----END PUBLIC KEY-----\n"
	wantFingerprint, err := crypto.ComputePublicKeyFingerprint(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	q := &auditKeyQueries{}
	event, err := NewAuditService(q).LogEvent(context.Background(), LogEventInput{
		BuildID: uuid.New(), ActorUserID: uuid.New(), ActorPublicKey: &publicKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if event.ActorPublicKey == nil || *event.ActorPublicKey != publicKey {
		t.Error("explicit public key was changed")
	}
	if event.ActorKeyFingerprint == nil || *event.ActorKeyFingerprint != wantFingerprint {
		t.Error("fingerprint was not derived from explicit public key")
	}
}
