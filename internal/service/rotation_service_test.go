package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
)

type rotationKeyQueries struct {
	repository.Querier
	expired                                                 []repository.ListExpiredUserPublicKeysRow
	missing                                                 []repository.ListUsersWithoutActiveKeyRow
	passwordErr, expiredErr, missingErr, userErr, revokeErr error
	revoked                                                 *repository.RevokeExpiredUserPublicKeysParams
}

func (q *rotationKeyQueries) GetUsersWithExpiredPasswords(context.Context) ([]repository.GetUsersWithExpiredPasswordsRow, error) {
	return nil, q.passwordErr
}
func (q *rotationKeyQueries) ListExpiredUserPublicKeys(context.Context) ([]repository.ListExpiredUserPublicKeysRow, error) {
	return q.expired, q.expiredErr
}
func (q *rotationKeyQueries) ListUsersWithoutActiveKey(context.Context) ([]repository.ListUsersWithoutActiveKeyRow, error) {
	return q.missing, q.missingErr
}
func (q *rotationKeyQueries) GetUserByID(context.Context, uuid.UUID) (repository.GetUserByIDRow, error) {
	return repository.GetUserByIDRow{}, q.userErr
}
func (q *rotationKeyQueries) RevokeExpiredUserPublicKeys(_ context.Context, params repository.RevokeExpiredUserPublicKeysParams) (int64, error) {
	q.revoked = &params
	return 1, q.revokeErr
}

func TestRotationReportsIndividualKeysAndMissingSetup(t *testing.T) {
	owner, keyID, missing := uuid.New(), uuid.New(), uuid.New()
	now := time.Now()
	q := &rotationKeyQueries{
		expired: []repository.ListExpiredUserPublicKeysRow{{
			ID: keyID, UserID: owner, UserName: "Owner", UserEmail: "owner@example.test",
			Label: "Old laptop", Fingerprint: "abcd", RegisteredAt: now.Add(-100 * 24 * time.Hour), ExpiresAt: now.Add(-10 * 24 * time.Hour),
		}},
		missing: []repository.ListUsersWithoutActiveKeyRow{{ID: missing, Name: "Needs setup", Email: "setup@example.test"}},
	}
	report, err := NewRotationService(q).CheckExpiredCredentials(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if report.TotalExpired != 1 || len(report.ExpiredPublicKeys) != 1 || len(report.UsersWithoutActiveKey) != 1 {
		t.Fatalf("unexpected report: %+v", report)
	}
	key := report.ExpiredPublicKeys[0]
	if key.KeyID != keyID || key.UserID != owner.String() || key.Label != "Old laptop" || key.Fingerprint != "abcd" || key.DaysOverdue != 10 {
		t.Errorf("incorrect key metadata: %+v", key)
	}
	if report.UsersWithoutActiveKey[0].UserID != missing {
		t.Error("missing setup account not reported")
	}
}

func TestRotationReportWrapsLookupFailures(t *testing.T) {
	want := errors.New("database unavailable")
	for _, q := range []*rotationKeyQueries{{passwordErr: want}, {expiredErr: want}, {missingErr: want}} {
		if _, err := NewRotationService(q).CheckExpiredCredentials(context.Background()); !errors.Is(err, want) {
			t.Errorf("error = %v, want wrapped database error", err)
		}
	}
}

func TestRotationRevokesOnlyExpiredKeysAndRecordsActor(t *testing.T) {
	owner, actor := uuid.New(), uuid.New()
	q := &rotationKeyQueries{}
	if err := NewRotationService(q).RevokeExpiredPublicKey(context.Background(), owner.String(), actor); err != nil {
		t.Fatal(err)
	}
	if q.revoked == nil || q.revoked.UserID != owner || q.revoked.RevokedBy != (pgtype.UUID{Bytes: actor, Valid: true}) {
		t.Errorf("incorrect expired-only revocation: %+v", q.revoked)
	}
	q = &rotationKeyQueries{}
	err := NewRotationService(q).RevokeExpiredPublicKey(context.Background(), "invalid", actor)
	requireUserKeyError(t, err, "INVALID_REQUEST")
	if q.revoked != nil {
		t.Error("invalid ID reached revocation")
	}
	q = &rotationKeyQueries{userErr: pgx.ErrNoRows}
	err = NewRotationService(q).RevokeExpiredPublicKey(context.Background(), owner.String(), actor)
	requireUserKeyError(t, err, "USER_NOT_FOUND")
	if q.revoked != nil {
		t.Error("unknown owner reached revocation")
	}
	want := errors.New("database unavailable")
	for _, q := range []*rotationKeyQueries{{userErr: want}, {revokeErr: want}} {
		if err := NewRotationService(q).RevokeExpiredPublicKey(context.Background(), owner.String(), actor); !errors.Is(err, want) {
			t.Errorf("error = %v, want wrapped database error", err)
		}
	}
}
