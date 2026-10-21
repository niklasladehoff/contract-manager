package service

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/crypto/bcrypt"

	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
)

type loginKeyQueries struct {
	repository.Querier
	user repository.GetUserByEmailRow
}

func (q *loginKeyQueries) GetUserByEmail(context.Context, string) (repository.GetUserByEmailRow, error) {
	return q.user, nil
}

func (q *loginKeyQueries) GetRolesByUserID(context.Context, uuid.UUID) ([]repository.UserRole, error) {
	return []repository.UserRole{{Role: "VIEWER"}}, nil
}

func (q *loginKeyQueries) CreateAPIToken(context.Context, repository.CreateAPITokenParams) (repository.CreateAPITokenRow, error) {
	return repository.CreateAPITokenRow{}, nil
}

func TestLoginMultipleKeyState(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name           string
		active, total  int64
		passwordChange bool
	}{
		{name: "no key ever"},
		{name: "expired or revoked keys only", total: 2},
		{name: "one active key", active: 1, total: 1},
		{name: "multiple keys with inactive history", active: 2, total: 4},
		{name: "password setup with active key", active: 1, total: 1, passwordChange: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			q := &loginKeyQueries{user: repository.GetUserByEmailRow{
				ID: uuid.New(), Email: "login@example.test", PasswordHash: string(hash), IsActive: true,
				ActiveKeyCount: tt.active, TotalKeyCount: tt.total, MustChangePassword: tt.passwordChange,
			}}
			if tt.active > 0 {
				fp := "latest-active-fingerprint"
				q.user.PublicKeyFingerprint = &fp
				q.user.PublicKeyExpiresAt = pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}
			}
			result, err := NewAuthService(q, bcrypt.MinCost, time.Hour).Login(context.Background(), q.user.Email, "password")
			if err != nil {
				t.Fatal(err)
			}
			if result.User.ActiveKeyCount != tt.active || result.User.HasPublicKey != (tt.active > 0) {
				t.Errorf("incorrect active key state: %+v", result.User)
			}
			if result.User.PublicKeyExpired != (tt.active == 0 && tt.total > 0) {
				t.Errorf("incorrect legacy renewal flag: %+v", result.User)
			}
			if result.RequiresSetup != (tt.active == 0 || tt.passwordChange) ||
				slices.Contains(result.SetupPending, "public_key_registration") != (tt.active == 0) ||
				slices.Contains(result.SetupPending, "password_change") != tt.passwordChange {
				t.Errorf("incorrect setup state: %+v", result)
			}
			if tt.active > 0 {
				if result.User.PublicKeyFingerprint == nil || *result.User.PublicKeyFingerprint != *q.user.PublicKeyFingerprint ||
					result.User.PublicKeyExpiresAt == nil || !result.User.PublicKeyExpiresAt.Equal(q.user.PublicKeyExpiresAt.Time) {
					t.Error("missing latest active key metadata")
				}
			} else if result.User.PublicKeyFingerprint != nil || result.User.PublicKeyExpiresAt != nil {
				t.Error("inactive history leaked into active key metadata")
			}
		})
	}
}
