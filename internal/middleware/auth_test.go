package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
)

type authSetupQueries struct {
	repository.Querier
	user repository.GetUserByIDRow
}

func (q *authSetupQueries) GetAPITokenByHash(context.Context, string) (repository.ApiToken, error) {
	return repository.ApiToken{ID: uuid.New(), UserID: q.user.ID, CreatedAt: time.Now()}, nil
}

func (q *authSetupQueries) GetUserByID(context.Context, uuid.UUID) (repository.GetUserByIDRow, error) {
	return q.user, nil
}

func (q *authSetupQueries) GetRolesByUserID(context.Context, uuid.UUID) ([]repository.UserRole, error) {
	return []repository.UserRole{}, nil
}

func (q *authSetupQueries) UpdateTokenLastUsed(context.Context, uuid.UUID) error {
	return nil
}

func TestAuthSetupUsesActiveKeyCount(t *testing.T) {
	legacyKey := "legacy public key"
	tests := []struct {
		name               string
		activeKeys         int64
		legacyKey          *string
		mustChangePassword bool
	}{
		{name: "active key without legacy key", activeKeys: 1},
		{name: "multiple active keys", activeKeys: 2},
		{name: "no active key"},
		{name: "legacy key cannot satisfy setup", legacyKey: &legacyKey},
		{name: "password setup remains required", activeKeys: 1, mustChangePassword: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			queries := &authSetupQueries{user: repository.GetUserByIDRow{
				ID: uuid.New(), Email: "test@example.test", IsActive: true,
				ActiveKeyCount: tt.activeKeys, PublicKey: tt.legacyKey,
				PublicKeyExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true},
				MustChangePassword: tt.mustChangePassword,
			}}
			handler := Auth(queries, time.Hour)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				pending := GetSetupPending(r.Context())
				if slices.Contains(pending, "public_key_registration") != (tt.activeKeys == 0) {
					t.Errorf("wrong key setup state: %v", pending)
				}
				if slices.Contains(pending, "password_change") != tt.mustChangePassword {
					t.Errorf("wrong password setup state: %v", pending)
				}
				if IsSetupRequired(r.Context()) != (tt.activeKeys == 0 || tt.mustChangePassword) {
					t.Errorf("wrong overall setup state: %v", pending)
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			r := httptest.NewRequest(http.MethodGet, "/builds", nil)
			r.Header.Set("Authorization", "Bearer test-token")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != http.StatusNoContent {
				t.Fatalf("status = %d; body: %s", w.Code, w.Body.String())
			}
		})
	}
}
