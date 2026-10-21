package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ibm-hyper-protect/contract-manager/internal/model"
	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
	"github.com/ibm-hyper-protect/contract-manager/internal/service"
)

type latestActiveKeyQueries struct {
	repository.Querier
	getUser    func(context.Context, uuid.UUID) (repository.GetUserByIDRow, error)
	activeKeys func(context.Context, uuid.UUID) ([]repository.UserPublicKey, error)
}

func (q *latestActiveKeyQueries) GetUserByID(ctx context.Context, id uuid.UUID) (repository.GetUserByIDRow, error) {
	return q.getUser(ctx, id)
}

func (q *latestActiveKeyQueries) ListActiveUserPublicKeys(ctx context.Context, id uuid.UUID) ([]repository.UserPublicKey, error) {
	return q.activeKeys(ctx, id)
}

func TestUserHandlerGetPublicKey(t *testing.T) {
	userID := uuid.New()
	registeredAt := time.Date(2026, 10, 20, 12, 0, 0, 123456789, time.UTC)
	latest := repository.UserPublicKey{
		ID: uuid.New(), UserID: userID, PublicKey: "latest-public-key", Fingerprint: "abcd",
		RegisteredAt: registeredAt, ExpiresAt: registeredAt.Add(90 * 24 * time.Hour),
	}
	older := repository.UserPublicKey{
		ID: uuid.New(), UserID: userID, PublicKey: "older-public-key", Fingerprint: "ef01",
		RegisteredAt: registeredAt.Add(-time.Hour), ExpiresAt: latest.ExpiresAt.Add(-time.Hour),
	}
	internalErr := errors.New("database password=secret unavailable")
	tests := []struct {
		name          string
		invalidID     bool
		keys          []repository.UserPublicKey
		userErr       error
		keysErr       error
		wantStatus    int
		wantCode      string
		wantMessage   string
		wantUserCalls int
		wantKeysCalls int
	}{
		{
			name: "success returns latest active key", keys: []repository.UserPublicKey{latest, older},
			wantStatus: http.StatusOK, wantUserCalls: 1, wantKeysCalls: 1,
		},
		{
			name:       "no active key returns only an error",
			wantStatus: http.StatusBadRequest, wantCode: "INVALID_REQUEST", wantMessage: "User has no active public key.",
			wantUserCalls: 1, wantKeysCalls: 1,
		},
		{
			name: "unknown user", userErr: pgx.ErrNoRows,
			wantStatus: http.StatusNotFound, wantCode: "USER_NOT_FOUND", wantMessage: model.ErrUserNotFound(userID.String()).Message,
			wantUserCalls: 1,
		},
		{
			name: "wrapped application error preserves status", userErr: fmt.Errorf("repository: %w", model.ErrUserNotFound(userID.String())),
			wantStatus: http.StatusNotFound, wantCode: "USER_NOT_FOUND", wantMessage: model.ErrUserNotFound(userID.String()).Message,
			wantUserCalls: 1,
		},
		{
			name: "user lookup failure hides internal details", userErr: internalErr,
			wantStatus: http.StatusInternalServerError, wantCode: "INTERNAL_ERROR", wantMessage: "Failed to retrieve public key.",
			wantUserCalls: 1,
		},
		{
			name: "active key lookup failure hides internal details", keysErr: internalErr,
			wantStatus: http.StatusInternalServerError, wantCode: "INTERNAL_ERROR", wantMessage: "Failed to retrieve public key.",
			wantUserCalls: 1, wantKeysCalls: 1,
		},
		{
			name: "invalid UUID never queries repository", invalidID: true,
			wantStatus: http.StatusBadRequest, wantCode: "INVALID_REQUEST", wantMessage: "Invalid user ID.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userCalls, keysCalls := 0, 0
			queries := &latestActiveKeyQueries{
				getUser: func(_ context.Context, id uuid.UUID) (repository.GetUserByIDRow, error) {
					userCalls++
					if id != userID {
						t.Fatalf("user ID = %s, want %s", id, userID)
					}
					return repository.GetUserByIDRow{ID: id}, tt.userErr
				},
				activeKeys: func(_ context.Context, id uuid.UUID) ([]repository.UserPublicKey, error) {
					keysCalls++
					if id != userID {
						t.Fatalf("key owner ID = %s, want %s", id, userID)
					}
					return tt.keys, tt.keysErr
				},
			}
			h := NewUserHandler(nil, service.NewUserKeyService(nil, queries), nil)
			router := chi.NewRouter()
			router.Get("/users/{id}/public-key", h.GetPublicKey)
			idParam := userID.String()
			if tt.invalidID {
				idParam = "invalid-uuid"
			}
			r := httptest.NewRequest(http.MethodGet, "/users/"+idParam+"/public-key", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d; body: %s", w.Code, tt.wantStatus, w.Body.String())
			}
			if got := w.Header().Get("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", got)
			}
			if userCalls != tt.wantUserCalls || keysCalls != tt.wantKeysCalls {
				t.Errorf("repository calls = (%d, %d), want (%d, %d)", userCalls, keysCalls, tt.wantUserCalls, tt.wantKeysCalls)
			}
			var body struct {
				PublicKey   string `json:"public_key"`
				Fingerprint string `json:"fingerprint"`
				CreatedAt   string `json:"created_at"`
				ExpiresAt   string `json:"expires_at"`
				Error       *struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			// Unmarshal rejects concatenated error and success responses.
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("expected one JSON response: %v; body: %s", err, w.Body.String())
			}
			if tt.wantStatus == http.StatusOK {
				if body.Error != nil {
					t.Fatalf("unexpected error: %+v", body.Error)
				}
				if body.PublicKey != latest.PublicKey || body.Fingerprint != latest.Fingerprint {
					t.Errorf("wrong key: public_key = %q, fingerprint = %q", body.PublicKey, body.Fingerprint)
				}
				if body.CreatedAt != latest.RegisteredAt.Format(time.RFC3339) || body.ExpiresAt != latest.ExpiresAt.Format(time.RFC3339) {
					t.Errorf("unexpected dates: created_at = %q, expires_at = %q", body.CreatedAt, body.ExpiresAt)
				}
				return
			}
			if body.Error == nil {
				t.Fatal("missing error response")
			}
			if body.Error.Code != tt.wantCode || body.Error.Message != tt.wantMessage {
				t.Errorf("error = %+v, want %s: %s", body.Error, tt.wantCode, tt.wantMessage)
			}
			if body.PublicKey != "" || body.Fingerprint != "" || body.CreatedAt != "" || body.ExpiresAt != "" {
				t.Error("error response includes key data")
			}
		})
	}
}
