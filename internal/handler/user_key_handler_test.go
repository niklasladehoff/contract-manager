package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/ibm-hyper-protect/contract-manager/internal/model"
	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
	"github.com/ibm-hyper-protect/contract-manager/internal/service"
)

type listKeysQueries struct {
	repository.Querier
	getUser  func(context.Context, uuid.UUID) (repository.GetUserByIDRow, error)
	listKeys func(context.Context, uuid.UUID) ([]repository.UserPublicKey, error)
}

func (q *listKeysQueries) GetUserByID(ctx context.Context, id uuid.UUID) (repository.GetUserByIDRow, error) {
	return q.getUser(ctx, id)
}

func (q *listKeysQueries) ListUserPublicKeys(ctx context.Context, id uuid.UUID) ([]repository.UserPublicKey, error) {
	return q.listKeys(ctx, id)
}

func TestUserKeyHandlerListKeys(t *testing.T) {
	userID := uuid.New()
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	keys := []repository.UserPublicKey{
		{
			ID: uuid.New(), UserID: userID, Label: "Laptop", PublicKey: "public-key-laptop", Fingerprint: "abcd",
			RegisteredAt: now, ExpiresAt: now.Add(90 * 24 * time.Hour),
			LastUsedAt: pgtype.Timestamptz{Time: now, Valid: true},
		},
		{
			ID: uuid.New(), UserID: userID, Label: "Lost device", PublicKey: "public-key-lost", Fingerprint: "ef01",
			RegisteredAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
			RevokedAt: pgtype.Timestamptz{Time: now, Valid: true},
			RevokedBy: pgtype.UUID{Bytes: userID, Valid: true},
		},
		{
			ID: uuid.New(), UserID: userID, Label: "Expired device", PublicKey: "public-key-expired", Fingerprint: "2345",
			RegisteredAt: now.Add(-91 * 24 * time.Hour), ExpiresAt: now.Add(-24 * time.Hour),
		},
	}
	internalErr := errors.New("database password=secret unavailable")
	tests := []struct {
		name          string
		invalidID     bool
		keys          []repository.UserPublicKey
		userErr       error
		listErr       error
		wantStatus    int
		wantCode      string
		wantMessage   string
		wantUserCalls int
		wantListCalls int
	}{
		{
			name: "returns complete key history", keys: keys,
			wantStatus: http.StatusOK, wantUserCalls: 1, wantListCalls: 1,
		},
		{
			name: "no keys returns empty array", keys: []repository.UserPublicKey{},
			wantStatus: http.StatusOK, wantUserCalls: 1, wantListCalls: 1,
		},
		{
			name: "invalid UUID never queries repository", invalidID: true,
			wantStatus: http.StatusBadRequest, wantCode: "INVALID_REQUEST", wantMessage: "Invalid user ID.",
		},
		{
			name: "unknown user", userErr: pgx.ErrNoRows,
			wantStatus: http.StatusNotFound, wantCode: "USER_NOT_FOUND", wantUserCalls: 1,
		},
		{
			name:       "wrapped application error retains status and message",
			userErr:    fmt.Errorf("repository: %w", model.ErrUserNotFound(userID.String())),
			wantStatus: http.StatusNotFound, wantCode: "USER_NOT_FOUND",
			wantMessage: model.ErrUserNotFound(userID.String()).Message, wantUserCalls: 1,
		},
		{
			name: "user lookup failure hides internal details", userErr: internalErr,
			wantStatus: http.StatusInternalServerError, wantCode: "INTERNAL_ERROR",
			wantMessage: "Failed to list public keys.", wantUserCalls: 1,
		},
		{
			name: "key lookup failure hides internal details", listErr: internalErr,
			wantStatus: http.StatusInternalServerError, wantCode: "INTERNAL_ERROR",
			wantMessage: "Failed to list public keys.", wantUserCalls: 1, wantListCalls: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userCalls, listCalls := 0, 0
			// A request marker checks that the handler forwards the request context.
			type contextKey struct{}
			checkRequest := func(ctx context.Context, id uuid.UUID) {
				t.Helper()
				if id != userID {
					t.Fatalf("repository user ID = %s, want %s", id, userID)
				}
				if ctx.Value(contextKey{}) != "request" {
					t.Fatal("request context was not forwarded")
				}
			}
			queries := &listKeysQueries{
				getUser: func(ctx context.Context, id uuid.UUID) (repository.GetUserByIDRow, error) {
					userCalls++
					checkRequest(ctx, id)
					return repository.GetUserByIDRow{ID: id}, tt.userErr
				},
				listKeys: func(ctx context.Context, id uuid.UUID) ([]repository.UserPublicKey, error) {
					listCalls++
					checkRequest(ctx, id)
					return tt.keys, tt.listErr
				},
			}
			h := NewUserKeyHandler(service.NewUserKeyService(nil, queries), nil)
			idParam := userID.String()
			if tt.invalidID {
				idParam = "invalid-uuid"
			}
			r := httptest.NewRequest(http.MethodGet, "/users/"+idParam+"/public-keys", nil)
			routeCtx := chi.NewRouteContext()
			routeCtx.URLParams.Add("id", idParam)
			ctx := context.WithValue(r.Context(), chi.RouteCtxKey, routeCtx)
			ctx = context.WithValue(ctx, contextKey{}, "request")
			w := httptest.NewRecorder()
			h.ListKeys(w, r.WithContext(ctx))

			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", w.Code, tt.wantStatus, w.Body.String())
			}
			if got := w.Header().Get("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", got)
			}
			if userCalls != tt.wantUserCalls || listCalls != tt.wantListCalls {
				t.Errorf("repository calls = (%d, %d), want (%d, %d)", userCalls, listCalls, tt.wantUserCalls, tt.wantListCalls)
			}
			if tt.wantStatus == http.StatusOK {
				var body struct {
					Keys []repository.UserPublicKey `json:"keys"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(body.Keys, tt.keys) {
					t.Errorf("response keys = %#v, want %#v", body.Keys, tt.keys)
				}
				return
			}
			var body struct {
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
					Details any    `json:"details"`
				} `json:"error"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body.Error.Code != tt.wantCode {
				t.Errorf("error code = %q, want %q", body.Error.Code, tt.wantCode)
			}
			if tt.wantMessage != "" && body.Error.Message != tt.wantMessage {
				t.Errorf("error message = %q, want %q", body.Error.Message, tt.wantMessage)
			}
			if body.Error.Details != nil {
				t.Errorf("unexpected error details: %v", body.Error.Details)
			}
		})
	}
}
