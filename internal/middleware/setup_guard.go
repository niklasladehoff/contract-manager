package middleware

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// SetupGuard restricts users with incomplete setup to setup-only endpoints.
func SetupGuard() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !IsSetupRequired(r.Context()) {
				next.ServeHTTP(w, r)
				return
			}

			if isAllowedSetupEndpoint(r) {
				next.ServeHTTP(w, r)
				return
			}

			pending := GetSetupPending(r.Context())
			if len(pending) == 0 {
				pending = []string{"password_change", "public_key_registration"}
			}
			emitSystemLog(
				r.Context(),
				actorEmailFromContext(r, "unknown"),
				"ACCOUNT_SETUP_BLOCKED",
				"Setup Guard",
				requestIP(r),
				"FAILED",
				"Blocked endpoint until setup completion",
			)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			writeSetupRequired(w, pending)
		})
	}
}

func isAllowedSetupEndpoint(r *http.Request) bool {
	path := strings.TrimSuffix(r.URL.Path, "/")

	// Allow logout while setup is pending.
	if r.Method == http.MethodPost && path == "/auth/logout" {
		return true
	}

	// Allow own credential setup and key history while setup is pending.
	userID, ok := GetUserID(r.Context())
	if !ok {
		return false
	}

	pathUserID := chi.URLParam(r, "id")
	if pathUserID == "" {
		pathUserID = extractUserIDFromPath(r.URL.Path)
	}

	parsedPathUserID, err := uuid.Parse(pathUserID)
	if err != nil || parsedPathUserID != userID {
		return false
	}

	switch path {
	case "/users/" + pathUserID + "/password":
		return r.Method == http.MethodPatch
	case "/users/" + pathUserID + "/public-key":
		return r.Method == http.MethodGet || r.Method == http.MethodPut
	case "/users/" + pathUserID + "/public-keys":
		return r.Method == http.MethodGet
	}

	return false
}

func extractUserIDFromPath(path string) string {
	// Expected setup paths:
	// /users/{id}/password
	// /users/{id}/public-key
	// /users/{id}/public-keys
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) != 3 {
		return ""
	}
	if parts[0] != "users" {
		return ""
	}
	if parts[2] != "password" && parts[2] != "public-key" && parts[2] != "public-keys" {
		return ""
	}
	return parts[1]
}

func writeSetupRequired(w http.ResponseWriter, pending []string) {
	payload := struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			Details struct {
				SetupPending []string `json:"setup_pending"`
			} `json:"details"`
		} `json:"error"`
	}{}
	payload.Error.Code = "ACCOUNT_SETUP_REQUIRED"
	payload.Error.Message = "Account setup incomplete. Complete required setup steps."
	payload.Error.Details.SetupPending = pending

	// Best effort JSON response.
	data, _ := json.Marshal(payload)
	w.Write(data)
}
