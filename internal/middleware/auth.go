package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
	"github.com/ibm-hyper-protect/contract-manager/internal/service"
)

// Auth returns middleware that validates Bearer token authentication.
// It extracts the token from the Authorization header, validates it against the DB,
// and populates the request context with user info.
func Auth(queries repository.Querier, tokenExpiry time.Duration) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract Bearer token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				emitSystemLog(
					r.Context(),
					"unknown",
					"AUTH_REQUEST_DENIED",
					"Authentication Middleware",
					requestIP(r),
					"FAILED",
					"Missing Authorization header",
				)
				writeUnauthorized(w)
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
				emitSystemLog(
					r.Context(),
					"unknown",
					"AUTH_REQUEST_DENIED",
					"Authentication Middleware",
					requestIP(r),
					"FAILED",
					"Invalid Authorization header format",
				)
				writeUnauthorized(w)
				return
			}
			rawToken := parts[1]

			// Hash the token and look it up
			tokenHash := service.HashToken(rawToken)
			token, err := queries.GetAPITokenByHash(r.Context(), tokenHash)
			if err != nil {
				emitSystemLog(
					r.Context(),
					"unknown",
					"AUTH_REQUEST_DENIED",
					"Authentication Middleware",
					requestIP(r),
					"FAILED",
					"Token lookup failed",
				)
				writeUnauthorized(w)
				return
			}

			// Check if token is revoked
			if token.RevokedAt.Valid {
				emitSystemLog(
					r.Context(),
					"unknown",
					"AUTH_REQUEST_DENIED",
					"Authentication Middleware",
					requestIP(r),
					"FAILED",
					"Token revoked",
				)
				writeUnauthorized(w)
				return
			}
			// Check if token is expired
			if tokenExpiry > 0 && time.Now().After(token.CreatedAt.Add(tokenExpiry)) {
				emitSystemLog(
					r.Context(),
					"unknown",
					"AUTH_REQUEST_DENIED",
					"Authentication Middleware",
					requestIP(r),
					"FAILED",
					"Token expired",
				)
				writeUnauthorized(w)
				return
			}

			// Load user
			user, err := queries.GetUserByID(r.Context(), token.UserID)
			if err != nil {
				emitSystemLog(
					r.Context(),
					"unknown",
					"AUTH_REQUEST_DENIED",
					"Authentication Middleware",
					requestIP(r),
					"FAILED",
					"User lookup failed for token",
				)
				writeUnauthorized(w)
				return
			}

			// Check if user is active
			if !user.IsActive {
				emitSystemLog(
					r.Context(),
					user.Email,
					"AUTH_REQUEST_DENIED",
					"Authentication Middleware",
					requestIP(r),
					"FAILED",
					"Inactive user",
				)
				writeUnauthorized(w)
				return
			}

			// Load user roles
			roles, err := queries.GetRolesByUserID(r.Context(), user.ID)
			if err != nil {
				slog.Error("failed to load user roles", "error", err, "user_id", user.ID)
				emitSystemLog(
					r.Context(),
					user.Email,
					"AUTH_REQUEST_DENIED",
					"Authentication Middleware",
					requestIP(r),
					"FAILED",
					"Failed to load user roles",
				)
				writeUnauthorized(w)
				return
			}

			roleStrings := make([]string, len(roles))
			for i, role := range roles {
				roleStrings[i] = role.Role
			}

			setupPending := make([]string, 0, 2)
			if user.MustChangePassword {
				setupPending = append(setupPending, "password_change")
			}
			if user.ActiveKeyCount == 0 {
				setupPending = append(setupPending, "public_key_registration")
			}
			setupRequired := len(setupPending) > 0

			// Update last_used_at (fire-and-forget, don't block the request).
			// Use a detached timeout context so request cancellation does not skip telemetry updates.
			tokenID := token.ID
			go func() {
				bgCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := queries.UpdateTokenLastUsed(bgCtx, tokenID); err != nil {
					slog.Debug("failed to update token last_used_at", "error", err, "token_id", tokenID)
				}
			}()

			// Set auth context and continue
			ctx := SetAuthContext(r.Context(), user.ID, user.Email, roleStrings, tokenHash, setupRequired, setupPending)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(`{"error":{"code":"UNAUTHORIZED","message":"Missing or invalid bearer token."}}`))
}
