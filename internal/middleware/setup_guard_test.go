package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func TestSetupGuardCredentialEndpoints(t *testing.T) {
	owner := uuid.New()
	other := uuid.New()
	base := "/users/" + owner.String()
	for _, test := range []struct {
		name   string
		method string
		path   string
		allow  bool
	}{
		{"own key history during first login", http.MethodGet, base + "/public-keys", true},
		{"own key history trailing slash", http.MethodGet, base + "/public-keys/", true},
		{"legacy own key lookup", http.MethodGet, base + "/public-key", true},
		{"own key registration", http.MethodPut, base + "/public-key", true},
		{"own password change", http.MethodPatch, base + "/password", true},
		{"logout", http.MethodPost, "/auth/logout", true},
		{"another user's history even for admin", http.MethodGet, "/users/" + other.String() + "/public-keys", false},
		{"another user's registration", http.MethodPut, "/users/" + other.String() + "/public-key", false},
		{"wrong method", http.MethodPost, base + "/public-keys", false},
		{"individual revocation", http.MethodDelete, base + "/public-keys/" + uuid.NewString(), false},
		{"revoke all", http.MethodPost, base + "/public-keys/revoke-all", false},
		{"nested key path", http.MethodGet, base + "/nested/public-keys", false},
		{"malformed user ID", http.MethodGet, "/users/invalid/public-keys", false},
		{"unrelated resource", http.MethodGet, "/builds", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			// SetupGuard runs before Chi has matched nested user-route parameters.
			// Repeat with parameters present to cover both middleware placements.
			for _, withParams := range []bool{false, true} {
				r := httptest.NewRequest(test.method, test.path, nil)
				ctx := SetAuthContext(r.Context(), owner, "setup@example.test", []string{"ADMIN"}, "token", true, []string{"password_change", "public_key_registration"})
				if withParams {
					routeContext := chi.NewRouteContext()
					routeContext.URLParams.Add("id", owner.String())
					ctx = context.WithValue(ctx, chi.RouteCtxKey, routeContext)
				}
				r = r.WithContext(ctx)
				w := httptest.NewRecorder()
				SetupGuard()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusNoContent)
				})).ServeHTTP(w, r)
				want := http.StatusForbidden
				if test.allow {
					want = http.StatusNoContent
				}
				if w.Code != want {
					t.Fatalf("withParams=%t: status=%d, want=%d; %s", withParams, w.Code, want, w.Body.String())
				}
			}
		})
	}
}
