package handler

import (
	"bytes"
	"context"
	stdcrypto "crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/ibm-hyper-protect/contract-manager/internal/crypto"
	"github.com/ibm-hyper-protect/contract-manager/internal/middleware"
	"github.com/ibm-hyper-protect/contract-manager/internal/model"
	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
	"github.com/ibm-hyper-protect/contract-manager/internal/service"
)

// TestUserKeysHTTP uses a migrated disposable database. Authentication, request
// signing, authorization, handlers and services all run without mocks.
func TestUserKeysHTTP(t *testing.T) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	q := repository.New(pool)
	password := "integration-password"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	var userIDs []uuid.UUID
	var buildID uuid.UUID
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if buildID != uuid.Nil {
			if _, err := pool.Exec(cleanupCtx, "DELETE FROM builds WHERE id = $1", buildID); err != nil {
				t.Error(err)
			}
		}
		if _, err := pool.Exec(cleanupCtx, "DELETE FROM users WHERE id = ANY($1::uuid[])", userIDs); err != nil {
			t.Error(err)
		}
	})
	createUser := func(role string) uuid.UUID {
		t.Helper()
		user, err := q.CreateUser(ctx, repository.CreateUserParams{Name: "HTTP key test", Email: uuid.NewString() + "@example.test", PasswordHash: string(hash)})
		if err != nil {
			t.Fatal(err)
		}
		userIDs = append(userIDs, user.ID)
		if err := q.UpdatePassword(ctx, repository.UpdatePasswordParams{ID: user.ID, PasswordHash: string(hash)}); err != nil {
			t.Fatal(err)
		}
		if _, err := q.AssignRole(ctx, repository.AssignRoleParams{UserID: user.ID, Role: role, AssignedBy: user.ID}); err != nil {
			t.Fatal(err)
		}
		return user.ID
	}
	owner, admin, other := createUser("ENV_OPERATOR"), createUser("ADMIN"), createUser("VIEWER")
	keys := service.NewUserKeyService(pool, q)
	findKey := func(userID, keyID uuid.UUID) repository.UserPublicKey {
		t.Helper()
		all, err := keys.ListKeys(ctx, userID)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range all {
			if key.ID == keyID {
				return key
			}
		}
		t.Fatalf("key %s not found", keyID)
		return repository.UserPublicKey{}
	}
	users := service.NewUserService(q, bcrypt.MinCost)
	// Match the server's default token lifetime, including for databases in a VM.
	const tokenLifetime = 24 * time.Hour
	auth := service.NewAuthService(q, bcrypt.MinCost, tokenLifetime)
	logs := service.NewSystemLogService(q)
	h := NewUserHandler(users, keys, logs)
	kh := NewUserKeyHandler(keys, logs)
	rh := NewRotationHandler(service.NewRotationService(q), logs)
	ah := NewAuthHandler(auth, logs)
	audit := service.NewAuditService(q)
	export := NewExportHandler(service.NewExportService(q, audit, service.NewAssignmentService(q, audit)), service.NewVerificationService(q), logs)
	build, err := q.CreateBuild(ctx, repository.CreateBuildParams{Name: "Key audit test", CreatedBy: owner})
	if err != nil {
		t.Fatal(err)
	}
	buildID = build.ID
	role, err := q.GetRoleByName(ctx, "ENV_OPERATOR")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateBuildAssignment(ctx, repository.CreateBuildAssignmentParams{BuildID: buildID, RoleID: role.ID, UserID: owner, AssignedBy: admin}); err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Post("/auth/login", ah.Login)
	router.Group(func(r chi.Router) {
		r.Use(middleware.Auth(q, tokenLifetime), middleware.SetupGuard(), middleware.RequireRequestSignature(keys))
		r.With(middleware.RequireRole("ADMIN")).Get("/users", h.ListUsers)
		r.Route("/users/{id}", func(r chi.Router) {
			r.With(middleware.RequireRole("ADMIN")).Post("/public-keys/revoke-all", kh.RevokeAllKeys)
			r.Group(func(r chi.Router) {
				r.Use(middleware.RequireOwnerOrAdmin("id"))
				r.With(middleware.StrictRateLimit()).Put("/public-key", h.RegisterPublicKey)
				r.Get("/public-key", h.GetPublicKey)
				r.Get("/public-keys", kh.ListKeys)
				r.Delete("/public-keys/{key_id}", kh.RevokeKey)
			})
		})
		r.With(middleware.RequireRole("ADMIN")).Get("/rotation/expired", rh.GetExpiredCredentials)
		r.With(middleware.RequireRole("ADMIN")).Post("/rotation/revoke-key/{user_id}", rh.RevokeExpiredPublicKey)
		r.With(middleware.RequireBuildAccess(q, "id")).Post("/builds/{id}/acknowledge-download", export.AcknowledgeDownload)
		r.Post("/test-audit", func(w http.ResponseWriter, r *http.Request) {
			actorID, _ := middleware.GetUserID(r.Context())
			sig := middleware.GetRequestSignature(r.Context())
			event, err := audit.LogEvent(r.Context(), service.LogEventInput{
				BuildID: buildID, EventType: model.EventBuildCreated, ActorUserID: actorID, Signature: &sig,
				EventData: map[string]any{"request_signature_hash": middleware.GetRequestSignatureHash(r.Context())},
			})
			if err != nil {
				writeError(w, model.ErrInternal(err.Error()))
				return
			}
			writeJSON(w, http.StatusOK, event)
		})
	})
	requests := 0
	request := func(method, path, token string, body any, signer *rsa.PrivateKey, fingerprint string, want int, code string) []byte {
		t.Helper()
		var data []byte
		if body != nil {
			data, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
		}
		r := httptest.NewRequest(method, path, bytes.NewReader(data))
		requests++
		// Separate client IPs keep the actual strict limiter from hiding assertions.
		r.RemoteAddr = fmt.Sprintf("192.0.2.%d:1234", requests)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		if signer != nil {
			ts := time.Now().UnixMilli()
			bodyJSON := "null"
			if len(data) > 0 {
				bodyJSON = string(data)
			}
			payload := fmt.Sprintf(`{"method":%q,"path":%q,"data":%s,"timestamp":%d}`, method, path, bodyJSON, ts)
			hashHex := crypto.SHA256HexString(payload)
			digest := sha256.Sum256([]byte(hashHex))
			sig, err := rsa.SignPSS(rand.Reader, signer, stdcrypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
			if err != nil {
				t.Fatal(err)
			}
			r.Header.Set("X-Signature", base64.StdEncoding.EncodeToString(sig))
			r.Header.Set("X-Signature-Hash", hashHex)
			r.Header.Set("X-Timestamp", strconv.FormatInt(ts, 10))
			if fingerprint != "" {
				r.Header.Set("X-Key-Fingerprint", fingerprint)
			}
		}
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s %s: status %d, want %d; %s", method, path, w.Code, want, w.Body.String())
		}
		if want == http.StatusNoContent {
			if w.Body.Len() != 0 {
				t.Fatal("204 response has a body")
			}
			return nil
		}
		if !json.Valid(w.Body.Bytes()) {
			t.Fatalf("invalid JSON: %s", w.Body.String())
		}
		if code != "" {
			var result struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.Error.Code != code {
				t.Fatalf("error=%s, want %s; %s", result.Error.Code, code, w.Body.String())
			}
		}
		return w.Body.Bytes()
	}
	login := func(id uuid.UUID) service.LoginResult {
		t.Helper()
		user, err := q.GetUserByID(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		data := request("POST", "/auth/login", "", map[string]string{"email": user.Email, "password": password}, nil, "", 200, "")
		var result service.LoginResult
		if err := json.Unmarshal(data, &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	newKey := func() (*rsa.PrivateKey, string) {
		t.Helper()
		key, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			t.Fatal(err)
		}
		der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		return key, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	}
	keyA, pemA := newKey()
	keyB, pemB := newKey()
	adminKey, adminPEM := newKey()
	path := "/users/" + owner.String()
	ownerLogin := login(owner)
	if !ownerLogin.RequiresSetup || ownerLogin.User.ActiveKeyCount != 0 {
		t.Fatal("new account should require key setup")
	}
	ownerToken := ownerLogin.Token
	request("GET", path+"/public-keys", ownerToken, nil, nil, "", 200, "")
	request("GET", path+"/public-key", ownerToken, nil, nil, "", 400, "INVALID_REQUEST")
	request("GET", "/users", ownerToken, nil, nil, "", 403, "ACCOUNT_SETUP_REQUIRED")
	request("PUT", path+"/public-key", ownerToken, map[string]string{"public_key": pemA, "label": "Laptop"}, nil, "", 200, "")
	active, _ := keys.ListKeys(ctx, owner)
	if len(active) != 1 {
		t.Fatalf("expected first key, got %+v", active)
	}
	first := active[0]
	ownerLogin = login(owner)
	if ownerLogin.RequiresSetup || ownerLogin.User.ActiveKeyCount != 1 || *ownerLogin.User.PublicKeyFingerprint != first.Fingerprint {
		t.Fatal("first key did not finish setup")
	}
	request("PUT", path+"/public-key", ownerToken, map[string]string{"public_key": pemB, "password": password}, nil, "", 400, "INVALID_SIGNATURE_HEADERS")
	request("PUT", path+"/public-key", ownerToken, map[string]string{"public_key": pemB, "password": "wrong"}, keyA, first.Fingerprint, 403, "PASSWORD_CONFIRMATION_FAILED")
	request("PUT", path+"/public-key", ownerToken, map[string]string{"public_key": pemA, "password": password}, keyA, first.Fingerprint, 409, "KEY_ALREADY_REGISTERED")
	response := request("PUT", path+"/public-key", ownerToken, map[string]string{"public_key": pemB, "label": "Desktop", "password": password}, keyA, first.Fingerprint, 200, "")
	var registered struct {
		KeyID         uuid.UUID `json:"key_id"`
		Label         string    `json:"label"`
		RequiresSetup bool      `json:"requires_setup"`
	}
	if err := json.Unmarshal(response, &registered); err != nil {
		t.Fatal(err)
	}
	if registered.KeyID == uuid.Nil || registered.Label != "Desktop" || registered.RequiresSetup {
		t.Fatalf("incorrect registration response: %s", response)
	}
	second := findKey(owner, registered.KeyID)
	ownerLogin = login(owner)
	if ownerLogin.User.ActiveKeyCount != 2 || *ownerLogin.User.PublicKeyFingerprint != second.Fingerprint {
		t.Fatal("login must expose newest active key and count")
	}
	data := request("GET", path+"/public-key", ownerToken, nil, nil, "", 200, "")
	var compat map[string]string
	if err := json.Unmarshal(data, &compat); err != nil {
		t.Fatal(err)
	}
	if compat["fingerprint"] != second.Fingerprint {
		t.Fatal("compatibility endpoint selected wrong key")
	}
	request("GET", path+"/public-keys", "", nil, nil, "", 401, "UNAUTHORIZED")
	otherToken := login(other).Token
	// Give the other account a completed setup state without reusing a fingerprint.
	otherKey, otherPEM := newKey()
	request("PUT", "/users/"+other.String()+"/public-key", otherToken, map[string]string{"public_key": otherPEM}, nil, "", 200, "")
	request("GET", path+"/public-keys", otherToken, nil, nil, "", 403, "FORBIDDEN")
	adminToken := login(admin).Token
	request("PUT", "/users/"+admin.String()+"/public-key", adminToken, map[string]string{"public_key": adminPEM}, nil, "", 200, "")
	adminKeys, err := keys.ListKeys(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	adminFP := adminKeys[0].Fingerprint
	request("PUT", path+"/public-key", adminToken, map[string]string{"public_key": otherPEM, "password": password}, adminKey, adminFP, 403, "FORBIDDEN")
	request("GET", path+"/public-keys", adminToken, nil, nil, "", 200, "")
	request("POST", "/test-audit", ownerToken, map[string]string{"value": "B"}, keyB, second.Fingerprint, 200, "")
	contractHash := crypto.SHA256HexString("test contract")
	contractYAML := "workload: test"
	if err := q.FinalizeBuild(ctx, repository.FinalizeBuildParams{ID: buildID, ContractHash: &contractHash, ContractYaml: &contractYAML}); err != nil {
		t.Fatal(err)
	}
	receipt := func(key *rsa.PrivateKey) string {
		t.Helper()
		digest := sha256.Sum256([]byte(contractHash))
		sig, err := rsa.SignPSS(rand.Reader, key, stdcrypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		if err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(sig)
	}
	ackPath := "/builds/" + buildID.String() + "/acknowledge-download"
	// The receipt and HTTP signature must use the same client key. Key A is
	// deliberately older than the newest key B returned by compatibility APIs.
	request("POST", ackPath, ownerToken, map[string]string{"contract_hash": contractHash, "signature": receipt(keyB)}, keyA, first.Fingerprint, 400, "INVALID_SIGNATURE")
	request("POST", ackPath, ownerToken, map[string]string{"contract_hash": contractHash, "signature": receipt(keyA)}, keyA, first.Fingerprint, 204, "")
	request("POST", "/test-audit", ownerToken, nil, keyA, "", 403, "SIGNATURE_KEY_FINGERPRINT_REQUIRED")
	request("POST", "/test-audit", ownerToken, nil, keyB, first.Fingerprint, 400, "INVALID_SIGNATURE")
	request("POST", "/test-audit", ownerToken, nil, keyA, adminFP, 403, "INVALID_SIGNATURE")
	request("POST", path+"/public-keys/revoke-all", ownerToken, nil, keyA, first.Fingerprint, 403, "FORBIDDEN")
	request("DELETE", path+"/public-keys/"+adminKeys[0].ID.String(), ownerToken, nil, keyA, first.Fingerprint, 404, "KEY_NOT_FOUND")
	request("DELETE", path+"/public-keys/"+second.ID.String(), ownerToken, nil, keyA, first.Fingerprint, 204, "")
	request("DELETE", path+"/public-keys/"+second.ID.String(), ownerToken, nil, keyA, first.Fingerprint, 404, "KEY_NOT_FOUND")
	request("POST", "/test-audit", ownerToken, nil, keyB, second.Fingerprint, 403, "SIGNATURE_KEY_REVOKED")
	// A single active key still supports the permanent header-less fallback.
	request("POST", "/test-audit", ownerToken, nil, keyA, "", 200, "")
	ownerLogin = login(owner)
	if ownerLogin.User.ActiveKeyCount != 1 || *ownerLogin.User.PublicKeyFingerprint != first.Fingerprint {
		t.Fatal("revoked latest key remained visible on login")
	}
	if _, err := pool.Exec(ctx, "UPDATE user_public_keys SET expires_at = NOW() - INTERVAL '1 day' WHERE id = $1", first.ID); err != nil {
		t.Fatal(err)
	}
	ownerLogin = login(owner)
	if !ownerLogin.RequiresSetup || !ownerLogin.User.PublicKeyExpired || ownerLogin.User.PublicKeyFingerprint != nil {
		t.Fatal("all-inactive account must return to setup")
	}
	request("GET", path+"/public-key", adminToken, nil, nil, "", 400, "INVALID_REQUEST")
	request("GET", path+"/public-keys", ownerToken, nil, nil, "", 200, "")
	recoveryKey, recoveryPEM := newKey()
	request("PUT", path+"/public-key", ownerToken, map[string]string{"public_key": recoveryPEM}, nil, "", 403, "PASSWORD_CONFIRMATION_FAILED")
	request("PUT", path+"/public-key", ownerToken, map[string]string{"public_key": recoveryPEM, "password": password}, nil, "", 200, "")
	request("GET", "/rotation/expired", adminToken, nil, nil, "", 200, "")
	request("POST", "/rotation/revoke-key/"+owner.String(), adminToken, nil, adminKey, adminFP, 200, "")
	expired := findKey(owner, first.ID)
	if !expired.RevokedAt.Valid || expired.RevokedBy != (pgtype.UUID{Bytes: admin, Valid: true}) {
		t.Fatal("rotation did not record administrator")
	}
	remaining, err := q.ListActiveUserPublicKeys(ctx, owner)
	if err != nil || len(remaining) != 1 {
		t.Fatalf("rotation revoked an active device: %v %v", remaining, err)
	}
	request("POST", "/test-audit", ownerToken, nil, recoveryKey, remaining[0].Fingerprint, 200, "")
	request("GET", "/users", adminToken, nil, nil, "", 200, "")
	data = request("POST", path+"/public-keys/revoke-all", adminToken, nil, adminKey, adminFP, 200, "")
	var revoked struct {
		Count int64 `json:"revoked_count"`
	}
	if err := json.Unmarshal(data, &revoked); err != nil {
		t.Fatal(err)
	}
	if revoked.Count != 1 {
		t.Fatalf("revoked_count=%d, want 1", revoked.Count)
	}
	data = request("POST", path+"/public-keys/revoke-all", adminToken, nil, adminKey, adminFP, 200, "")
	if err := json.Unmarshal(data, &revoked); err != nil {
		t.Fatal(err)
	}
	if revoked.Count != 0 {
		t.Fatalf("second revoke-all count=%d", revoked.Count)
	}
	if !login(owner).RequiresSetup {
		t.Fatal("revoke-all must require new key setup")
	}
	request("GET", path+"/public-keys", ownerToken, nil, nil, "", 200, "")
	events, err := q.GetAuditEventsByBuildID(ctx, pgtype.UUID{Bytes: buildID, Valid: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 4 || events[0].ActorKeyFingerprint == nil || *events[0].ActorKeyFingerprint != second.Fingerprint {
		t.Fatal("audit did not preserve signing key B")
	}
	if events[1].EventType != model.EventContractDownloaded.String() || events[1].ActorKeyFingerprint == nil || *events[1].ActorKeyFingerprint != first.Fingerprint {
		t.Fatal("download receipt did not preserve the actual signing key A")
	}
	verification, err := service.NewVerificationService(q).VerifyBuildAuditChain(ctx, buildID)
	if err != nil || !verification.IsValid || !verification.SignaturesValid {
		t.Fatalf("historical audit failed after revocation: %+v %v", verification, err)
	}
	otherFP, err := crypto.ComputePublicKeyFingerprint(otherPEM)
	if err != nil {
		t.Fatal(err)
	}
	request("POST", path+"/public-keys/revoke-all", otherToken, nil, otherKey, otherFP, 403, "FORBIDDEN")
}
