package middleware

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	appcrypto "github.com/ibm-hyper-protect/contract-manager/internal/crypto"
	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
	"github.com/ibm-hyper-protect/contract-manager/internal/service"
)

type signatureQueries struct {
	repository.Querier
	keys []repository.UserPublicKey
	err  error
}

func (q *signatureQueries) ListUserPublicKeys(_ context.Context, userID uuid.UUID) ([]repository.UserPublicKey, error) {
	keys := make([]repository.UserPublicKey, 0, len(q.keys))
	for _, key := range q.keys {
		if key.UserID == userID {
			keys = append(keys, key)
		}
	}
	return keys, q.err
}

func TestSignatureExemptions(t *testing.T) {
	userID := uuid.New()
	first := repository.UserPublicKey{ID: uuid.New(), UserID: userID, Fingerprint: "aa", ExpiresAt: time.Now().Add(time.Hour)}
	second := repository.UserPublicKey{ID: uuid.New(), UserID: userID, Fingerprint: "bb", ExpiresAt: first.ExpiresAt}
	expired := first
	expired.ExpiresAt = time.Now().Add(-time.Hour)
	revoked := first
	revoked.RevokedAt = pgtype.Timestamptz{Time: time.Now(), Valid: true}
	backendErr := errors.New("database unavailable")
	tests := []struct {
		name       string
		method     string
		path       string
		keys       []repository.UserPublicKey
		queryErr   error
		wantStatus int
	}{
		{"read request", http.MethodGet, "/builds", nil, backendErr, http.StatusNoContent},
		{"logout", http.MethodPost, "/auth/logout", nil, backendErr, http.StatusNoContent},
		{"password change", http.MethodPatch, "/users/" + userID.String() + "/password", nil, backendErr, http.StatusNoContent},
		{"first key", http.MethodPut, "/users/" + userID.String() + "/public-key", nil, nil, http.StatusNoContent},
		{"only expired key", http.MethodPut, "/users/" + userID.String() + "/public-key", []repository.UserPublicKey{expired}, nil, http.StatusNoContent},
		{"only revoked key", http.MethodPut, "/users/" + userID.String() + "/public-key", []repository.UserPublicKey{revoked}, nil, http.StatusNoContent},
		{"one active key requires signature", http.MethodPut, "/users/" + userID.String() + "/public-key", []repository.UserPublicKey{first}, nil, http.StatusBadRequest},
		{"multiple active keys require signature", http.MethodPut, "/users/" + userID.String() + "/public-key", []repository.UserPublicKey{first, second}, nil, http.StatusBadRequest},
		{"database error blocks registration", http.MethodPut, "/users/" + userID.String() + "/public-key", nil, backendErr, http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			queries := &signatureQueries{keys: tt.keys, err: tt.queryErr}
			keySvc := service.NewUserKeyService(nil, queries)
			handler := RequireRequestSignature(keySvc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))
			r := httptest.NewRequest(tt.method, tt.path, strings.NewReader(`{}`))
			r = r.WithContext(SetAuthContext(r.Context(), userID, "test@example.test", nil, "token-hash", false, nil))
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", w.Code, tt.wantStatus, w.Body.String())
			}
		})
	}
}

func newSignatureTestKey(t *testing.T, userID uuid.UUID) (*rsa.PrivateKey, repository.UserPublicKey) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	fingerprint, err := appcrypto.ComputePublicKeyFingerprint(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return privateKey, repository.UserPublicKey{
		ID: uuid.New(), UserID: userID, PublicKey: publicKey,
		Fingerprint: fingerprint, ExpiresAt: time.Now().Add(time.Hour),
	}
}

func TestRequestSignatureKeySelection(t *testing.T) {
	userID := uuid.New()
	privateA, keyA := newSignatureTestKey(t, userID)
	privateB, keyB := newSignatureTestKey(t, userID)
	revoked := keyB
	revoked.RevokedAt = pgtype.Timestamptz{Time: time.Now(), Valid: true}
	expired := keyB
	expired.ExpiresAt = time.Now().Add(-time.Hour)
	tests := []struct {
		name        string
		keys        []repository.UserPublicKey
		fingerprint string
		privateKey  *rsa.PrivateKey
		wantKey     uuid.UUID
		wantStatus  int
		wantCode    string
	}{
		{"first key", []repository.UserPublicKey{keyA, keyB}, keyA.Fingerprint, privateA, keyA.ID, http.StatusNoContent, ""},
		{"second key and normalized header", []repository.UserPublicKey{keyA, keyB}, strings.ToUpper(keyB.Fingerprint), privateB, keyB.ID, http.StatusNoContent, ""},
		{"single key fallback", []repository.UserPublicKey{keyA}, "", privateA, keyA.ID, http.StatusNoContent, ""},
		{"multiple keys without fingerprint", []repository.UserPublicKey{keyA, keyB}, "", privateA, uuid.Nil, http.StatusForbidden, "SIGNATURE_KEY_FINGERPRINT_REQUIRED"},
		{"signature from different key", []repository.UserPublicKey{keyA, keyB}, keyA.Fingerprint, privateB, uuid.Nil, http.StatusBadRequest, "INVALID_SIGNATURE"},
		{"unknown fingerprint", []repository.UserPublicKey{keyA}, keyB.Fingerprint, privateB, uuid.Nil, http.StatusForbidden, "INVALID_SIGNATURE"},
		{"foreign key", []repository.UserPublicKey{keyA}, keyA.Fingerprint, privateA, uuid.Nil, http.StatusForbidden, "INVALID_SIGNATURE"},
		{"revoked key", []repository.UserPublicKey{keyA, revoked}, keyB.Fingerprint, privateB, uuid.Nil, http.StatusForbidden, "SIGNATURE_KEY_REVOKED"},
		{"expired key", []repository.UserPublicKey{keyA, expired}, keyB.Fingerprint, privateB, uuid.Nil, http.StatusForbidden, "SIGNATURE_KEY_EXPIRED"},
		{"no keys", nil, "", privateA, uuid.Nil, http.StatusForbidden, "SIGNATURE_KEY_MISSING"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			queries := &signatureQueries{keys: tt.keys}
			keySvc := service.NewUserKeyService(nil, queries)
			const body = `{"name":"demo"}`
			r := httptest.NewRequest(http.MethodPost, "/builds", strings.NewReader(body))
			authUserID := userID
			if tt.name == "foreign key" {
				authUserID = uuid.New()
			}
			r = r.WithContext(SetAuthContext(r.Context(), authUserID, "test@example.test", nil, "token-hash", false, nil))
			timestamp := time.Now().UnixMilli()
			hash, err := computeRequestHash(r.Method, r.URL.Path, timestamp, []byte(body))
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256([]byte(hash))
			sig, err := rsa.SignPSS(rand.Reader, tt.privateKey, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
			if err != nil {
				t.Fatal(err)
			}
			signature := base64.StdEncoding.EncodeToString(sig)
			r.Header.Set("X-Signature", signature)
			r.Header.Set("X-Signature-Hash", hash)
			r.Header.Set("X-Timestamp", strconv.FormatInt(timestamp, 10))
			r.Header.Set("X-Key-Fingerprint", tt.fingerprint)
			called := false
			handler := RequireRequestSignature(keySvc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				key, ok := service.SigningKeyFromContext(r.Context())
				if !ok || key.ID != tt.wantKey {
					t.Errorf("context signing key = %s, present = %v; want %s", key.ID, ok, tt.wantKey)
				}
				if id, ok := GetUserID(r.Context()); !ok || id != userID {
					t.Error("authentication context was lost")
				}
				if GetRequestSignature(r.Context()) != signature || GetRequestSignatureHash(r.Context()) != hash {
					t.Error("signature metadata was lost")
				}
				gotBody, err := io.ReadAll(r.Body)
				if err != nil || string(gotBody) != body {
					t.Errorf("request body changed: %q, %v", gotBody, err)
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d; body: %s", w.Code, tt.wantStatus, w.Body.String())
			}
			if called != (tt.wantStatus == http.StatusNoContent) {
				t.Error("unexpected downstream handler invocation")
			}
			if tt.wantCode != "" {
				var response struct {
					Error struct {
						Code string `json:"code"`
					} `json:"error"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
					t.Fatal(err)
				}
				if response.Error.Code != tt.wantCode {
					t.Errorf("error code = %q, want %q", response.Error.Code, tt.wantCode)
				}
			}
		})
	}
}
