// Copyright (c) 2026 IBM Corp.
// All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package handler

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"gopkg.in/yaml.v3"

	contractengine "github.com/ibm-hyper-protect/contract-manager/internal/contract"
	"github.com/ibm-hyper-protect/contract-manager/internal/contract/contractgo"
	keydb "github.com/ibm-hyper-protect/contract-manager/internal/keymgmt/db"
	"github.com/ibm-hyper-protect/contract-manager/internal/middleware"
	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
	"github.com/ibm-hyper-protect/contract-manager/internal/service"
)

// The real handlers, services, provider and signing engine use an isolated migrated
// schema. Only the attestation records/signature engine is stubbed: these checks
// concern unlocking the build key before evidence is consumed, not IBM evidence.
func TestKeyPassphraseHTTP(t *testing.T) {
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set TEST_DATABASE_URL for PostgreSQL integration coverage")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	schema := "passphrase_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP SCHEMA "+quotedSchema+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	migrations, err := filepath.Glob("../../migrations/*.up.sql")
	if err != nil || len(migrations) == 0 {
		t.Fatal("migration files unavailable", err)
	}
	for _, name := range migrations {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, string(data)); err != nil {
			t.Fatalf("migration %s: %v", filepath.Base(name), err)
		}
	}
	execSQL := func(query string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	actor, buildID := uuid.New(), uuid.New()
	execSQL("INSERT INTO users (id,name,email,password_hash) VALUES ($1,'Passphrase review','passphrase@example.test','unused-test-hash')", actor)
	execSQL("INSERT INTO user_roles (user_id,role,assigned_by) VALUES ($1,'AUDITOR',$1)", actor)
	execSQL("INSERT INTO builds (id,name,created_by) VALUES ($1,'Passphrase regression',$2)", buildID, actor)
	execSQL("INSERT INTO build_assignments (build_id,role_id,user_id,assigned_by) SELECT $1,id,$2,$2 FROM roles WHERE name='AUDITOR'", buildID, actor)

	queries := repository.New(pool)
	audit := service.NewAuditService(queries)
	assignments := service.NewAssignmentService(queries, audit)
	builds := service.NewBuildService(queries, audit)
	provider := keydb.New(queries)
	engine := &passphraseEvidenceEngine{Engine: contractgo.New()}
	keys := service.NewKeyService(queries, pool, builds, assignments, audit, provider, engine)
	contracts := service.NewContractService(queries, pool, builds, assignments, keys, provider, engine)
	attestations := service.NewAttestationService(queries, pool, assignments, audit, provider, engine)
	keyHandler := NewKeyHandler(keys, nil)
	contractHandler := NewContractHandler(contracts, nil)
	attestationHandler := NewAttestationHandler(attestations, nil)
	router := chi.NewRouter()
	router.Post("/builds/{id}/keys/signing", keyHandler.RegisterSigningKey)
	router.Post("/builds/{id}/keys/attestation", keyHandler.RegisterAttestationKey)
	router.Post("/builds/{id}/finalize", contractHandler.FinalizeContract)
	router.Post("/builds/{id}/attestation/evidence/{evidence_id}/verify", attestationHandler.VerifyEvidence)
	request := func(t *testing.T, path string, payload map[string]any, status int, message string) []byte {
		t.Helper()
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/builds/"+buildID.String()+path, bytes.NewReader(body))
		authContext := middleware.SetAuthContext(req.Context(), actor, "passphrase@example.test", []string{"AUDITOR"}, "test-token", false, nil)
		authContext = middleware.SetRequestSignatureContext(authContext, "test-request-signature", "test-request-hash")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req.WithContext(authContext))
		if response.Code != status || !strings.Contains(response.Body.String(), message) {
			t.Fatalf("%s: got %d %s; want %d containing %q", path, response.Code, response.Body.String(), status, message)
		}
		for _, secret := range []string{"  Correct!Signing2026  ", "  Correct!Attest2026  ", "Wrong!Passphrase2026"} {
			if strings.Contains(response.Body.String(), secret) {
				t.Fatal("response leaked passphrase")
			}
		}
		return response.Body.Bytes()
	}
	assertState := func(t *testing.T, status string, keyCount, verificationCount int, certificatePinned bool) {
		t.Helper()
		var gotStatus string
		var pinned, immutable, hasContract bool
		var gotKeys, gotVerifications int
		err := pool.QueryRow(ctx, `SELECT status::text,encryption_certificate IS NOT NULL,is_immutable,contract_yaml IS NOT NULL OR contract_hash IS NOT NULL,
            (SELECT count(*) FROM build_keys WHERE build_id=$1),
            (SELECT count(*) FROM attestation_verifications WHERE build_id=$1) FROM builds WHERE id=$1`, buildID).Scan(&gotStatus, &pinned, &immutable, &hasContract, &gotKeys, &gotVerifications)
		if err != nil {
			t.Fatal(err)
		}
		if gotStatus != status || gotKeys != keyCount || gotVerifications != verificationCount || pinned != certificatePinned || immutable != (status == "FINALIZED") || hasContract != (status == "FINALIZED") {
			t.Fatalf("unexpected state: %s keys=%d verifications=%d pinned=%v immutable=%v", gotStatus, gotKeys, gotVerifications, pinned, immutable)
		}
	}
	// A current disposable certificate is also supplied when exercising optional PR9.
	runtimeKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &runtimeKey.PublicKey, runtimeKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))

	t.Run("registration errors precede all persistent changes", func(t *testing.T) {
		for _, keyType := range []string{"signing", "attestation"} {
			for _, tc := range []struct{ value, message string }{{"", "passphrase is required"}, {"Short!1", "at least 12"}, {"     Short!1     ", "at least 12"}, {" LongPassword12 ", "special character"}, {"longpassword!1", "uppercase"}, {"LONGPASSWORD!1", "lowercase"}, {"LongPassword!!", "digit"}, {"LongPassword12", "special character"}} {
				request(t, "/keys/"+keyType, map[string]any{"mode": "generate", "passphrase": tc.value, "encryption_cert_pem": certPEM}, http.StatusBadRequest, tc.message)
				assertState(t, "CREATED", 0, 0, false)
			}
		}
	})
	signingPassphrase := "  Correct!Signing2026  "
	attestationPassphrase := "  Correct!Attest2026  "
	registered := request(t, "/keys/signing", map[string]any{"mode": "generate", "passphrase": signingPassphrase}, http.StatusCreated, "public_key")
	var signing struct {
		KeyID     uuid.UUID `json:"signing_key_id"`
		PublicKey string    `json:"public_key"`
	}
	if err := json.Unmarshal(registered, &signing); err != nil {
		t.Fatal(err)
	}
	var storedSigning []byte
	if err := pool.QueryRow(ctx, "SELECT encrypted_key FROM build_keys_private WHERE key_id=$1", signing.KeyID).Scan(&storedSigning); err != nil {
		t.Fatal(err)
	}
	keyBlock, _ := pem.Decode(storedSigning)
	if _, err := x509.DecryptPEMBlock(keyBlock, []byte(strings.TrimSpace(signingPassphrase))); err != nil {
		t.Fatal("registration did not normalize the key passphrase")
	}
	execSQL("UPDATE builds SET status='ENVIRONMENT_STAGED' WHERE id=$1", buildID)
	for _, role := range []string{"SOLUTION_PROVIDER", "DATA_OWNER"} {
		encrypted, err := engine.EncryptString(ctx, "type: test\n", certPEM)
		if err != nil {
			t.Fatal(err)
		}
		execSQL("INSERT INTO build_sections (build_id,persona_role,submitted_by,encrypted_payload,section_hash,signature) VALUES ($1,$2,$3,$4,'test-hash','test-signature')", buildID, role, actor, encrypted)
	}
	request(t, "/keys/attestation", map[string]any{"mode": "generate", "passphrase": attestationPassphrase, "encryption_cert_pem": certPEM}, http.StatusCreated, "public_key")
	assertState(t, "ATTESTATION_KEY_REGISTERED", 2, 0, true)
	t.Run("failed finalization leaves build editable and retryable", func(t *testing.T) {
		for _, tc := range []struct{ value, message string }{{"", "passphrase is required"}, {"Wrong!Passphrase2026", "Unable to unlock the signing key"}} {
			request(t, "/finalize", map[string]any{"signing_key_passphrase": tc.value}, http.StatusBadRequest, tc.message)
			assertState(t, "ATTESTATION_KEY_REGISTERED", 2, 0, true)
		}
		var savedKey []byte
		if err := pool.QueryRow(ctx, "SELECT encrypted_key FROM build_keys_private WHERE key_id=$1", signing.KeyID).Scan(&savedKey); err != nil {
			t.Fatal(err)
		}
		execSQL("UPDATE build_keys_private SET encrypted_key=$2 WHERE key_id=$1", signing.KeyID, []byte("malformed stored key"))
		response := request(t, "/finalize", map[string]any{"signing_key_passphrase": signingPassphrase}, http.StatusInternalServerError, "Failed to finalize contract.")
		if strings.Contains(string(response), "invalid private key PEM") {
			t.Fatal("internal detail leaked")
		}
		assertState(t, "ATTESTATION_KEY_REGISTERED", 2, 0, true)
		execSQL("DELETE FROM build_keys_private WHERE key_id=$1", signing.KeyID)
		request(t, "/finalize", map[string]any{"signing_key_passphrase": signingPassphrase}, http.StatusInternalServerError, "Failed to finalize contract.")
		assertState(t, "ATTESTATION_KEY_REGISTERED", 2, 0, true)
		execSQL("INSERT INTO build_keys_private (key_id,encrypted_key,encryption_algo) VALUES ($1,$2,'aes-256-cbc')", signing.KeyID, savedKey)
	})
	request(t, "/finalize", map[string]any{"signing_key_passphrase": strings.TrimSpace(signingPassphrase)}, http.StatusOK, "FINALIZED")
	var signedYAML string
	if err := pool.QueryRow(ctx, "SELECT contract_yaml FROM builds WHERE id=$1", buildID).Scan(&signedYAML); err != nil {
		t.Fatal(err)
	}
	var contract map[string]string
	if err := yaml.Unmarshal([]byte(signedYAML), &contract); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(signing.PublicKey))
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.StdEncoding.DecodeString(contract["envWorkloadSignature"])
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(contract["workload"] + contract["env"]))
	if err := rsa.VerifyPKCS1v15(publicKey.(*rsa.PublicKey), crypto.SHA256, digest[:], signature); err != nil {
		t.Fatal("invalid finalized signature", err)
	}

	evidenceID := uuid.New()
	execSQL("INSERT INTO attestation_evidence (id,build_id,uploaded_by,uploader_role,records_file_name,records_content,signature_file_name,signature_content) VALUES ($1,$2,$3,'ENV_OPERATOR','records', $4,'signature',$5)", evidenceID, buildID, actor, []byte("fixture-records"), []byte("fixture-signature"))
	execSQL("UPDATE builds SET attestation_state='UPLOADED' WHERE id=$1", buildID)
	t.Run("bad attestation passphrase does not reject evidence", func(t *testing.T) {
		for _, tc := range []struct{ value, message string }{{"", "passphrase is required"}, {"Wrong!Passphrase2026", "Unable to unlock the attestation key"}} {
			request(t, "/attestation/evidence/"+evidenceID.String()+"/verify", map[string]any{"attestation_key_passphrase": tc.value, "attestation_certificate_pem": certPEM}, http.StatusBadRequest, tc.message)
			assertState(t, "FINALIZED", 2, 0, true)
			var state string
			if err := pool.QueryRow(ctx, "SELECT attestation_state FROM builds WHERE id=$1", buildID).Scan(&state); err != nil {
				t.Fatal(err)
			}
			if state != "UPLOADED" || engine.calls != 0 {
				t.Fatal("evidence consumed on passphrase error")
			}
		}
	})
	t.Run("malformed attestation key does not consume evidence", func(t *testing.T) {
		var keyID uuid.UUID
		var saved []byte
		if err := pool.QueryRow(ctx, "SELECT k.id,p.encrypted_key FROM build_keys k JOIN build_keys_private p ON p.key_id=k.id WHERE k.build_id=$1 AND k.key_type='ATTESTATION'", buildID).Scan(&keyID, &saved); err != nil {
			t.Fatal(err)
		}
		execSQL("UPDATE build_keys_private SET encrypted_key=$2 WHERE key_id=$1", keyID, []byte("malformed stored key"))
		request(t, "/attestation/evidence/"+evidenceID.String()+"/verify", map[string]any{"attestation_key_passphrase": attestationPassphrase, "attestation_certificate_pem": certPEM}, http.StatusInternalServerError, "Failed to verify attestation evidence.")
		assertState(t, "FINALIZED", 2, 0, true)
		execSQL("UPDATE build_keys_private SET encrypted_key=$2 WHERE key_id=$1", keyID, saved)
	})
	request(t, "/attestation/evidence/"+evidenceID.String()+"/verify", map[string]any{"attestation_key_passphrase": "\t" + strings.TrimSpace(attestationPassphrase) + "\n", "attestation_certificate_pem": certPEM}, http.StatusOK, "VERIFIED")
	if engine.password != strings.TrimSpace(attestationPassphrase) || engine.calls != 1 {
		t.Fatal("attestation passphrase not normalized or retry not performed")
	}
	assertState(t, "FINALIZED", 2, 1, true)
}

type passphraseEvidenceEngine struct {
	contractengine.Engine
	calls    int
	password string
}

func (e *passphraseEvidenceEngine) HpcrGetAttestationRecords(_ context.Context, _ string, _ string, password string) (string, error) {
	e.calls++
	e.password = password
	return "fixture records", nil
}

func (e *passphraseEvidenceEngine) HpcrVerifySignatureAttestationRecords(context.Context, string, string, string) error {
	return nil
}
