package contractgo

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// newAttestationSigner returns a self-signed certificate standing in for the IBM attestation
// certificate, plus a function that signs records like `openssl dgst -sha256 -sign`.
func newAttestationSigner(t *testing.T) (string, func(string) []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test attestation"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	sign := func(records string) []byte {
		digest := sha256.Sum256([]byte(records))
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return sig
	}
	return certPEM, sign
}

func TestHpcrVerifySignatureAttestationRecords(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available")
	}
	certPEM, sign := newAttestationSigner(t)
	records := "sha256:abc  root.tar.gz\nsha256:def  cidata\n"
	sig := sign(records)
	engine := New()
	ctx := context.Background()

	if err := engine.HpcrVerifySignatureAttestationRecords(ctx, records, string(sig), certPEM); err != nil {
		t.Fatalf("raw signature: unexpected error: %v", err)
	}
	if err := engine.HpcrVerifySignatureAttestationRecords(ctx, records, base64.StdEncoding.EncodeToString(sig), certPEM); err != nil {
		t.Fatalf("base64 signature: unexpected error: %v", err)
	}
	if err := engine.HpcrVerifySignatureAttestationRecords(ctx, records+"tampered", string(sig), certPEM); err == nil {
		t.Fatal("tampered records: expected verification error")
	}

	otherCert, _ := newAttestationSigner(t)
	if err := engine.HpcrVerifySignatureAttestationRecords(ctx, records, string(sig), otherCert); err == nil {
		t.Fatal("wrong certificate: expected verification error")
	}
	if err := engine.HpcrVerifySignatureAttestationRecords(ctx, records, string(sig), ""); err == nil {
		t.Fatal("missing certificate: expected error")
	}
}

func TestEncryptString_UsesEncryptionCertificate(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available")
	}
	certPEM, _ := newAttestationSigner(t)
	out, err := New().EncryptString(context.Background(), "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----\n", certPEM)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(out, "hyper-protect-basic.") {
		t.Fatalf("expected hyper-protect-basic envelope, got %q", out)
	}
}
