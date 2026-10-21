package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"unicode/utf8"
)

// NormalizeFingerprint returns lowercase hex without separators.
func NormalizeFingerprint(fp string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(fp), ":", ""))
}

// ComputePublicKeyFingerprint computes the SHA-256 fingerprint of a PEM-encoded public key.
func ComputePublicKeyFingerprint(publicKeyPEM string) (string, error) {
	// Decode PEM public key
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block")
	}

	// Compute SHA-256 hash of the DER-encoded public key
	hash := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(hash[:]), nil
}

// ValidatePublicKey validates that a PEM-encoded string is a valid RSA-4096 public key.
func ValidatePublicKey(publicKeyPEM string) error {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not RSA")
	}

	// Verify key size is 4096 bits
	if rsaPub.N.BitLen() != 4096 {
		return fmt.Errorf("public key must be RSA-4096, got %d bits", rsaPub.N.BitLen())
	}

	return nil
}

// VerifySignature verifies an RSA-PSS signature against a hash using a PEM-encoded public key.
// The hash should be a hex-encoded SHA-256 hash of the data.
func VerifySignature(publicKeyPEM string, hashHex string, signatureBase64 string) error {
	// Decode PEM public key
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return fmt.Errorf("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not RSA")
	}

	// Decode signature from base64
	sig, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// Decode the hash from hex
	hashBytes, err := hex.DecodeString(hashHex)
	if err != nil {
		return fmt.Errorf("failed to decode hash: %w", err)
	}

	if len(hashBytes) != 32 {
		return fmt.Errorf("invalid hash length: expected 32 bytes, got %d", len(hashBytes))
	}

	// Verify using RSA-PSS with SHA-256
	opts := &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthEqualsHash,
		Hash:       crypto.SHA256,
	}

	// Primary mode: RSA-SHA256 semantics (sign/verify over the hash string bytes).
	// This matches Node createSign/createVerify('RSA-SHA256') with PSS padding.
	digest := sha256.Sum256([]byte(hashHex))
	if err := rsa.VerifyPSS(rsaPub, crypto.SHA256, digest[:], sig, opts); err == nil {
		return nil
	}

	// Backward compatibility: verify against pre-hashed digest bytes directly.
	if err := rsa.VerifyPSS(rsaPub, crypto.SHA256, hashBytes, sig, opts); err == nil {
		return nil
	}

	return fmt.Errorf("signature verification failed")
}

// ParseCertificatePEM validates and parses a PEM-encoded X.509 certificate.
func ParseCertificatePEM(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// EncryptPrivateKeyPEM encrypts a PEM-encoded private key with a passphrase using AES-256-CBC.
// The output PEM has Proc-Type/DEK-Info headers compatible with OpenSSL and contract-go.
func EncryptPrivateKeyPEM(privateKeyPEM string, passphrase string) (string, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block")
	}

	//nolint:staticcheck // x509.EncryptPEMBlock is deprecated in Go stdlib but required
	// for OpenSSL PEM compatibility. contract-go's SignContract expects Proc-Type/DEK-Info
	// headers that only this format provides.
	encryptedBlock, err := x509.EncryptPEMBlock(
		rand.Reader,
		block.Type,
		block.Bytes,
		[]byte(passphrase),
		x509.PEMCipherAES256,
	)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt PEM block: %w", err)
	}

	return string(pem.EncodeToMemory(encryptedBlock)), nil
}

// GenerateEncryptedKeyPair generates an RSA-4096 key pair and returns the public key PEM
// and the private key PEM encrypted with the given passphrase (AES-256-CBC).
// The encrypted PEM format is compatible with OpenSSL and the contract-go library.
func GenerateEncryptedKeyPair(passphrase string) (publicKeyPEM string, encryptedPrivateKeyPEM string, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate RSA-4096 key: %w", err)
	}
	defer func() {
		// Zeroize private key material after use
		privateKey.D.SetInt64(0)
		for i := range privateKey.Primes {
			privateKey.Primes[i].SetInt64(0)
		}
	}()

	// Marshal public key
	pubDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	}))

	// Marshal private key to PKCS1 DER
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)
	defer func() {
		for i := range privDER {
			privDER[i] = 0
		}
	}()

	// Encrypt with AES-256-CBC passphrase protection
	//nolint:staticcheck // Required for OpenSSL/contract-go PEM compatibility
	encryptedBlock, err := x509.EncryptPEMBlock(
		rand.Reader,
		"RSA PRIVATE KEY",
		privDER,
		[]byte(passphrase),
		x509.PEMCipherAES256,
	)
	if err != nil {
		return "", "", fmt.Errorf("failed to encrypt private key: %w", err)
	}

	encPrivPEM := string(pem.EncodeToMemory(encryptedBlock))
	return pubPEM, encPrivPEM, nil
}

// DecryptPrivateKeyPEM decrypts a passphrase-protected PEM private key and returns
// the plaintext PEM. Caller MUST zeroize the returned string after use.
func DecryptPrivateKeyPEM(encryptedPEM string, passphrase string) (string, error) {
	block, _ := pem.Decode([]byte(encryptedPEM))
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM block")
	}

	//nolint:staticcheck // Required for OpenSSL PEM compatibility
	if !x509.IsEncryptedPEMBlock(block) {
		// Already unencrypted
		return encryptedPEM, nil
	}

	//nolint:staticcheck // Required for OpenSSL PEM compatibility
	decryptedDER, err := x509.DecryptPEMBlock(block, []byte(passphrase))
	if err != nil {
		return "", fmt.Errorf("failed to decrypt private key (wrong passphrase?): %w", err)
	}

	plaintextPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  block.Type,
		Bytes: decryptedDER,
	}))

	// Zeroize the DER bytes
	for i := range decryptedDER {
		decryptedDER[i] = 0
	}

	return plaintextPEM, nil
}

// ValidatePassphraseStrength enforces minimum passphrase complexity:
// - At least 12 characters
// - At least one uppercase letter
// - At least one lowercase letter
// - At least one digit
// - At least one special character
func ValidatePassphraseStrength(passphrase string) error {
	if utf8.RuneCountInString(passphrase) < 12 {
		return fmt.Errorf("passphrase must be at least 12 characters long")
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, r := range passphrase {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
	}

	if !hasUpper {
		return fmt.Errorf("passphrase must contain at least one uppercase letter")
	}
	if !hasLower {
		return fmt.Errorf("passphrase must contain at least one lowercase letter")
	}
	if !hasDigit {
		return fmt.Errorf("passphrase must contain at least one digit")
	}
	if !hasSpecial {
		return fmt.Errorf("passphrase must contain at least one special character")
	}

	return nil
}
