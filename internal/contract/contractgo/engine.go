package contractgo

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"

	hpattestation "github.com/ibm-hyper-protect/contract-go/v2/attestation"
	hpcertificate "github.com/ibm-hyper-protect/contract-go/v2/certificate"
	hpcontract "github.com/ibm-hyper-protect/contract-go/v2/contract"

	"github.com/ibm-hyper-protect/contract-manager/internal/contract"
	appcrypto "github.com/ibm-hyper-protect/contract-manager/internal/crypto"
)

type encryptedEnvelope struct {
	Algorithm  string `json:"algorithm"`
	WrappedKey string `json:"wrapped_key"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// Engine is a Go-native replacement for contract-cli cryptography calls.
type Engine struct{}

// New returns a contract-go engine implementation.
func New() *Engine {
	return &Engine{}
}

const fallbackWorkloadTemplate = `type: workload
auths:
  <registry url>:
    password: <password>
    username: <user name>
# Use either compose or pods
play:
  archive: <base64 TGZ of podman play support files>
compose:
  archive: <base64 TGZ of docker compose support files>
images:
  dct:
    <docker image name (without the tag, an example is docker.io/redbookuser/s390x:)>:
      notary: "<notary URL>"
      publicKey: <docker content trust signed public key>
volumes:
  <volume key>:
    mount: "<data volume mount path>"
    seed: "<Passphrase of the LUKS encryption>"
    filesystem: "ext4"
`

const fallbackEnvTemplate = `type: env
logging:
  # Use logRouter for ICL & syslog for syslog server (only one)
  logRouter:
    hostname: <host name of the service instance> /
    iamApiKey: <iamApiKey of the service instance> / xxxx
    port: <port of the service instance(443)
  syslog:
    hostname: ${RSYSLOG_SERVER_IP}
    port: 6514
    server: "${RSYSLOG_SERVER_ROOT_CA}"
    cert: "${RSYSLOG_CLIENT_CA}"
    key: "${RSYSLOG_CLIENT_KEY}"
volumes:
  test:
    seed: "seed_value_with_minimum_15_characters"
env:
  <env-name>: "env-value"
signingKey: <signing key or certificate>
`

// EncryptString encrypts plaintext using the official contract-go v2 format:
// "hyper-protect-basic.<encrypted-password>.<encrypted-data>".
func (e *Engine) EncryptString(ctx context.Context, plaintext, certPEM string) (string, error) {
	_ = ctx
	encrypted, _, _, err := hpcontract.HpcrTextEncrypted(plaintext, "", "", certPEM)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt plaintext with contract-go v2: %w", err)
	}
	return encrypted, nil
}

func aesCipher(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %w", err)
	}
	return aead, nil
}

// AssembleContract builds deterministic YAML and computes SHA-256 hash.
func (e *Engine) AssembleContract(ctx context.Context, in contract.AssembleInput) (string, string, error) {
	_ = ctx
	contractYAML := strings.TrimSpace(fmt.Sprintf(
		"env: %s\nworkload: %s\nenvWorkloadSignature: %s\nattestationPublicKey: %s\n",
		in.EncryptedEnvironment,
		in.EncryptedWorkload,
		in.EnvWorkloadSignature,
		in.EncryptedAttestationKey,
	))
	contractYAML += "\n"

	hash := appcrypto.SHA256HexString(contractYAML)
	return contractYAML, hash, nil
}

// HpcrContractSign provides an HPCR-compatible signing hook.
// It delegates to contract-go/v2 and returns:
// 1) final signed contract YAML
// 2) SHA-256 of input contract YAML
// 3) SHA-256 of output signed contract YAML
func (e *Engine) HpcrContractSign(ctx context.Context, contractData, privateKeyPEM, password string) (string, string, string, error) {
	_ = ctx
	signedContract, inputChecksum, outputChecksum, err := hpcontract.HpcrContractSign(contractData, privateKeyPEM, password)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to sign contract with contract-go v2: %w", err)
	}

	return signedContract, inputChecksum, outputChecksum, nil
}

// HpcrContractTemplate delegates template generation to contract-go/v2.
func (e *Engine) HpcrContractTemplate(ctx context.Context, templateType string) (string, error) {
	_ = ctx
	normalized := strings.ToLower(strings.TrimSpace(templateType))
	switch normalized {
	case "docker_compose", "docker-compose", "podman_play", "podman-play":
		// Legacy aliases retained for backward compatibility; both map to workload template.
		normalized = "workload"
	}

	template, err := hpcontract.HpcrContractTemplate(normalized, "")
	if err != nil {
		// contract-go template retrieval uses runtime source file paths and can fail
		// in slim container images where module source files are absent.
		if fallback, ok := fallbackContractTemplate(normalized); ok {
			return fallback, nil
		}
		return "", fmt.Errorf("failed to generate contract template: %w", err)
	}
	if strings.TrimSpace(template) == "" {
		if fallback, ok := fallbackContractTemplate(normalized); ok {
			return fallback, nil
		}
	}
	return template, nil
}

func fallbackContractTemplate(templateType string) (string, bool) {
	switch templateType {
	case "workload":
		return fallbackWorkloadTemplate, true
	case "env":
		return fallbackEnvTemplate, true
	case "":
		indentedWorkload := strings.ReplaceAll(strings.TrimRight(fallbackWorkloadTemplate, "\n"), "\n", "\n  ")
		indentedEnv := strings.ReplaceAll(strings.TrimRight(fallbackEnvTemplate, "\n"), "\n", "\n  ")
		return "workload: |\n  " + indentedWorkload + "\n" +
			"env: |\n  " + indentedEnv + "\n", true
	default:
		return "", false
	}
}

// HpcrGetAttestationRecords decrypts attestation records when they are provided
// in the contract-go envelope format; otherwise returns data as-is.
func (e *Engine) HpcrGetAttestationRecords(ctx context.Context, data, privateKeyPEM, password string) (string, error) {
	_ = ctx
	trimmed := strings.TrimSpace(data)
	if trimmed == "" {
		return "", fmt.Errorf("attestation records payload is empty")
	}
	if !strings.HasPrefix(trimmed, "contract-go.v1.") {
		// v2 official format from contract-go library.
		if strings.HasPrefix(trimmed, "hyper-protect-basic.") {
			decrypted, _, _, err := hpcontract.HpcrTextDecrypted(trimmed, privateKeyPEM, password)
			if err != nil {
				return "", fmt.Errorf("failed to decrypt hyper-protect-basic payload: %w", err)
			}
			return decrypted, nil
		}
		return trimmed, nil
	}

	privateKey, err := parseRSAPrivateKey(privateKeyPEM, password)
	if err != nil {
		return "", err
	}

	rawEnvelope, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(trimmed, "contract-go.v1."))
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted attestation envelope: %w", err)
	}

	var env encryptedEnvelope
	if err := json.Unmarshal(rawEnvelope, &env); err != nil {
		return "", fmt.Errorf("failed to decode attestation envelope JSON: %w", err)
	}

	wrappedKey, err := base64.StdEncoding.DecodeString(env.WrappedKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode wrapped key: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return "", fmt.Errorf("failed to decode nonce: %w", err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, wrappedKey, nil)
	if err != nil {
		return "", fmt.Errorf("failed to unwrap symmetric key: %w", err)
	}

	aead, err := aesCipher(aesKey)
	if err != nil {
		return "", err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt attestation records: %w", err)
	}
	return string(plaintext), nil
}

// HpcrVerifySignatureAttestationRecords verifies the HPCR attestation records signature
// against the IBM attestation certificate using contract-go. The signature may be raw
// bytes (se-signature.bin) or their base64 encoding.
func (e *Engine) HpcrVerifySignatureAttestationRecords(ctx context.Context, attestationRecords, signature, attestationCert string) error {
	_ = ctx
	trimmedSignature := strings.TrimSpace(signature)
	if trimmedSignature == "" {
		return fmt.Errorf("attestation signature is empty")
	}
	if strings.TrimSpace(attestationCert) == "" {
		return fmt.Errorf("attestation certificate is required")
	}
	if _, err := appcrypto.ParseCertificatePEM(attestationCert); err != nil {
		return fmt.Errorf("invalid attestation certificate: %w", err)
	}

	// Raw signature bytes are used untrimmed; only a base64 form may carry surrounding whitespace.
	rawSignature := signature
	if decoded, err := base64.StdEncoding.DecodeString(trimmedSignature); err == nil {
		rawSignature = string(decoded)
	}

	if err := hpattestation.HpcrVerifySignatureAttestationRecords(attestationRecords, rawSignature, attestationCert); err != nil {
		return fmt.Errorf("attestation signature verification failed: %w", err)
	}
	return nil
}

func parseEncryptionPublicKey(certPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("invalid certificate/public key PEM")
	}

	switch block.Type {
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("certificate public key is not RSA")
		}
		return pub, nil
	default:
		pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}
		pub, ok := pubAny.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("public key is not RSA")
		}
		return pub, nil
	}
}

func parseRSAPrivateKey(privateKeyPEM, password string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("invalid private key PEM")
	}

	privateDER := block.Bytes
	if x509.IsEncryptedPEMBlock(block) {
		if password == "" {
			return nil, fmt.Errorf("encrypted private key requires password")
		}
		decrypted, err := x509.DecryptPEMBlock(block, []byte(password))
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt private key: %w", err)
		}
		privateDER = decrypted
	}

	if key, err := x509.ParsePKCS1PrivateKey(privateDER); err == nil {
		return key, nil
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(privateDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
	}
	key, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}
	return key, nil
}

// ListAvailableEncCertVersions returns the list of available encryption certificate versions
// by calling HpcrListAvailableEncCertVersions from contract-go certificate package.
// It returns all available certificate versions in JSON format.
func (e *Engine) ListAvailableEncCertVersions(ctx context.Context) ([]string, error) {
	_ = ctx
	// Get all available certificate versions in JSON format
	// Empty osType returns all OS types, "json" format returns structured data
	versionsJSON, err := hpcertificate.HpcrListAvailableEncCertVersions("", "json")
	if err != nil {
		return nil, fmt.Errorf("failed to list available encryption certificate versions: %w", err)
	}

	// Parse the JSON response to extract version strings
	var certData map[string][]string
	if err := json.Unmarshal([]byte(versionsJSON), &certData); err != nil {
		return nil, fmt.Errorf("failed to parse certificate versions JSON: %w", err)
	}

	// Collect all unique versions from all OS types
	versionSet := make(map[string]bool)
	for _, versions := range certData {
		for _, version := range versions {
			versionSet[version] = true
		}
	}

	// Convert set to slice
	result := make([]string, 0, len(versionSet))
	for version := range versionSet {
		result = append(result, version)
	}

	return result, nil
}
