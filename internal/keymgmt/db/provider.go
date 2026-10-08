package db

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"

	appcrypto "github.com/ibm-hyper-protect/contract-manager/internal/crypto"
	"github.com/ibm-hyper-protect/contract-manager/internal/keymgmt"
	"github.com/ibm-hyper-protect/contract-manager/internal/model"
	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
)

// Provider implements KeyProvider using PostgreSQL for key storage.
// Private keys are always encrypted with a user-supplied passphrase (AES-256-CBC PEM format).
type Provider struct {
	queries repository.Querier
}

// New creates a database-backed key provider.
func New(queries repository.Querier) *Provider {
	return &Provider{queries: queries}
}

func (p *Provider) CreateSigningKey(ctx context.Context, buildID, actorID uuid.UUID, mode model.BuildKeyMode, publicKeyPEM *string, passphrase *string) (keymgmt.KeyRecord, error) {
	return p.createKey(ctx, buildID, actorID, model.BuildKeyTypeSigning, mode, publicKeyPEM, passphrase)
}

func (p *Provider) CreateAttestationKey(ctx context.Context, buildID, actorID uuid.UUID, mode model.BuildKeyMode, publicKeyPEM *string, passphrase *string) (keymgmt.KeyRecord, *keymgmt.OneTimePrivateExport, error) {
	record, err := p.createKey(ctx, buildID, actorID, model.BuildKeyTypeAttestation, mode, publicKeyPEM, passphrase)
	if err != nil {
		return keymgmt.KeyRecord{}, nil, err
	}
	// Private key export is intentionally not returned — caller decrypts with passphrase when needed.
	return record, nil, nil
}

func (p *Provider) GetPublicKey(ctx context.Context, keyID uuid.UUID) (string, error) {
	// Public key is stored in build_keys table via v2Store; this is a fallback path.
	// In practice, the key service reads public keys from the v2Store directly.
	return "", fmt.Errorf("GetPublicKey: use v2Store.getLatestActiveBuildKeyByType for public key lookups")
}

func (p *Provider) GetPrivateKey(ctx context.Context, keyID uuid.UUID) ([]byte, error) {
	row, err := p.queries.GetBuildKeyPrivate(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to read encrypted private key for key_id %s: %w", keyID, err)
	}
	// Return the encrypted PEM bytes — caller decrypts with passphrase.
	return row.EncryptedKey, nil
}

func (p *Provider) SignDigest(ctx context.Context, keyID uuid.UUID, digestHex string) (string, error) {
	// DB provider does not perform server-side signing.
	// Signing is done in contract_service.go using the decrypted private key + contract-go library.
	return "", fmt.Errorf("SignDigest is not supported by the DB key provider; use contract-go signing with passphrase")
}

func (p *Provider) createKey(ctx context.Context, buildID, actorID uuid.UUID, keyType model.BuildKeyType, mode model.BuildKeyMode, publicKeyPEM *string, passphrase *string) (keymgmt.KeyRecord, error) {
	record := keymgmt.KeyRecord{
		ID:        uuid.New(),
		BuildID:   buildID,
		Type:      keyType,
		Mode:      mode,
		Status:    model.BuildKeyStatusActive,
		CreatedBy: actorID,
	}

	switch mode {
	case model.BuildKeyModeGenerate:
		// Passphrase is mandatory for key generation
		if passphrase == nil || strings.TrimSpace(*passphrase) == "" {
			return keymgmt.KeyRecord{}, fmt.Errorf("passphrase is required for key generation")
		}

		// Validate passphrase strength
		if err := appcrypto.ValidatePassphraseStrength(*passphrase); err != nil {
			return keymgmt.KeyRecord{}, fmt.Errorf("weak passphrase: %w", err)
		}

		// Generate RSA-4096 key pair with passphrase-encrypted private key
		pubPEM, encPrivPEM, err := appcrypto.GenerateEncryptedKeyPair(*passphrase)
		if err != nil {
			return keymgmt.KeyRecord{}, fmt.Errorf("failed to generate key pair: %w", err)
		}

		record.PublicKey = pubPEM

		// Stored in build_keys_private by the caller once the build_keys row exists.
		record.EncryptedPrivateKey = []byte(encPrivPEM)

	case model.BuildKeyModeUploadPublic:
		if publicKeyPEM == nil || *publicKeyPEM == "" {
			return keymgmt.KeyRecord{}, fmt.Errorf("public key is required for upload_public mode")
		}
		if err := appcrypto.ValidatePublicKey(*publicKeyPEM); err != nil {
			return keymgmt.KeyRecord{}, fmt.Errorf("invalid public key: %w", err)
		}
		record.PublicKey = *publicKeyPEM

	default:
		return keymgmt.KeyRecord{}, fmt.Errorf("unsupported key mode: %s", mode)
	}

	fingerprint, err := appcrypto.ComputePublicKeyFingerprint(record.PublicKey)
	if err != nil {
		return keymgmt.KeyRecord{}, fmt.Errorf("failed to compute public key fingerprint: %w", err)
	}
	record.PublicKeyFingerprint = fingerprint

	return record, nil
}
