package keymgmt

import (
	"context"

	"github.com/google/uuid"

	"github.com/ibm-hyper-protect/contract-manager/internal/model"
)

// OneTimePrivateExport is returned only for explicitly exportable key operations.
type OneTimePrivateExport struct {
	WrappedPrivateKey string `json:"wrapped_private_key"`
	ExpiresAt         string `json:"expires_at,omitempty"`
}

// KeyRecord contains provider-managed metadata returned during key registration.
type KeyRecord struct {
	ID                   uuid.UUID
	BuildID              uuid.UUID
	Type                 model.BuildKeyType
	Mode                 model.BuildKeyMode
	Status               model.BuildKeyStatus
	PublicKey            string
	PublicKeyFingerprint string
	CreatedBy            uuid.UUID
	// EncryptedPrivateKey holds passphrase-encrypted private key material for generated keys.
	// The caller persists it after the parent build_keys row exists (FK on build_keys_private).
	EncryptedPrivateKey []byte
}

// KeyProvider abstracts key lifecycle operations for DB and mock providers.
type KeyProvider interface {
	CreateSigningKey(ctx context.Context, buildID, actorID uuid.UUID, mode model.BuildKeyMode, publicKeyPEM *string, passphrase *string) (KeyRecord, error)
	CreateAttestationKey(ctx context.Context, buildID, actorID uuid.UUID, mode model.BuildKeyMode, publicKeyPEM *string, passphrase *string) (KeyRecord, *OneTimePrivateExport, error)
	GetPublicKey(ctx context.Context, keyID uuid.UUID) (string, error)
	GetPrivateKey(ctx context.Context, keyID uuid.UUID) ([]byte, error)
	SignDigest(ctx context.Context, keyID uuid.UUID, digestHex string) (string, error)
}
