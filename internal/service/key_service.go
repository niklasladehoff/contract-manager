package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/ibm-hyper-protect/contract-manager/internal/keymgmt"
	"github.com/ibm-hyper-protect/contract-manager/internal/model"
	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
)

// KeyService orchestrates build-scoped signing and attestation keys.
type KeyService struct {
	queries           repository.Querier
	buildService      *BuildService
	assignmentService *AssignmentService
	auditService      *AuditService
	store             *v2Store
	keyProvider       keymgmt.KeyProvider
	engine            contractEngine
}

// contractEngine defines the subset of contract operations needed by KeyService
type contractEngine interface {
	EncryptString(ctx context.Context, plaintext, certPEM string) (string, error)
}

// KeyRegistrationResult is returned from key registration endpoints.
type KeyRegistrationResult struct {
	KeyID       uuid.UUID `json:"key_id"`
	PublicKey   string    `json:"public_key"`
	Fingerprint string    `json:"fingerprint"`
	Mode        string    `json:"mode"`
	KeyType     string    `json:"key_type"`
}

// NewKeyService creates a key orchestration service.
func NewKeyService(
	queries repository.Querier,
	db repository.DBTX,
	buildService *BuildService,
	assignmentService *AssignmentService,
	auditService *AuditService,
	keyProvider keymgmt.KeyProvider,
	engine contractEngine,
) *KeyService {
	return &KeyService{
		queries:           queries,
		buildService:      buildService,
		assignmentService: assignmentService,
		auditService:      auditService,
		store:             newV2Store(db),
		keyProvider:       keyProvider,
		engine:            engine,
	}
}

// encryptAttestationPublicKey encrypts the attestation public key using HpcrTextEncrypted
func (s *KeyService) encryptAttestationPublicKey(ctx context.Context, publicKey, encryptionCertPEM string) (string, error) {
	return s.engine.EncryptString(ctx, publicKey, encryptionCertPEM)
}

func (s *KeyService) RegisterSigningKey(
	ctx context.Context,
	buildID, actorID uuid.UUID,
	mode model.BuildKeyMode,
	publicKey *string,
	passphrase *string,
	ip string,
	actorRoles []string,
	requestSignature *string,
	requestSignatureHash *string,
) (*KeyRegistrationResult, error) {
	if err := s.ensureBuildAndAuditorAssignment(ctx, buildID, actorID); err != nil {
		return nil, err
	}

	providerRecord, err := s.keyProvider.CreateSigningKey(ctx, buildID, actorID, mode, publicKey, passphrase)
	if err != nil {
		return nil, err
	}

	record, err := s.store.createBuildKey(ctx, buildKeyRow{
		ID:                   providerRecord.ID,
		BuildID:              buildID,
		KeyType:              model.BuildKeyTypeSigning,
		Mode:                 mode,
		Status:               model.BuildKeyStatusActive,
		PublicKey:            providerRecord.PublicKey,
		PublicKeyFingerprint: providerRecord.PublicKeyFingerprint,
		CreatedBy:            actorID,
	})
	if err != nil {
		return nil, err
	}

	if err := s.storePrivateKey(ctx, providerRecord); err != nil {
		return nil, err
	}

	// Status transition will log the audit event, so we don't log it here to avoid duplicates
	if err := s.moveToSigningKeyRegistered(ctx, buildID, actorID, actorRoles, ip, requestSignature, requestSignatureHash); err != nil {
		return nil, err
	}

	return &KeyRegistrationResult{
		KeyID:       record.ID,
		PublicKey:   record.PublicKey,
		Fingerprint: record.PublicKeyFingerprint,
		Mode:        string(record.Mode),
		KeyType:     string(record.KeyType),
	}, nil
}

func (s *KeyService) RegisterAttestationKey(
	ctx context.Context,
	buildID, actorID uuid.UUID,
	mode model.BuildKeyMode,
	publicKey *string,
	passphrase *string,
	encryptionCertPEM *string,
	ip string,
	actorRoles []string,
	requestSignature *string,
	requestSignatureHash *string,
) (*KeyRegistrationResult, *keymgmt.OneTimePrivateExport, error) {
	if err := s.ensureBuildAndAuditorAssignment(ctx, buildID, actorID); err != nil {
		return nil, nil, err
	}

	providerRecord, exportToken, err := s.keyProvider.CreateAttestationKey(ctx, buildID, actorID, mode, publicKey, passphrase)
	if err != nil {
		return nil, nil, err
	}

	// Encrypt the attestation public key using the provided encryption certificate
	encryptedPublicKey := providerRecord.PublicKey
	if encryptionCertPEM != nil && strings.TrimSpace(*encryptionCertPEM) != "" {
		encrypted, err := s.encryptAttestationPublicKey(ctx, providerRecord.PublicKey, *encryptionCertPEM)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to encrypt attestation public key: %w", err)
		}
		encryptedPublicKey = encrypted
	}

	record, err := s.store.createBuildKey(ctx, buildKeyRow{
		ID:                   providerRecord.ID,
		BuildID:              buildID,
		KeyType:              model.BuildKeyTypeAttestation,
		Mode:                 mode,
		Status:               model.BuildKeyStatusActive,
		PublicKey:            encryptedPublicKey,
		PublicKeyFingerprint: providerRecord.PublicKeyFingerprint,
		CreatedBy:            actorID,
	})
	if err != nil {
		return nil, nil, err
	}

	if err := s.storePrivateKey(ctx, providerRecord); err != nil {
		return nil, nil, err
	}

	// Status transition will log the audit event, so we don't log it here to avoid duplicates
	if err := s.moveToAttestationKeyRegistered(ctx, buildID, actorID, actorRoles, ip, requestSignature, requestSignatureHash); err != nil {
		return nil, nil, err
	}

	return &KeyRegistrationResult{
		KeyID:       record.ID,
		PublicKey:   record.PublicKey,
		Fingerprint: record.PublicKeyFingerprint,
		Mode:        string(record.Mode),
		KeyType:     string(record.KeyType),
	}, exportToken, nil
}

// storePrivateKey persists generated private key material after the build_keys row is created.
func (s *KeyService) storePrivateKey(ctx context.Context, record keymgmt.KeyRecord) error {
	if len(record.EncryptedPrivateKey) == 0 {
		return nil
	}
	if err := s.queries.StoreBuildKeyPrivate(ctx, repository.StoreBuildKeyPrivateParams{
		KeyID:          record.ID,
		EncryptedKey:   record.EncryptedPrivateKey,
		EncryptionAlgo: "aes-256-cbc",
	}); err != nil {
		return fmt.Errorf("failed to store encrypted private key: %w", err)
	}
	return nil
}

func (s *KeyService) GetLatestSigningPublicKey(ctx context.Context, buildID, actorID uuid.UUID, actorRoles []string) (*KeyRegistrationResult, error) {
	if !hasRole(actorRoles, model.RoleAdmin.String()) {
		// Assigned DATA_OWNER and AUDITOR can access this for workflow composition.
		if err := s.assignmentService.ValidateAssignmentForSubmission(ctx, buildID, actorID, model.RoleDataOwner.String()); err != nil {
			if errAuditor := s.assignmentService.ValidateAssignmentForSubmission(ctx, buildID, actorID, model.RoleAuditor.String()); errAuditor != nil {
				return nil, model.ErrForbidden("only assigned DATA_OWNER or AUDITOR can fetch signing public key")
			}
		}
	}

	row, err := s.store.getLatestActiveBuildKeyByType(ctx, buildID, model.BuildKeyTypeSigning)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no rows") {
			return nil, model.ErrNotFound("signing key not found")
		}
		return nil, fmt.Errorf("failed to fetch signing key: %w", err)
	}
	return &KeyRegistrationResult{
		KeyID:       row.ID,
		PublicKey:   row.PublicKey,
		Fingerprint: row.PublicKeyFingerprint,
		Mode:        string(row.Mode),
		KeyType:     string(row.KeyType),
	}, nil
}

func (s *KeyService) GetBuildKey(ctx context.Context, keyID uuid.UUID) (*buildKeyRow, error) {
	return s.store.getBuildKeyByID(ctx, keyID)
}

func (s *KeyService) ensureBuildAndAuditorAssignment(ctx context.Context, buildID, actorID uuid.UUID) error {
	if _, err := s.queries.GetBuildByID(ctx, buildID); err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "no rows") {
			return model.ErrNotFound("build not found")
		}
		return fmt.Errorf("failed to load build: %w", err)
	}
	if err := s.assignmentService.ValidateAssignmentForSubmission(ctx, buildID, actorID, model.RoleAuditor.String()); err != nil {
		return err
	}
	return nil
}

// moveToSigningKeyRegistered transitions the build from CREATED to SIGNING_KEY_REGISTERED.
func (s *KeyService) moveToSigningKeyRegistered(
	ctx context.Context,
	buildID, actorID uuid.UUID,
	actorRoles []string,
	ip string,
	requestSignature *string,
	requestSignatureHash *string,
) error {
	build, err := s.queries.GetBuildByID(ctx, buildID)
	if err != nil {
		return nil
	}
	currentStatus := model.BuildStatus(build.Status)
	if currentStatus != model.StatusCreated {
		return nil
	}
	return s.buildService.TransitionStatus(
		ctx,
		buildID,
		model.StatusSigningKeyRegistered,
		actorID,
		ip,
		actorRoles,
		requestSignature,
		requestSignatureHash,
	)
}

// moveToAttestationKeyRegistered transitions the build from ENVIRONMENT_STAGED to ATTESTATION_KEY_REGISTERED.
func (s *KeyService) moveToAttestationKeyRegistered(
	ctx context.Context,
	buildID, actorID uuid.UUID,
	actorRoles []string,
	ip string,
	requestSignature *string,
	requestSignatureHash *string,
) error {
	build, err := s.queries.GetBuildByID(ctx, buildID)
	if err != nil {
		return nil
	}
	currentStatus := model.BuildStatus(build.Status)
	if currentStatus != model.StatusEnvironmentStaged {
		return nil
	}
	return s.buildService.TransitionStatus(
		ctx,
		buildID,
		model.StatusAttestationKeyRegistered,
		actorID,
		ip,
		actorRoles,
		requestSignature,
		requestSignatureHash,
	)
}
