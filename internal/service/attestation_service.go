package service

import (
	"context"
	"encoding/base64"
	"strings"
	"time"

	"github.com/google/uuid"

	contractengine "github.com/ibm-hyper-protect/contract-manager/internal/contract"
	appcrypto "github.com/ibm-hyper-protect/contract-manager/internal/crypto"
	"github.com/ibm-hyper-protect/contract-manager/internal/model"
	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
)

// AttestationService handles evidence uploads and verification.
type AttestationService struct {
	queries           repository.Querier
	assignmentService *AssignmentService
	auditService      *AuditService
	keyProvider       interface {
		GetPrivateKey(ctx context.Context, keyID uuid.UUID) ([]byte, error)
	}
	engine contractengine.Engine
	store  *v2Store
}

func NewAttestationService(
	queries repository.Querier,
	db repository.DBTX,
	assignmentService *AssignmentService,
	auditService *AuditService,
	keyProvider interface {
		GetPrivateKey(ctx context.Context, keyID uuid.UUID) ([]byte, error)
	},
	engine contractengine.Engine,
) *AttestationService {
	return &AttestationService{
		queries:           queries,
		assignmentService: assignmentService,
		auditService:      auditService,
		keyProvider:       keyProvider,
		engine:            engine,
		store:             newV2Store(db),
	}
}

type UploadAttestationEvidenceInput struct {
	BuildID              uuid.UUID
	ActorID              uuid.UUID
	ActorRoles           []string
	ActorIP              string
	RequestSignature     *string
	RequestSignatureHash *string
	RecordsFileName      string
	RecordsContent       []byte
	SignatureFileName    string
	SignatureContent     []byte
	Metadata             map[string]interface{}
}

type AttestationEvidenceUploadResult struct {
	EvidenceID        uuid.UUID `json:"evidence_id"`
	BuildID           uuid.UUID `json:"build_id"`
	UploadedBy        uuid.UUID `json:"uploaded_by"`
	RecordsFileName   string    `json:"records_file_name"`
	SignatureFileName string    `json:"signature_file_name"`
	CreatedAt         time.Time `json:"created_at"`
	State             string    `json:"state"` // backward-compatible alias
}

type VerifyAttestationEvidenceInput struct {
	BuildID                  uuid.UUID
	EvidenceID               uuid.UUID
	ActorID                  uuid.UUID
	ActorIP                  string
	AttestationKeyPassphrase string
	// AttestationCertificatePEM is the IBM attestation certificate that signed the records.
	AttestationCertificatePEM string
	RequestSignature          *string
	RequestSignatureHash      *string
}

type VerifyAttestationEvidenceResult struct {
	VerificationID uuid.UUID              `json:"verification_id"`
	EvidenceID     uuid.UUID              `json:"evidence_id"`
	Verdict        string                 `json:"verdict"`
	State          string                 `json:"state"` // backward-compatible alias
	Details        map[string]interface{} `json:"details"`
	VerifiedAt     time.Time              `json:"verified_at"`
}

type AttestationVerificationStatus struct {
	BuildID          uuid.UUID              `json:"build_id"`
	AttestationState string                 `json:"attestation_state"`
	EvidenceCount    int64                  `json:"evidence_count"`
	LatestVerdict    *string                `json:"latest_verdict,omitempty"`
	VerifiedAt       *time.Time             `json:"verified_at,omitempty"`
	VerifiedBy       *uuid.UUID             `json:"verified_by,omitempty"`
	LastResult       map[string]interface{} `json:"last_result,omitempty"` // backward-compatible details bundle
	State            string                 `json:"state"`                 // backward-compatible alias
}

func (s *AttestationService) UploadEvidence(ctx context.Context, in UploadAttestationEvidenceInput) (*AttestationEvidenceUploadResult, error) {
	build, err := s.queries.GetBuildByID(ctx, in.BuildID)
	if err != nil {
		return nil, model.ErrNotFound("build not found")
	}
	buildStatus := model.BuildStatus(build.Status)
	if buildStatus != model.StatusFinalized && buildStatus != model.StatusContractDownloaded {
		return nil, model.ErrInvalidRequest("attestation evidence can only be uploaded after build finalization")
	}

	state, _, _, err := s.store.getBuildAttestationState(ctx, in.BuildID)
	if err != nil {
		return nil, model.ErrNotFound("build not found")
	}
	if state != model.AttestationStatePendingUpload && state != model.AttestationStateRejected {
		return nil, model.ErrInvalidRequest("attestation evidence upload is only allowed when state is PENDING_UPLOAD or REJECTED")
	}

	role, err := s.validateUploaderRole(ctx, in.BuildID, in.ActorID)
	if err != nil {
		return nil, err
	}
	if len(in.RecordsContent) == 0 || len(in.SignatureContent) == 0 {
		return nil, model.ErrInvalidRequest("records and signature files are required")
	}

	row, err := s.store.createAttestationEvidence(ctx, attestationEvidenceRow{
		BuildID:           in.BuildID,
		UploadedBy:        in.ActorID,
		UploaderRole:      role,
		RecordsFileName:   in.RecordsFileName,
		RecordsContent:    in.RecordsContent,
		SignatureFileName: in.SignatureFileName,
		SignatureContent:  in.SignatureContent,
		Metadata:          in.Metadata,
	})
	if err != nil {
		return nil, err
	}

	if err := s.store.updateBuildAttestationState(ctx, in.BuildID, model.AttestationStateUploaded, nil, nil); err != nil {
		return nil, err
	}

	eventData := map[string]string{
		"evidence_id":    row.ID.String(),
		"uploader_role":  role.String(),
		"records_file":   row.RecordsFileName,
		"signature_file": row.SignatureFileName,
	}
	if in.RequestSignatureHash != nil && *in.RequestSignatureHash != "" {
		eventData["request_signature_hash"] = *in.RequestSignatureHash
	}
	_, _ = s.auditService.LogEvent(ctx, LogEventInput{
		BuildID:     in.BuildID,
		EventType:   model.EventAttestationUploaded,
		ActorUserID: in.ActorID,
		IpAddress:   in.ActorIP,
		EventData:   eventData,
		Signature:   in.RequestSignature,
	})

	return &AttestationEvidenceUploadResult{
		EvidenceID:        row.ID,
		BuildID:           row.BuildID,
		UploadedBy:        row.UploadedBy,
		RecordsFileName:   row.RecordsFileName,
		SignatureFileName: row.SignatureFileName,
		CreatedAt:         row.CreatedAt,
		State:             model.AttestationStateUploaded.String(),
	}, nil
}

func (s *AttestationService) VerifyEvidence(ctx context.Context, in VerifyAttestationEvidenceInput) (*VerifyAttestationEvidenceResult, error) {
	build, err := s.queries.GetBuildByID(ctx, in.BuildID)
	if err != nil {
		return nil, model.ErrNotFound("build not found")
	}
	buildStatus := model.BuildStatus(build.Status)
	if buildStatus != model.StatusFinalized && buildStatus != model.StatusContractDownloaded {
		return nil, model.ErrInvalidRequest("attestation verification is only available after build finalization")
	}

	attestationState, _, _, err := s.store.getBuildAttestationState(ctx, in.BuildID)
	if err != nil {
		return nil, model.ErrNotFound("build not found")
	}
	if attestationState != model.AttestationStateUploaded {
		return nil, model.ErrInvalidRequest("attestation verification requires attestation_state=UPLOADED")
	}

	if err := s.assignmentService.ValidateAssignmentForSubmission(ctx, in.BuildID, in.ActorID, model.RoleAuditor.String()); err != nil {
		return nil, err
	}

	attestationCert := strings.TrimSpace(in.AttestationCertificatePEM)
	if attestationCert == "" {
		return nil, model.ErrInvalidRequest("attestation_certificate_pem is required to verify the attestation records signature")
	}
	if _, err := appcrypto.ParseCertificatePEM(attestationCert); err != nil {
		return nil, model.ErrInvalidRequest("attestation_certificate_pem must be a PEM-encoded X.509 certificate")
	}

	evidence, err := s.store.getAttestationEvidenceByID(ctx, in.EvidenceID)
	if err != nil {
		return nil, model.ErrNotFound("attestation evidence not found")
	}
	if evidence.BuildID != in.BuildID {
		return nil, model.ErrInvalidRequest("evidence does not belong to the specified build")
	}

	keyRow, err := s.store.getLatestActiveBuildKeyByType(ctx, in.BuildID, model.BuildKeyTypeAttestation)
	if err != nil {
		return nil, model.ErrInvalidRequest("attestation key not found for this build")
	}

	verdict := model.AttestationVerdictVerified
	signatureBase64 := normalizeSignaturePayload(evidence.SignatureContent)
	details := map[string]interface{}{
		"attestation_key_id": keyRow.ID.String(),
		"key_fingerprint":    keyRow.PublicKeyFingerprint,
		"records_decrypted":  false,
		"signature_valid":    false,
	}

	privateKeyPEM, err := s.keyProvider.GetPrivateKey(ctx, keyRow.ID)
	if err != nil {
		verdict = model.AttestationVerdictRejected
		details["reason"] = "attestation private key is unavailable (requires generated key with passphrase)"
	} else {
		defer zeroizeBytes(privateKeyPEM)
		recordsText, decryptErr := s.engine.HpcrGetAttestationRecords(ctx, string(evidence.RecordsContent), string(privateKeyPEM), strings.TrimSpace(in.AttestationKeyPassphrase))
		if decryptErr != nil {
			verdict = model.AttestationVerdictRejected
			details["reason"] = decryptErr.Error()
		} else {
			details["records_decrypted"] = true
			recordsHash := appcrypto.SHA256HexString(recordsText)
			details["records_hash"] = recordsHash
			// The records are signed by IBM's attestation key; the build's attestation key only encrypts them.
			verifyErr := s.engine.HpcrVerifySignatureAttestationRecords(ctx, recordsText, signatureBase64, attestationCert)
			if verifyErr != nil {
				verdict = model.AttestationVerdictRejected
				details["reason"] = verifyErr.Error()
			} else {
				details["signature_valid"] = true
			}
		}
	}

	// Fallback hash for observability when decryption is not possible.
	if _, ok := details["records_hash"]; !ok {
		details["records_hash"] = appcrypto.SHA256Hex(evidence.RecordsContent)
	}

	now := time.Now().UTC()
	verification, err := s.store.createAttestationVerification(ctx, attestationVerificationRow{
		BuildID:    in.BuildID,
		EvidenceID: in.EvidenceID,
		VerifiedBy: in.ActorID,
		Verdict:    verdict,
		Details:    details,
	})
	if err != nil {
		return nil, err
	}

	var nextState model.AttestationState
	if verdict == model.AttestationVerdictVerified {
		nextState = model.AttestationStateVerified
	} else {
		nextState = model.AttestationStateRejected
	}
	if err := s.store.updateBuildAttestationState(ctx, in.BuildID, nextState, &now, &in.ActorID); err != nil {
		return nil, err
	}

	eventData := map[string]string{
		"evidence_id":     in.EvidenceID.String(),
		"verification_id": verification.ID.String(),
		"verdict":         string(verdict),
	}
	if in.RequestSignatureHash != nil && *in.RequestSignatureHash != "" {
		eventData["request_signature_hash"] = *in.RequestSignatureHash
	}
	_, _ = s.auditService.LogEvent(ctx, LogEventInput{
		BuildID:     in.BuildID,
		EventType:   model.EventAttestationVerified,
		ActorUserID: in.ActorID,
		IpAddress:   in.ActorIP,
		EventData:   eventData,
		Signature:   in.RequestSignature,
	})

	return &VerifyAttestationEvidenceResult{
		VerificationID: verification.ID,
		EvidenceID:     in.EvidenceID,
		Verdict:        string(verdict),
		State:          nextState.String(),
		Details:        details,
		VerifiedAt:     now,
	}, nil
}

func (s *AttestationService) GetVerificationStatus(ctx context.Context, buildID uuid.UUID) (*AttestationVerificationStatus, error) {
	state, verifiedAt, verifiedBy, err := s.store.getBuildAttestationState(ctx, buildID)
	if err != nil {
		return nil, model.ErrNotFound("build not found")
	}

	evidenceCount, err := s.store.countAttestationEvidenceByBuildID(ctx, buildID)
	if err != nil {
		return nil, err
	}

	status := &AttestationVerificationStatus{
		BuildID:          buildID,
		AttestationState: state.String(),
		EvidenceCount:    evidenceCount,
		VerifiedAt:       verifiedAt,
		VerifiedBy:       verifiedBy,
		State:            state.String(),
	}

	latest, err := s.store.getLatestAttestationVerification(ctx, buildID)
	if err == nil {
		verdict := latest.Verdict.String()
		status.LatestVerdict = &verdict
		status.LastResult = map[string]interface{}{
			"verification_id": latest.ID.String(),
			"evidence_id":     latest.EvidenceID.String(),
			"verdict":         latest.Verdict,
			"details":         latest.Details,
			"created_at":      latest.CreatedAt,
		}
	}
	return status, nil
}

func (s *AttestationService) validateUploaderRole(ctx context.Context, buildID, actorID uuid.UUID) (model.PersonaRole, error) {
	if err := s.assignmentService.ValidateAssignmentForSubmission(ctx, buildID, actorID, model.RoleDataOwner.String()); err == nil {
		return model.RoleDataOwner, nil
	}
	if err := s.assignmentService.ValidateAssignmentForSubmission(ctx, buildID, actorID, model.RoleEnvOperator.String()); err == nil {
		return model.RoleEnvOperator, nil
	}
	return "", model.ErrForbidden("only assigned DATA_OWNER or ENV_OPERATOR can upload attestation evidence")
}

func normalizeSignaturePayload(signatureBytes []byte) string {
	sigText := strings.TrimSpace(string(signatureBytes))
	if sigText != "" {
		if _, err := base64.StdEncoding.DecodeString(sigText); err == nil {
			return sigText
		}
	}
	return base64.StdEncoding.EncodeToString(signatureBytes)
}
