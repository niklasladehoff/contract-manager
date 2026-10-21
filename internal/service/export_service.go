package service

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/ibm-hyper-protect/contract-manager/internal/crypto"
	"github.com/ibm-hyper-protect/contract-manager/internal/model"
	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
)

// ExportService handles contract export and download operations.
type ExportService struct {
	queries           repository.Querier
	auditService      *AuditService
	assignmentService *AssignmentService
}

func decodeContractYAMLForUserData(contractYAML string) string {
	trimmed := strings.TrimSpace(contractYAML)
	if trimmed == "" {
		return ""
	}

	// Raw YAML path
	if strings.Contains(trimmed, "\n") ||
		strings.Contains(trimmed, "workload:") ||
		strings.Contains(trimmed, "env:") {
		return contractYAML
	}

	// Backward-compatible base64 path
	decodedYAML, err := base64.StdEncoding.DecodeString(trimmed)
	if err == nil {
		return string(decodedYAML)
	}

	// Fallback: return as-is instead of failing hard.
	return contractYAML
}

// NewExportService creates a new ExportService.
func NewExportService(queries repository.Querier, auditService *AuditService, assignmentService *AssignmentService) *ExportService {
	return &ExportService{
		queries:           queries,
		auditService:      auditService,
		assignmentService: assignmentService,
	}
}

func (s *ExportService) hasDownloadAcknowledgment(ctx context.Context, buildID uuid.UUID) (bool, error) {
	buildIDPg := pgtype.UUID{
		Bytes: buildID,
		Valid: true,
	}
	events, err := s.queries.GetAuditEventsByBuildID(ctx, buildIDPg)
	if err != nil {
		return false, err
	}

	for _, event := range events {
		if event.EventType == model.EventContractDownloaded.String() {
			return true, nil
		}
	}
	return false, nil
}

// ExportContractOutput contains the exported contract data.
type ExportContractOutput struct {
	ContractYAML string `json:"contract_yaml"` // base64-encoded
	ContractHash string `json:"contract_hash"`
	BuildID      string `json:"build_id"`
	BuildName    string `json:"build_name"`
	FinalizedAt  string `json:"finalized_at"`
}

// ExportContract returns the finalized contract for download.
// Only assigned ENV_OPERATOR can export.
func (s *ExportService) ExportContract(ctx context.Context, buildID, userID uuid.UUID) (*ExportContractOutput, error) {
	// 1. Get build
	build, err := s.queries.GetBuildByID(ctx, buildID)
	if err != nil {
		return nil, model.ErrBuildNotFound(buildID.String())
	}

	// 2. Verify build is in exportable state
	buildStatus := model.BuildStatus(build.Status)
	if buildStatus == model.StatusContractDownloaded {
		return nil, model.ErrInvalidRequest("contract has already been downloaded and acknowledged")
	}
	if buildStatus != model.StatusFinalized {
		return nil, model.ErrInvalidRequest("build must be finalized before export")
	}

	alreadyDownloaded, err := s.hasDownloadAcknowledgment(ctx, buildID)
	if err != nil {
		return nil, fmt.Errorf("failed to check prior download acknowledgment: %w", err)
	}
	if alreadyDownloaded {
		return nil, model.ErrInvalidRequest("contract has already been downloaded and acknowledged")
	}

	// 3. Verify contract exists
	if build.ContractYaml == nil || build.ContractHash == nil {
		return nil, model.ErrInvalidRequest("contract not available")
	}

	// 4. Verify user is assigned as ENV_OPERATOR
	isEnvOp, err := s.assignmentService.CheckUserAssignment(ctx, buildID, userID, "ENV_OPERATOR")
	if err != nil {
		return nil, fmt.Errorf("failed to check env operator assignment: %w", err)
	}
	if !isEnvOp {
		return nil, model.ErrForbidden("only assigned ENV_OPERATOR can export contract")
	}

	// 5. Return contract data
	return &ExportContractOutput{
		ContractYAML: *build.ContractYaml,
		ContractHash: *build.ContractHash,
		BuildID:      buildID.String(),
		BuildName:    build.Name,
		FinalizedAt:  build.FinalizedAt.Time.Format("2006-01-02T15:04:05Z07:00"),
	}, nil
}

// AcknowledgeDownloadInput contains data for download acknowledgment.
type AcknowledgeDownloadInput struct {
	BuildID      uuid.UUID
	UserID       uuid.UUID
	ContractHash string
	Signature    string // RSA-PSS signature of contract_hash
	IPAddress    string
	SigningKey   repository.UserPublicKey
}

// AcknowledgeDownload records that ENV_OPERATOR downloaded and verified the contract.
// This creates cryptographic proof-of-receipt in the audit chain.
func (s *ExportService) AcknowledgeDownload(ctx context.Context, input AcknowledgeDownloadInput) error {
	// 1. Get build
	build, err := s.queries.GetBuildByID(ctx, input.BuildID)
	if err != nil {
		return model.ErrBuildNotFound(input.BuildID.String())
	}

	// 2. Verify build is in downloadable state
	buildStatus := model.BuildStatus(build.Status)
	if buildStatus == model.StatusContractDownloaded {
		return model.ErrInvalidRequest("contract has already been downloaded and acknowledged")
	}
	if buildStatus != model.StatusFinalized {
		return model.ErrInvalidRequest("build must be finalized")
	}

	alreadyDownloaded, err := s.hasDownloadAcknowledgment(ctx, input.BuildID)
	if err != nil {
		return fmt.Errorf("failed to check prior download acknowledgment: %w", err)
	}
	if alreadyDownloaded {
		return model.ErrInvalidRequest("contract has already been downloaded and acknowledged")
	}

	// 3. Verify contract hash matches
	if build.ContractHash == nil || *build.ContractHash != input.ContractHash {
		return model.ErrHashMismatch(*build.ContractHash, input.ContractHash)
	}

	// 4. Verify user is assigned as ENV_OPERATOR
	isEnvOp, err := s.assignmentService.CheckUserAssignment(ctx, input.BuildID, input.UserID, "ENV_OPERATOR")
	if err != nil {
		return fmt.Errorf("failed to check env operator assignment: %w", err)
	}
	if !isEnvOp {
		return model.ErrForbidden("only assigned ENV_OPERATOR can acknowledge download")
	}

	// 5. Use the key verified by request signature middleware.
	key := input.SigningKey
	if key.ID == uuid.Nil || key.UserID != input.UserID {
		return model.ErrForbidden("A verified signing key belonging to the user is required.")
	}

	// 6. Verify the download receipt with the same key.
	err = crypto.VerifySignature(
		key.PublicKey,
		input.ContractHash,
		input.Signature,
	)
	if err != nil {
		return model.ErrInvalidSignature()
	}

	// 7. Reuse the fingerprint of the verified key.
	fingerprint := key.Fingerprint

	// 8. Log download acknowledgment to audit trail
	_, err = s.auditService.LogEvent(ctx, LogEventInput{
		BuildID:             input.BuildID,
		EventType:           model.EventContractDownloaded,
		ActorUserID:         input.UserID,
		ActorPublicKey:      &key.PublicKey,
		ActorKeyFingerprint: &key.Fingerprint,
		IpAddress:           input.IPAddress,
		Signature:           &input.Signature,
		EventData: map[string]string{
			"contract_hash":         input.ContractHash,
			"actor_key_fingerprint": fingerprint,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to log download acknowledgment: %w", err)
	}

	// 9. Move build into terminal "downloaded" status to prevent re-download.
	err = s.queries.UpdateBuildStatus(ctx, repository.UpdateBuildStatusParams{
		ID:     input.BuildID,
		Status: model.StatusContractDownloaded.String(),
	})
	if err != nil {
		return fmt.Errorf("download acknowledged but failed to update build status: %w", err)
	}

	return nil
}

// GetUserDataOutput contains the contract in raw YAML format for deployment.
type GetUserDataOutput struct {
	ContractYAML string `json:"contract_yaml"` // Raw YAML (decoded from base64)
	ContractHash string `json:"contract_hash"`
	BuildID      string `json:"build_id"`
}

// GetUserData returns the decoded contract YAML for ENV_OPERATOR deployment.
// This is the final step before deploying to HPCR instances.
func (s *ExportService) GetUserData(ctx context.Context, buildID, userID uuid.UUID) (*GetUserDataOutput, error) {
	// 1. Get build
	build, err := s.queries.GetBuildByID(ctx, buildID)
	if err != nil {
		return nil, model.ErrBuildNotFound(buildID.String())
	}

	// 2. Verify build is in downloadable state
	buildStatus := model.BuildStatus(build.Status)
	if buildStatus == model.StatusContractDownloaded {
		return nil, model.ErrInvalidRequest("contract has already been downloaded and acknowledged")
	}
	if buildStatus != model.StatusFinalized {
		return nil, model.ErrInvalidRequest("build must be finalized")
	}

	alreadyDownloaded, err := s.hasDownloadAcknowledgment(ctx, buildID)
	if err != nil {
		return nil, fmt.Errorf("failed to check prior download acknowledgment: %w", err)
	}
	if alreadyDownloaded {
		return nil, model.ErrInvalidRequest("contract has already been downloaded and acknowledged")
	}

	// 3. Verify contract exists
	if build.ContractYaml == nil || build.ContractHash == nil {
		return nil, model.ErrInvalidRequest("contract not available")
	}

	// 4. Verify user is assigned as ENV_OPERATOR
	isEnvOp, err := s.assignmentService.CheckUserAssignment(ctx, buildID, userID, "ENV_OPERATOR")
	if err != nil {
		return nil, fmt.Errorf("failed to check env operator assignment: %w", err)
	}
	if !isEnvOp {
		return nil, model.ErrForbidden("only assigned ENV_OPERATOR can get userdata")
	}

	// 5. Decode contract YAML if needed (supports raw YAML and base64-encoded YAML).
	decodedYAML := decodeContractYAMLForUserData(*build.ContractYaml)

	// 6. Return decoded YAML
	return &GetUserDataOutput{
		ContractYAML: decodedYAML,
		ContractHash: *build.ContractHash,
		BuildID:      buildID.String(),
	}, nil
}
