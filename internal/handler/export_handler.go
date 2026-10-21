package handler

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/ibm-hyper-protect/contract-manager/internal/middleware"
	"github.com/ibm-hyper-protect/contract-manager/internal/model"
	"github.com/ibm-hyper-protect/contract-manager/internal/service"
)

type ExportHandler struct {
	exportService       *service.ExportService
	verificationService *service.VerificationService
	systemLogService    *service.SystemLogService
}

func NewExportHandler(
	exportService *service.ExportService,
	verificationService *service.VerificationService,
	systemLogService *service.SystemLogService,
) *ExportHandler {
	return &ExportHandler{
		exportService:       exportService,
		verificationService: verificationService,
		systemLogService:    systemLogService,
	}
}

// ExportContract handles GET /builds/{id}/export
// @Summary Export finalized contract
// @Description Export the finalized contract (AUDITOR or ENV_OPERATOR only)
// @Tags export
// @Produce json
// @Param id path string true "Build ID"
// @Success 200 {object} service.ExportContractOutput
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /builds/{id}/export [get]
func (h *ExportHandler) ExportContract(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get build ID from URL
	buildIDStr := chi.URLParam(r, "id")
	buildID, err := uuid.Parse(buildIDStr)
	if err != nil {
		writeError(w, model.ErrInvalidRequest("Invalid build ID format"))
		return
	}

	// Get authenticated user
	userID, ok := middleware.GetUserID(ctx)
	if !ok {
		writeError(w, model.ErrUnauthorized())
		return
	}

	// Export contract
	output, err := h.exportService.ExportContract(ctx, buildID, userID)
	if err != nil {
		logSystemEvent(
			h.systemLogService,
			r,
			"unknown",
			"CONTRACT_EXPORTED",
			"Build: "+buildID.String(),
			"FAILED",
			"Failed to export contract: "+err.Error(),
		)
		if appErr, ok := err.(*model.AppError); ok {
			writeError(w, appErr)
		} else {
			writeError(w, model.ErrInternal("Failed to export contract"))
		}
		return
	}

	logSystemEvent(
		h.systemLogService,
		r,
		"unknown",
		"CONTRACT_EXPORTED",
		"Build: "+buildID.String(),
		"SUCCESS",
		"Exported finalized contract",
	)

	writeJSON(w, http.StatusOK, output)
}

// AcknowledgeDownloadRequest represents the request body for download acknowledgment.
type AcknowledgeDownloadRequest struct {
	ContractHash string `json:"contract_hash"`
	Signature    string `json:"signature"` // RSA-PSS signature of contract_hash
}

// AcknowledgeDownload handles POST /builds/{id}/acknowledge-download
// @Summary Acknowledge contract download
// @Description ENV_OPERATOR acknowledges download and verifies contract (creates proof-of-receipt)
// @Tags export
// @Accept json
// @Produce json
// @Param id path string true "Build ID"
// @Param request body AcknowledgeDownloadRequest true "Download acknowledgment"
// @Success 204 "No Content"
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /builds/{id}/acknowledge-download [post]
func (h *ExportHandler) AcknowledgeDownload(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get build ID from URL
	buildIDStr := chi.URLParam(r, "id")
	buildID, err := uuid.Parse(buildIDStr)
	if err != nil {
		writeError(w, model.ErrInvalidRequest("Invalid build ID format"))
		return
	}

	// Parse request body
	var req AcknowledgeDownloadRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, model.ErrInvalidRequest(err.Error()))
		return
	}

	// Validate required fields
	if req.ContractHash == "" {
		writeError(w, model.ErrInvalidRequest("contract_hash is required"))
		return
	}
	if req.Signature == "" {
		writeError(w, model.ErrInvalidRequest("signature is required"))
		return
	}

	// Get authenticated user
	userID, ok := middleware.GetUserID(ctx)
	if !ok {
		writeError(w, model.ErrUnauthorized())
		return
	}

	// Read the key verified by request signature middleware.
	key, ok := service.SigningKeyFromContext(ctx)
	if !ok || key.UserID != userID {
		writeError(w, model.ErrForbidden("A verified signing key is required."))
		return
	}

	// Acknowledge download
	err = h.exportService.AcknowledgeDownload(ctx, service.AcknowledgeDownloadInput{
		BuildID:      buildID,
		UserID:       userID,
		ContractHash: req.ContractHash,
		Signature:    req.Signature,
		IPAddress:    requestIP(r),
		SigningKey:   key,
	})
	if err != nil {
		logSystemEvent(
			h.systemLogService,
			r,
			"unknown",
			"CONTRACT_DOWNLOAD_ACKNOWLEDGED",
			"Build: "+buildID.String(),
			"FAILED",
			"Failed to acknowledge contract download: "+err.Error(),
		)
		if appErr, ok := err.(*model.AppError); ok {
			writeError(w, appErr)
		} else {
			writeError(w, model.ErrInternal("Failed to acknowledge download"))
		}
		return
	}

	logSystemEvent(
		h.systemLogService,
		r,
		"unknown",
		"CONTRACT_DOWNLOAD_ACKNOWLEDGED",
		"Build: "+buildID.String(),
		"SUCCESS",
		"Acknowledged contract download",
	)

	w.WriteHeader(http.StatusNoContent)
}

// GetUserData handles GET /builds/{id}/userdata
// @Summary Get contract userdata
// @Description Get decoded contract YAML for deployment (ENV_OPERATOR only)
// @Tags export
// @Produce json
// @Param id path string true "Build ID"
// @Success 200 {object} service.GetUserDataOutput
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 403 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /builds/{id}/userdata [get]
func (h *ExportHandler) GetUserData(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get build ID from URL
	buildIDStr := chi.URLParam(r, "id")
	buildID, err := uuid.Parse(buildIDStr)
	if err != nil {
		writeError(w, model.ErrInvalidRequest("Invalid build ID format"))
		return
	}

	// Get authenticated user
	userID, ok := middleware.GetUserID(ctx)
	if !ok {
		writeError(w, model.ErrUnauthorized())
		return
	}

	// Get userdata
	output, err := h.exportService.GetUserData(ctx, buildID, userID)
	if err != nil {
		logSystemEvent(
			h.systemLogService,
			r,
			"unknown",
			"CONTRACT_USERDATA_FETCHED",
			"Build: "+buildID.String(),
			"FAILED",
			"Failed to get userdata: "+err.Error(),
		)
		if appErr, ok := err.(*model.AppError); ok {
			writeError(w, appErr)
		} else {
			writeError(w, model.ErrInternal("Failed to get userdata"))
		}
		return
	}

	logSystemEvent(
		h.systemLogService,
		r,
		"unknown",
		"CONTRACT_USERDATA_FETCHED",
		"Build: "+buildID.String(),
		"SUCCESS",
		"Fetched contract userdata",
	)

	writeJSON(w, http.StatusOK, output)
}

// VerifyAuditChain handles GET /builds/{id}/verify
// @Summary Verify audit chain integrity
// @Description Verify the integrity of the audit hash chain for a build
// @Tags verification
// @Produce json
// @Param id path string true "Build ID"
// @Success 200 {object} service.VerificationResult
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /builds/{id}/verify [get]
func (h *ExportHandler) VerifyAuditChain(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get build ID from URL
	buildIDStr := chi.URLParam(r, "id")
	buildID, err := uuid.Parse(buildIDStr)
	if err != nil {
		writeError(w, model.ErrInvalidRequest("Invalid build ID format"))
		return
	}

	// Verify audit chain
	result, err := h.verificationService.VerifyBuildAuditChain(ctx, buildID)
	if err != nil {
		logSystemEvent(
			h.systemLogService,
			r,
			"unknown",
			"AUDIT_CHAIN_VERIFIED",
			"Build: "+buildID.String(),
			"FAILED",
			"Failed to verify audit chain: "+err.Error(),
		)
		if appErr, ok := err.(*model.AppError); ok {
			writeError(w, appErr)
		} else {
			writeError(w, model.ErrInternal("Failed to verify audit chain"))
		}
		return
	}

	logSystemEvent(
		h.systemLogService,
		r,
		"unknown",
		"AUDIT_CHAIN_VERIFIED",
		"Build: "+buildID.String(),
		"SUCCESS",
		"Verified audit chain",
	)

	writeJSON(w, http.StatusOK, result)
}

// VerifyContractIntegrity handles GET /builds/{id}/verify-contract
// @Summary Verify contract integrity
// @Description Verify the integrity of the finalized contract
// @Tags verification
// @Produce json
// @Param id path string true "Build ID"
// @Success 200 {object} service.ContractIntegrityResult
// @Failure 400 {object} ErrorResponse
// @Failure 401 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /builds/{id}/verify-contract [get]
func (h *ExportHandler) VerifyContractIntegrity(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get build ID from URL
	buildIDStr := chi.URLParam(r, "id")
	buildID, err := uuid.Parse(buildIDStr)
	if err != nil {
		writeError(w, model.ErrInvalidRequest("Invalid build ID format"))
		return
	}

	// Verify contract integrity
	result, err := h.verificationService.VerifyContractIntegrity(ctx, buildID)
	if err != nil {
		logSystemEvent(
			h.systemLogService,
			r,
			"unknown",
			"CONTRACT_INTEGRITY_VERIFIED",
			"Build: "+buildID.String(),
			"FAILED",
			"Failed to verify contract integrity: "+err.Error(),
		)
		if appErr, ok := err.(*model.AppError); ok {
			writeError(w, appErr)
		} else {
			writeError(w, model.ErrInternal("Failed to verify contract integrity"))
		}
		return
	}

	logSystemEvent(
		h.systemLogService,
		r,
		"unknown",
		"CONTRACT_INTEGRITY_VERIFIED",
		"Build: "+buildID.String(),
		"SUCCESS",
		"Verified contract integrity",
	)

	writeJSON(w, http.StatusOK, result)
}
