package handler

import (
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/ibm-hyper-protect/contract-manager/internal/middleware"
	"github.com/ibm-hyper-protect/contract-manager/internal/model"
	"github.com/ibm-hyper-protect/contract-manager/internal/service"
)

// AttestationHandler handles attestation evidence upload and verification endpoints.
type AttestationHandler struct {
	attestationService *service.AttestationService
	systemLogService   *service.SystemLogService
}

type uploadEvidenceJSONRequest struct {
	RecordsFileName        string                 `json:"records_file_name"`
	RecordsContent         string                 `json:"records_content"`
	RecordsContentBase64   string                 `json:"records_content_base64"`
	SignatureFileName      string                 `json:"signature_file_name"`
	SignatureContent       string                 `json:"signature_content"`
	SignatureContentBase64 string                 `json:"signature_content_base64"`
	Metadata               map[string]interface{} `json:"metadata"`
}

type verifyEvidenceRequest struct {
	AttestationKeyPassphrase  string `json:"attestation_key_passphrase"`
	AttestationCertificatePEM string `json:"attestation_certificate_pem"`
}

// NewAttestationHandler creates a new AttestationHandler.
func NewAttestationHandler(attestationService *service.AttestationService, systemLogService *service.SystemLogService) *AttestationHandler {
	return &AttestationHandler{
		attestationService: attestationService,
		systemLogService:   systemLogService,
	}
}

// UploadEvidence handles POST /builds/{id}/attestation/evidence
// Accepts either:
// - multipart/form-data with records_file and signature_file fields, or
// - application/json with records_content/signature_content payload fields.
func (h *AttestationHandler) UploadEvidence(w http.ResponseWriter, r *http.Request) {
	buildID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, model.ErrInvalidRequest("Invalid build ID."))
		return
	}

	var (
		recordsFileName   string
		recordsContent    []byte
		signatureFileName string
		signatureContent  []byte
		metadata          = make(map[string]interface{})
	)

	contentType := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type")))
	if strings.Contains(contentType, "multipart/form-data") {
		// Parse multipart form (max 10MB total)
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			writeError(w, model.ErrInvalidRequest("Invalid multipart form: "+err.Error()))
			return
		}

		recordsFile, recordsHeader, err := r.FormFile("records_file")
		if err != nil {
			writeError(w, model.ErrInvalidRequest("records_file is required."))
			return
		}
		defer recordsFile.Close()

		signatureFile, signatureHeader, err := r.FormFile("signature_file")
		if err != nil {
			writeError(w, model.ErrInvalidRequest("signature_file is required."))
			return
		}
		defer signatureFile.Close()

		recordsContent, err = io.ReadAll(recordsFile)
		if err != nil {
			writeError(w, model.ErrInvalidRequest("Failed to read records file."))
			return
		}
		signatureContent, err = io.ReadAll(signatureFile)
		if err != nil {
			writeError(w, model.ErrInvalidRequest("Failed to read signature file."))
			return
		}

		recordsFileName = sanitizeFileName(recordsHeader.Filename)
		signatureFileName = sanitizeFileName(signatureHeader.Filename)

		// Build optional metadata from multipart form fields
		for key, values := range r.MultipartForm.Value {
			if key == "records_file" || key == "signature_file" {
				continue
			}
			if len(values) == 1 {
				metadata[key] = values[0]
			} else {
				metadata[key] = values
			}
		}
	} else {
		var req uploadEvidenceJSONRequest
		if err := readJSONLarge(r, &req, 10<<20); err != nil {
			writeError(w, model.ErrInvalidRequest(err.Error()))
			return
		}

		recordsContent, err = decodeUploadContent(req.RecordsContent, req.RecordsContentBase64)
		if err != nil {
			writeError(w, model.ErrInvalidRequest("records_content_base64 must be valid base64."))
			return
		}
		signatureContent, err = decodeUploadContent(req.SignatureContent, req.SignatureContentBase64)
		if err != nil {
			writeError(w, model.ErrInvalidRequest("signature_content_base64 must be valid base64."))
			return
		}

		if len(recordsContent) == 0 {
			writeError(w, model.ErrInvalidRequest("records_content (or records_content_base64) is required."))
			return
		}
		if len(signatureContent) == 0 {
			writeError(w, model.ErrInvalidRequest("signature_content (or signature_content_base64) is required."))
			return
		}

		recordsFileName = sanitizeFileName(req.RecordsFileName)
		if recordsFileName == "" {
			recordsFileName = "attestation-records.txt"
		}
		signatureFileName = sanitizeFileName(req.SignatureFileName)
		if signatureFileName == "" {
			signatureFileName = "attestation-signature.sig"
		}
		if req.Metadata != nil {
			metadata = req.Metadata
		}
	}

	actorID, _ := middleware.GetUserID(r.Context())
	actorRoles := middleware.GetUserRoles(r.Context())
	ip := requestIP(r)
	sig := middleware.GetRequestSignature(r.Context())
	sigHash := middleware.GetRequestSignatureHash(r.Context())
	var sigPtr, sigHashPtr *string
	if sig != "" {
		sigPtr = &sig
	}
	if sigHash != "" {
		sigHashPtr = &sigHash
	}

	result, err := h.attestationService.UploadEvidence(r.Context(), service.UploadAttestationEvidenceInput{
		BuildID:              buildID,
		ActorID:              actorID,
		ActorRoles:           actorRoles,
		ActorIP:              ip,
		RequestSignature:     sigPtr,
		RequestSignatureHash: sigHashPtr,
		RecordsFileName:      recordsFileName,
		RecordsContent:       recordsContent,
		SignatureFileName:    signatureFileName,
		SignatureContent:     signatureContent,
		Metadata:             metadata,
	})
	if err != nil {
		logSystemEvent(h.systemLogService, r, "unknown", "ATTESTATION_EVIDENCE_UPLOADED", "Build: "+buildID.String(), "FAILED", "Failed to upload attestation evidence: "+err.Error())
		if appErr, ok := err.(*model.AppError); ok {
			writeError(w, appErr)
			return
		}
		writeError(w, model.ErrInternal("Failed to upload attestation evidence."))
		return
	}

	logSystemEvent(h.systemLogService, r, "unknown", "ATTESTATION_EVIDENCE_UPLOADED", "Build: "+buildID.String(), "SUCCESS", "Uploaded attestation evidence")
	writeJSON(w, http.StatusCreated, result)
}

// VerifyEvidence handles POST /builds/{id}/attestation/evidence/{evidence_id}/verify
func (h *AttestationHandler) VerifyEvidence(w http.ResponseWriter, r *http.Request) {
	buildID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, model.ErrInvalidRequest("Invalid build ID."))
		return
	}

	evidenceID, err := uuid.Parse(chi.URLParam(r, "evidence_id"))
	if err != nil {
		writeError(w, model.ErrInvalidRequest("Invalid evidence ID."))
		return
	}

	var req verifyEvidenceRequest
	if r.ContentLength != 0 {
		if err := readJSONLarge(r, &req, 1<<20); err != nil && !errors.Is(err, io.EOF) {
			writeError(w, model.ErrInvalidRequest(err.Error()))
			return
		}
	}

	actorID, _ := middleware.GetUserID(r.Context())
	ip := requestIP(r)
	sig := middleware.GetRequestSignature(r.Context())
	sigHash := middleware.GetRequestSignatureHash(r.Context())
	var sigPtr, sigHashPtr *string
	if sig != "" {
		sigPtr = &sig
	}
	if sigHash != "" {
		sigHashPtr = &sigHash
	}

	result, err := h.attestationService.VerifyEvidence(r.Context(), service.VerifyAttestationEvidenceInput{
		BuildID:                   buildID,
		EvidenceID:                evidenceID,
		ActorID:                   actorID,
		ActorIP:                   ip,
		AttestationKeyPassphrase:  req.AttestationKeyPassphrase,
		AttestationCertificatePEM: req.AttestationCertificatePEM,
		RequestSignature:          sigPtr,
		RequestSignatureHash:      sigHashPtr,
	})
	if err != nil {
		logSystemEvent(h.systemLogService, r, "unknown", "ATTESTATION_VERIFIED", "Build: "+buildID.String(), "FAILED", "Failed to verify attestation: "+err.Error())
		if appErr, ok := err.(*model.AppError); ok {
			writeError(w, appErr)
			return
		}
		writeError(w, model.ErrInternal("Failed to verify attestation evidence."))
		return
	}

	logSystemEvent(h.systemLogService, r, "unknown", "ATTESTATION_VERIFIED", "Build: "+buildID.String(), "SUCCESS", "Verified attestation evidence: "+string(result.Verdict))
	writeJSON(w, http.StatusOK, result)
}

// GetVerificationStatus handles GET /builds/{id}/attestation/status
func (h *AttestationHandler) GetVerificationStatus(w http.ResponseWriter, r *http.Request) {
	buildID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, model.ErrInvalidRequest("Invalid build ID."))
		return
	}

	status, err := h.attestationService.GetVerificationStatus(r.Context(), buildID)
	if err != nil {
		if appErr, ok := err.(*model.AppError); ok {
			writeError(w, appErr)
			return
		}
		writeError(w, model.ErrInternal("Failed to get attestation status."))
		return
	}

	writeJSON(w, http.StatusOK, status)
}

// sanitizeFileName strips directory paths from uploaded file names.
func sanitizeFileName(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	parts := strings.Split(name, "/")
	return parts[len(parts)-1]
}

func decodeUploadContent(textPayload, base64Payload string) ([]byte, error) {
	trimmedBase64 := strings.TrimSpace(base64Payload)
	if trimmedBase64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(trimmedBase64)
		if err != nil {
			return nil, err
		}
		return decoded, nil
	}
	return []byte(textPayload), nil
}
