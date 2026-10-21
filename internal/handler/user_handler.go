package handler

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/ibm-hyper-protect/contract-manager/internal/middleware"
	"github.com/ibm-hyper-protect/contract-manager/internal/model"
	"github.com/ibm-hyper-protect/contract-manager/internal/service"
)

// UserHandler handles user management endpoints.
type UserHandler struct {
	userService      *service.UserService
	userKeyService   *service.UserKeyService
	systemLogService *service.SystemLogService
}

// NewUserHandler creates a new UserHandler.
func NewUserHandler(userService *service.UserService, userKeyService *service.UserKeyService, systemLogService *service.SystemLogService) *UserHandler {
	return &UserHandler{
		userService:      userService,
		userKeyService:   userKeyService,
		systemLogService: systemLogService,
	}
}

// ListUsers handles GET /users.
func (h *UserHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.userService.ListUsers(r.Context())
	if err != nil {
		writeError(w, model.ErrInternal("Failed to list users."))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"users": users})
}

// createUserRequest is the JSON request for POST /users.
type createUserRequest struct {
	Name     string   `json:"name"`
	Email    string   `json:"email"`
	Password string   `json:"password"`
	Roles    []string `json:"roles"`
}

// CreateUser handles POST /users.
func (h *UserHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, model.ErrInvalidRequest(err.Error()))
		return
	}

	if req.Name == "" || req.Email == "" || req.Password == "" {
		writeError(w, model.ErrInvalidRequest("Name, email, and password are required."))
		return
	}

	if len(req.Roles) == 0 {
		writeError(w, model.ErrInvalidRequest("At least one role is required."))
		return
	}

	// Validate roles
	for _, role := range req.Roles {
		if !model.PersonaRole(role).IsValid() {
			writeError(w, model.ErrInvalidRequest("Invalid role: "+role))
			return
		}
	}

	assignedBy, ok := middleware.GetUserID(r.Context())
	if !ok {
		writeError(w, model.ErrUnauthorized())
		return
	}

	user, err := h.userService.CreateUser(r.Context(), service.CreateUserInput{
		Name:     req.Name,
		Email:    req.Email,
		Password: req.Password,
		Roles:    req.Roles,
	}, assignedBy)
	if err != nil {
		logSystemEvent(
			h.systemLogService,
			r,
			req.Email,
			"USER_CREATED",
			"User Management",
			"FAILED",
			"Failed to create user: "+err.Error(),
		)
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			writeError(w, model.ErrDuplicateEmail(req.Email))
			return
		}
		writeError(w, model.ErrInternal("Failed to create user."))
		return
	}

	logSystemEvent(
		h.systemLogService,
		r,
		req.Email,
		"USER_CREATED",
		"User Management",
		"SUCCESS",
		"Created new user account",
	)

	writeJSON(w, http.StatusCreated, user)
}

// updateRolesRequest is the JSON request for PATCH /users/{id}/roles.
type updateRolesRequest struct {
	Roles []string `json:"roles"`
}

// updateProfileRequest is the JSON request for PATCH /users/{id}.
type updateProfileRequest struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// UpdateUserProfile handles PATCH /users/{id}.
func (h *UserHandler) UpdateUserProfile(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, model.ErrInvalidRequest("Invalid user ID."))
		return
	}

	var req updateProfileRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, model.ErrInvalidRequest(err.Error()))
		return
	}

	if req.Name == "" || req.Email == "" {
		writeError(w, model.ErrInvalidRequest("Name and email are required."))
		return
	}

	user, err := h.userService.UpdateUserProfile(r.Context(), userID, req.Name, req.Email)
	if err != nil {
		logSystemEvent(
			h.systemLogService,
			r,
			"unknown",
			"USER_PROFILE_UPDATED",
			"User: "+userID.String(),
			"FAILED",
			"Failed to update profile: "+err.Error(),
		)
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") || strings.Contains(strings.ToLower(err.Error()), "unique") {
			writeError(w, model.ErrDuplicateEmail(req.Email))
			return
		}
		if strings.Contains(strings.ToLower(err.Error()), "not found") {
			writeError(w, model.ErrUserNotFound(userID.String()))
			return
		}
		writeError(w, model.ErrInternal("Failed to update user profile."))
		return
	}

	logSystemEvent(
		h.systemLogService,
		r,
		"unknown",
		"USER_PROFILE_UPDATED",
		"User: "+userID.String(),
		"SUCCESS",
		"Updated user profile",
	)

	writeJSON(w, http.StatusOK, user)
}

// DeactivateUser handles DELETE /users/{id}.
func (h *UserHandler) DeactivateUser(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, model.ErrInvalidRequest("Invalid user ID."))
		return
	}

	err = h.userService.DeactivateUser(r.Context(), userID)
	if err != nil {
		logSystemEvent(
			h.systemLogService,
			r,
			"unknown",
			"USER_DEACTIVATED",
			"User: "+userID.String(),
			"FAILED",
			"Failed to deactivate user: "+err.Error(),
		)
		writeError(w, model.ErrInternal("Failed to deactivate user."))
		return
	}

	logSystemEvent(
		h.systemLogService,
		r,
		"unknown",
		"USER_DEACTIVATED",
		"User: "+userID.String(),
		"SUCCESS",
		"Deactivated user account",
	)

	writeJSON(w, http.StatusOK, map[string]string{"message": "User deactivated successfully."})
}

// UpdateRoles handles PATCH /users/{id}/roles.
func (h *UserHandler) UpdateRoles(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, model.ErrInvalidRequest("Invalid user ID."))
		return
	}

	var req updateRolesRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, model.ErrInvalidRequest(err.Error()))
		return
	}

	if len(req.Roles) == 0 {
		writeError(w, model.ErrInvalidRequest("At least one role is required."))
		return
	}

	assignedBy, ok := middleware.GetUserID(r.Context())
	if !ok {
		writeError(w, model.ErrUnauthorized())
		return
	}

	user, err := h.userService.UpdateRoles(r.Context(), userID, req.Roles, assignedBy)
	if err != nil {
		logSystemEvent(
			h.systemLogService,
			r,
			"unknown",
			"USER_ROLES_UPDATED",
			"User: "+userID.String(),
			"FAILED",
			"Failed to update roles: "+err.Error(),
		)
		if strings.Contains(err.Error(), "not found") {
			writeError(w, model.ErrUserNotFound(userID.String()))
			return
		}
		writeError(w, model.ErrInternal("Failed to update roles."))
		return
	}

	logSystemEvent(
		h.systemLogService,
		r,
		"unknown",
		"USER_ROLES_UPDATED",
		"User: "+userID.String(),
		"SUCCESS",
		"Updated user roles",
	)

	writeJSON(w, http.StatusOK, user)
}

// ListTokens handles GET /users/{id}/tokens.
func (h *UserHandler) ListTokens(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, model.ErrInvalidRequest("Invalid user ID."))
		return
	}

	tokens, err := h.userService.ListTokens(r.Context(), userID)
	if err != nil {
		writeError(w, model.ErrInternal("Failed to list tokens."))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"tokens": tokens})
}

// createTokenRequest is the JSON request for POST /users/{id}/tokens.
type createTokenRequest struct {
	Name string `json:"name"`
}

// CreateToken handles POST /users/{id}/tokens.
func (h *UserHandler) CreateToken(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, model.ErrInvalidRequest("Invalid user ID."))
		return
	}

	var req createTokenRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, model.ErrInvalidRequest(err.Error()))
		return
	}

	if req.Name == "" {
		writeError(w, model.ErrInvalidRequest("Token name is required."))
		return
	}

	result, err := h.userService.CreateToken(r.Context(), userID, req.Name)
	if err != nil {
		logSystemEvent(
			h.systemLogService,
			r,
			"unknown",
			"API_TOKEN_CREATED",
			"User: "+userID.String(),
			"FAILED",
			"Failed to create API token: "+err.Error(),
		)
		writeError(w, model.ErrInternal("Failed to create token."))
		return
	}

	logSystemEvent(
		h.systemLogService,
		r,
		"unknown",
		"API_TOKEN_CREATED",
		"User: "+userID.String(),
		"SUCCESS",
		"Created API token",
	)

	writeJSON(w, http.StatusCreated, result)
}

// RevokeToken handles DELETE /users/{id}/tokens/{token_id}.
func (h *UserHandler) RevokeToken(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, model.ErrInvalidRequest("Invalid user ID."))
		return
	}

	tokenID, err := uuid.Parse(chi.URLParam(r, "token_id"))
	if err != nil {
		writeError(w, model.ErrInvalidRequest("Invalid token ID."))
		return
	}

	if err := h.userService.RevokeToken(r.Context(), userID, tokenID); err != nil {
		logSystemEvent(
			h.systemLogService,
			r,
			"unknown",
			"API_TOKEN_REVOKED",
			"User: "+userID.String(),
			"FAILED",
			"Failed to revoke API token: "+err.Error(),
		)
		writeError(w, model.ErrInternal("Failed to revoke token."))
		return
	}

	logSystemEvent(
		h.systemLogService,
		r,
		"unknown",
		"API_TOKEN_REVOKED",
		"User: "+userID.String(),
		"SUCCESS",
		"Revoked API token",
	)

	w.WriteHeader(http.StatusNoContent)
}

// registerPublicKeyRequest is the JSON request for PUT /users/{id}/public-key.
type registerPublicKeyRequest struct {
	PublicKey string `json:"public_key"`
	Label     string `json:"label"`
	Password  string `json:"password"`
}

// RegisterPublicKey handles PUT /users/{id}/public-key.
func (h *UserHandler) RegisterPublicKey(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		drainBody(r)
		writeError(w, model.ErrInvalidRequest("Invalid user ID."))
		return
	}

	currUserID, ok := middleware.GetUserID(r.Context())
	if !ok {
		drainBody(r)
		writeError(w, model.ErrUnauthorized())
		return
	}

	if userID != currUserID {
		drainBody(r)
		writeError(w, model.ErrForbidden("You can only register a public key for your own account."))
		return
	}

	var req registerPublicKeyRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, model.ErrInvalidRequest(err.Error()))
		return
	}

	if req.PublicKey == "" {
		writeError(w, model.ErrInvalidRequest("Public key is required."))
		return
	}

	key, err := h.userKeyService.AddKey(r.Context(), service.AddKeyInput{
		UserID:       userID,
		PublicKeyPEM: req.PublicKey,
		Label:        req.Label,
		Password:     req.Password,
	})
	if err != nil {
		logSystemEvent(
			h.systemLogService,
			r,
			"unknown",
			"PUBLIC_KEY_REGISTERED",
			"User: "+userID.String(),
			"FAILED",
			"Failed to register public key: "+err.Error(),
		)
		var appErr *model.AppError
		if errors.As(err, &appErr) {
			writeError(w, appErr)
		} else {
			writeError(w, model.ErrInternal("Failed to register public key."))
		}
		return
	}

	logSystemEvent(
		h.systemLogService,
		r,
		"unknown",
		"PUBLIC_KEY_REGISTERED",
		"User: "+userID.String(),
		"SUCCESS",
		"Registered public key",
	)

	// Use the key metadata returned by the registration service.
	fingerprint, keyID, registeredAt, expiresAt := key.Fingerprint, key.ID, key.RegisteredAt, key.ExpiresAt
	setupState, err := h.userService.GetSetupState(r.Context(), userID)
	if err != nil {
		writeError(w, model.ErrInternal("Failed to retrieve setup state."))
		return
	}

	resp := map[string]any{
		"fingerprint": fingerprint,
		"key_id":      keyID,
		"label":       key.Label,
		"created_at":  registeredAt.Format(time.RFC3339),
		"expires_at":  expiresAt.Format(time.RFC3339),
		"message":     "Public key registered successfully",
	}

	if setupState != nil {
		resp["requires_setup"] = setupState.RequiresSetup
		resp["setup_pending"] = setupState.SetupPending
		resp["must_change_password"] = containsSetupStep(setupState.SetupPending, "password_change")
	}

	writeJSON(w, http.StatusOK, resp)
}

// GetPublicKey handles GET /users/{id}/public-key.
func (h *UserHandler) GetPublicKey(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, model.ErrInvalidRequest("Invalid user ID."))
		return
	}

	key, err := h.userKeyService.GetLatestActiveKey(r.Context(), userID)
	if err != nil {
		var appErr *model.AppError
		if errors.As(err, &appErr) {
			writeError(w, appErr)
		} else {
			writeError(w, model.ErrInternal("Failed to retrieve public key."))
		}
		return
	}

	resp := map[string]string{
		"public_key":  key.PublicKey,
		"fingerprint": key.Fingerprint,
		"created_at":  key.RegisteredAt.Format(time.RFC3339),
		"expires_at":  key.ExpiresAt.Format(time.RFC3339),
	}

	writeJSON(w, http.StatusOK, resp)
}

// changePasswordRequest is the JSON request for PATCH /users/{id}/password.
type changePasswordRequest struct {
	NewPassword string `json:"new_password"`
}

// ChangePassword handles PATCH /users/{id}/password.
func (h *UserHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, model.ErrInvalidRequest("Invalid user ID."))
		return
	}

	var req changePasswordRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, model.ErrInvalidRequest(err.Error()))
		return
	}

	if req.NewPassword == "" {
		writeError(w, model.ErrInvalidRequest("New password is required."))
		return
	}

	// Validate password strength (minimum 8 characters)
	if len(req.NewPassword) < 8 {
		writeError(w, model.ErrInvalidRequest("Password must be at least 8 characters long."))
		return
	}

	if err := h.userService.ChangePassword(r.Context(), userID, req.NewPassword); err != nil {
		logSystemEvent(
			h.systemLogService,
			r,
			"unknown",
			"PASSWORD_CHANGED",
			"User: "+userID.String(),
			"FAILED",
			"Failed to change password: "+err.Error(),
		)
		writeError(w, model.ErrInternal("Failed to change password."))
		return
	}

	logSystemEvent(
		h.systemLogService,
		r,
		"unknown",
		"PASSWORD_CHANGED",
		"User: "+userID.String(),
		"SUCCESS",
		"Changed password",
	)

	setupState, _ := h.userService.GetSetupState(r.Context(), userID)

	resp := map[string]any{
		"message": "Password changed successfully",
	}
	if setupState != nil {
		resp["requires_setup"] = setupState.RequiresSetup
		resp["setup_pending"] = setupState.SetupPending
		resp["must_change_password"] = containsSetupStep(setupState.SetupPending, "password_change")
	}

	writeJSON(w, http.StatusOK, resp)
}

// ReactivateUser handles PATCH /users/{id}/reactivate.
func (h *UserHandler) ReactivateUser(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, model.ErrInvalidRequest("Invalid user ID."))
		return
	}

	if err := h.userService.ReactivateUser(r.Context(), userID); err != nil {
		logSystemEvent(
			h.systemLogService,
			r,
			"unknown",
			"USER_REACTIVATED",
			"User: "+userID.String(),
			"FAILED",
			"Failed to reactivate user: "+err.Error(),
		)
		if strings.Contains(err.Error(), "not found") {
			writeError(w, model.ErrUserNotFound(userID.String()))
			return
		}
		writeError(w, model.ErrInternal("Failed to reactivate user."))
		return
	}

	logSystemEvent(
		h.systemLogService,
		r,
		"unknown",
		"USER_REACTIVATED",
		"User: "+userID.String(),
		"SUCCESS",
		"Reactivated user account",
	)

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "User reactivated successfully.",
	})
}

// adminResetPasswordRequest is the JSON request for PATCH /users/{id}/reset-password.
type adminResetPasswordRequest struct {
	NewPassword string `json:"new_password"`
}

// AdminResetPassword handles PATCH /users/{id}/reset-password.
func (h *UserHandler) AdminResetPassword(w http.ResponseWriter, r *http.Request) {
	userID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, model.ErrInvalidRequest("Invalid user ID."))
		return
	}

	var req adminResetPasswordRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, model.ErrInvalidRequest(err.Error()))
		return
	}

	if req.NewPassword == "" {
		writeError(w, model.ErrInvalidRequest("New password is required."))
		return
	}

	if len(req.NewPassword) < 8 {
		writeError(w, model.ErrInvalidRequest("Password must be at least 8 characters long."))
		return
	}

	if err := h.userService.AdminResetPassword(r.Context(), userID, req.NewPassword); err != nil {
		logSystemEvent(
			h.systemLogService,
			r,
			"unknown",
			"ADMIN_PASSWORD_RESET",
			"User: "+userID.String(),
			"FAILED",
			"Failed to reset password: "+err.Error(),
		)
		if strings.Contains(err.Error(), "not found") {
			writeError(w, model.ErrUserNotFound(userID.String()))
			return
		}
		writeError(w, model.ErrInternal("Failed to reset password."))
		return
	}

	logSystemEvent(
		h.systemLogService,
		r,
		"unknown",
		"ADMIN_PASSWORD_RESET",
		"User: "+userID.String(),
		"SUCCESS",
		"Admin reset user password",
	)

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "Password reset successfully. User must change password on next login.",
	})
}

func containsSetupStep(pending []string, step string) bool {
	for _, s := range pending {
		if s == step {
			return true
		}
	}
	return false
}
