package model

import (
	"fmt"
	"net/http"
)

// AppError represents a structured application error with an HTTP status code.
type AppError struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	Details    any    `json:"details,omitempty"`
	HTTPStatus int    `json:"-"`
}

func (e *AppError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Common error constructors.

func ErrInvalidRequest(msg string) *AppError {
	return &AppError{Code: "INVALID_REQUEST", Message: msg, HTTPStatus: http.StatusBadRequest}
}

func ErrHashMismatch(expected, got string) *AppError {
	return &AppError{
		Code:       "HASH_MISMATCH",
		Message:    "Computed hash does not match submitted hash.",
		Details:    map[string]string{"expected": expected, "got": got},
		HTTPStatus: http.StatusBadRequest,
	}
}

func ErrInvalidSignature() *AppError {
	return &AppError{Code: "INVALID_SIGNATURE", Message: "Signature verification failed.", HTTPStatus: http.StatusBadRequest}
}

func ErrInvalidCertificate(msg string) *AppError {
	return &AppError{Code: "INVALID_CERTIFICATE", Message: msg, HTTPStatus: http.StatusBadRequest}
}

func ErrUnauthorized() *AppError {
	return &AppError{Code: "UNAUTHORIZED", Message: "Missing or invalid bearer token.", HTTPStatus: http.StatusUnauthorized}
}

func ErrForbidden(msg string) *AppError {
	return &AppError{Code: "FORBIDDEN", Message: msg, HTTPStatus: http.StatusForbidden}
}

func ErrNotFound(msg string) *AppError {
	return &AppError{Code: "NOT_FOUND", Message: msg, HTTPStatus: http.StatusNotFound}
}

func ErrBuildNotFound(id string) *AppError {
	return &AppError{
		Code:       "BUILD_NOT_FOUND",
		Message:    fmt.Sprintf("Build %s not found.", id),
		HTTPStatus: http.StatusNotFound,
	}
}

func ErrUserNotFound(id string) *AppError {
	return &AppError{
		Code:       "USER_NOT_FOUND",
		Message:    fmt.Sprintf("User %s not found.", id),
		HTTPStatus: http.StatusNotFound,
	}
}

func ErrDuplicateEmail(email string) *AppError {
	return &AppError{
		Code:       "DUPLICATE_EMAIL",
		Message:    fmt.Sprintf("Email %s is already registered.", email),
		HTTPStatus: http.StatusConflict,
	}
}

func ErrDuplicateSection(role string) *AppError {
	return &AppError{
		Code:       "DUPLICATE_SECTION",
		Message:    fmt.Sprintf("Section already submitted for role %s.", role),
		HTTPStatus: http.StatusConflict,
	}
}

func ErrInvalidStateTransition(current, expected string) *AppError {
	return &AppError{
		Code:       "INVALID_STATE_TRANSITION",
		Message:    fmt.Sprintf("Build is in %s state; expected %s.", current, expected),
		Details:    map[string]string{"current_status": current, "expected_status": expected},
		HTTPStatus: http.StatusUnprocessableEntity,
	}
}

func ErrBuildImmutable() *AppError {
	return &AppError{
		Code:       "BUILD_IMMUTABLE",
		Message:    "Cannot modify a finalized build.",
		HTTPStatus: http.StatusUnprocessableEntity,
	}
}

func ErrInternal(msg string) *AppError {
	return &AppError{Code: "INTERNAL_ERROR", Message: msg, HTTPStatus: http.StatusInternalServerError}
}

// ErrKeyLimitReached reports that all five active identity-key slots are in use.
func ErrKeyLimitReached() *AppError {
	return &AppError{Code: "KEY_LIMIT_REACHED", Message: "A user can have at most 5 active public keys.", HTTPStatus: http.StatusConflict}
}

// ErrKeyAlreadyRegistered reports a fingerprint that already exists in key history.
func ErrKeyAlreadyRegistered() *AppError {
	return &AppError{Code: "KEY_ALREADY_REGISTERED", Message: "This public key has already been registered.", HTTPStatus: http.StatusConflict}
}

// ErrKeyNotFound reports an unknown, foreign, or already revoked identity key.
func ErrKeyNotFound() *AppError {
	return &AppError{Code: "KEY_NOT_FOUND", Message: "Public key not found or already revoked.", HTTPStatus: http.StatusNotFound}
}

// ErrPasswordConfirmation reports a missing or incorrect registration password.
func ErrPasswordConfirmation() *AppError {
	return &AppError{Code: "PASSWORD_CONFIRMATION_FAILED", Message: "Confirm your current password to register another public key.", HTTPStatus: http.StatusForbidden}
}
