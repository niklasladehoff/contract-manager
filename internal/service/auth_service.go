package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
)

// AuthService handles authentication logic including login, logout, and token management.
type AuthService struct {
	queries     repository.Querier
	bcryptCost  int
	tokenExpiry time.Duration
}

// NewAuthService creates a new AuthService.
func NewAuthService(queries repository.Querier, bcryptCost int, tokenExpiry time.Duration) *AuthService {
	return &AuthService{
		queries:     queries,
		bcryptCost:  bcryptCost,
		tokenExpiry: tokenExpiry,
	}
}

// LoginResult contains the result of a successful login.
type LoginResult struct {
	Token         string    `json:"token"`
	ExpiresAt     time.Time `json:"expires_at"`
	RequiresSetup bool      `json:"requires_setup"`
	SetupPending  []string  `json:"setup_pending"`
	User          UserInfo  `json:"user"`
}

// UserInfo represents the user information returned on login.
type UserInfo struct {
	ID                   uuid.UUID  `json:"id"`
	Name                 string     `json:"name"`
	Email                string     `json:"email"`
	Roles                []string   `json:"roles"`
	IsActive             bool       `json:"is_active"`
	CreatedAt            time.Time  `json:"created_at"`
	HasPublicKey         bool       `json:"has_public_key"`
	ActiveKeyCount       int64      `json:"active_key_count"`
	PublicKeyExpired     bool       `json:"public_key_expired"`
	PublicKeyFingerprint *string    `json:"public_key_fingerprint"`
	PublicKeyExpiresAt   *time.Time `json:"public_key_expires_at"`
	MustChangePassword   bool       `json:"must_change_password"`
	PasswordChangedAt    *time.Time `json:"password_changed_at"`
}

// Login validates credentials and returns a bearer token.
func (s *AuthService) Login(ctx context.Context, email, password string) (*LoginResult, error) {
	// Look up user by email
	user, err := s.queries.GetUserByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Check if user is active
	if !user.IsActive {
		return nil, fmt.Errorf("user account is deactivated")
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Load roles
	roles, err := s.queries.GetRolesByUserID(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to load roles: %w", err)
	}

	roleStrings := make([]string, len(roles))
	for i, r := range roles {
		roleStrings[i] = r.Role
	}

	// Generate token
	rawToken, hashedToken, err := GenerateToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	// Store token in DB
	_, err = s.queries.CreateAPIToken(ctx, repository.CreateAPITokenParams{
		UserID:    user.ID,
		Name:      "login-" + time.Now().Format("20060102-150405"),
		TokenHash: hashedToken,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create token: %w", err)
	}

	var publicKeyFingerprint *string
	if user.PublicKeyFingerprint != nil {
		publicKeyFingerprint = user.PublicKeyFingerprint
	}
	var publicKeyExpiresAt *time.Time
	if user.PublicKeyExpiresAt.Valid {
		t := user.PublicKeyExpiresAt.Time
		publicKeyExpiresAt = &t
	}
	var passwordChangedAt *time.Time
	if user.PasswordChangedAt.Valid {
		t := user.PasswordChangedAt.Time
		passwordChangedAt = &t
	}
	hasPublicKey := user.ActiveKeyCount > 0
	// Keep the legacy flag useful for clients requiring key renewal after all
	// previously registered keys have expired or been revoked.
	publicKeyExpired := !hasPublicKey && user.TotalKeyCount > 0

	setupPending := make([]string, 0, 2)
	if user.MustChangePassword {
		setupPending = append(setupPending, "password_change")
	}
	if !hasPublicKey || publicKeyExpired {
		setupPending = append(setupPending, "public_key_registration")
	}
	requiresSetup := len(setupPending) > 0

	return &LoginResult{
		Token:         rawToken,
		ExpiresAt:     time.Now().Add(s.tokenExpiry),
		RequiresSetup: requiresSetup,
		SetupPending:  setupPending,
		User: UserInfo{
			ID:                   user.ID,
			Name:                 user.Name,
			Email:                user.Email,
			Roles:                roleStrings,
			IsActive:             user.IsActive,
			CreatedAt:            user.CreatedAt,
			HasPublicKey:         hasPublicKey,
			ActiveKeyCount:       user.ActiveKeyCount,
			PublicKeyExpired:     publicKeyExpired,
			PublicKeyFingerprint: publicKeyFingerprint,
			PublicKeyExpiresAt:   publicKeyExpiresAt,
			MustChangePassword:   user.MustChangePassword,
			PasswordChangedAt:    passwordChangedAt,
		},
	}, nil
}

// Logout revokes the token used for the current session.
func (s *AuthService) Logout(ctx context.Context, tokenHash string) error {
	// Look up the token to get its ID and user_id
	token, err := s.queries.GetAPITokenByHash(ctx, tokenHash)
	if err != nil {
		return fmt.Errorf("token not found: %w", err)
	}

	return s.queries.RevokeAPIToken(ctx, repository.RevokeAPITokenParams{
		ID:     token.ID,
		UserID: token.UserID,
	})
}

// HashPassword hashes a password using bcrypt.
func (s *AuthService) HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.bcryptCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hash), nil
}

// GenerateToken generates a cryptographically secure token and its SHA256 hash.
func GenerateToken() (raw string, hashed string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("crypto/rand failed: %w", err)
	}
	raw = base64.URLEncoding.EncodeToString(b)
	hashed = HashToken(raw)
	return raw, hashed, nil
}

// HashToken computes the SHA256 hash of a raw token string.
func HashToken(rawToken string) string {
	hash := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(hash[:])
}
