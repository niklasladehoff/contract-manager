package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/ibm-hyper-protect/contract-manager/internal/model"
	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
)

// UserService handles user management operations.
type UserService struct {
	queries    repository.Querier
	bcryptCost int
}

// SetupState represents setup requirements for a user account.
type SetupState struct {
	RequiresSetup bool     `json:"requires_setup"`
	SetupPending  []string `json:"setup_pending"`
}

// NewUserService creates a new UserService.
func NewUserService(queries repository.Querier, bcryptCost int) *UserService {
	return &UserService{
		queries:    queries,
		bcryptCost: bcryptCost,
	}
}

// UserWithRoles represents a user with their assigned roles.
type UserWithRoles struct {
	ID                   uuid.UUID `json:"id"`
	Name                 string    `json:"name"`
	Email                string    `json:"email"`
	Roles                []string  `json:"roles"`
	IsActive             bool      `json:"is_active"`
	CreatedAt            string    `json:"created_at"`
	MustChangePassword   bool      `json:"must_change_password"`
	PublicKeyFingerprint *string   `json:"public_key_fingerprint"`
	PublicKeyExpiresAt   *string   `json:"public_key_expires_at"`
	ActiveKeyCount       int64     `json:"active_key_count"`
}

// ListUsers returns all users with their roles. ADMIN only.
func (s *UserService) ListUsers(ctx context.Context) ([]UserWithRoles, error) {
	users, err := s.queries.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	result := make([]UserWithRoles, 0, len(users))
	for _, u := range users {
		roles, err := s.queries.GetRolesByUserID(ctx, u.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to load roles for user %s: %w", u.ID, err)
		}

		roleStrings := make([]string, len(roles))
		for i, r := range roles {
			roleStrings[i] = r.Role
		}

		var fingerprint *string
		if u.PublicKeyFingerprint != nil {
			fingerprint = u.PublicKeyFingerprint
		}

		var expiresAt *string
		if u.PublicKeyExpiresAt.Valid {
			tStr := u.PublicKeyExpiresAt.Time.Format(time.RFC3339)
			expiresAt = &tStr
		}

		result = append(result, UserWithRoles{
			ID:                   u.ID,
			Name:                 u.Name,
			Email:                u.Email,
			Roles:                roleStrings,
			IsActive:             u.IsActive,
			CreatedAt:            u.CreatedAt.Format(time.RFC3339),
			MustChangePassword:   u.MustChangePassword,
			PublicKeyFingerprint: fingerprint,
			PublicKeyExpiresAt:   expiresAt,
			ActiveKeyCount:       u.ActiveKeyCount,
		})
	}

	return result, nil
}

// CreateUserInput contains the input for creating a new user.
type CreateUserInput struct {
	Name     string   `json:"name"`
	Email    string   `json:"email"`
	Password string   `json:"password"`
	Roles    []string `json:"roles"`
}

// CreateUser creates a new user with the specified roles.
func (s *UserService) CreateUser(ctx context.Context, input CreateUserInput, assignedBy uuid.UUID) (*UserWithRoles, error) {
	// Validate roles
	for _, role := range input.Roles {
		if !model.PersonaRole(role).IsValid() {
			return nil, fmt.Errorf("invalid role: %s", role)
		}
	}

	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(input.Password), s.bcryptCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	user, err := s.queries.CreateUser(ctx, repository.CreateUserParams{
		Name:         input.Name,
		Email:        input.Email,
		PasswordHash: string(hash),
	})
	if err != nil {
		// Check for duplicate email (PostgreSQL unique constraint violation)
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Assign roles
	for _, role := range input.Roles {
		_, err = s.queries.AssignRole(ctx, repository.AssignRoleParams{
			UserID:     user.ID,
			Role:       role,
			AssignedBy: assignedBy,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to assign role %s: %w", role, err)
		}
	}

	return &UserWithRoles{
		ID:        user.ID,
		Name:      user.Name,
		Email:     user.Email,
		Roles:     input.Roles,
		IsActive:  user.IsActive,
		CreatedAt: user.CreatedAt.Format("2006-01-02T15:04:05Z"),
	}, nil
}

// UpdateUserProfile updates a user's name and email.
func (s *UserService) UpdateUserProfile(ctx context.Context, userID uuid.UUID, name, email string) (*UserWithRoles, error) {
	if name == "" || email == "" {
		return nil, fmt.Errorf("name and email cannot be empty")
	}

	user, err := s.queries.UpdateUser(ctx, repository.UpdateUserParams{
		ID:    userID,
		Name:  name,
		Email: email,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to update user profile: %w", err)
	}

	// Fetch existing roles to return a full UserWithRoles object
	roles, err := s.queries.GetRolesByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to load roles: %w", err)
	}

	roleStrings := make([]string, len(roles))
	for i, r := range roles {
		roleStrings[i] = r.Role
	}

	return &UserWithRoles{
		ID:        user.ID,
		Name:      user.Name,
		Email:     user.Email,
		Roles:     roleStrings,
		IsActive:  user.IsActive,
		CreatedAt: user.CreatedAt.Format("2006-01-02T15:04:05Z"),
	}, nil
}

// DeactivateUser disables a user making them unable to log in
func (s *UserService) DeactivateUser(ctx context.Context, userID uuid.UUID) error {
	err := s.queries.DeactivateUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to deactivate user: %w", err)
	}
	return nil
}

// UpdateRoles replaces all roles for a user.
func (s *UserService) UpdateRoles(ctx context.Context, userID uuid.UUID, roles []string, assignedBy uuid.UUID) (*UserWithRoles, error) {
	// Validate roles
	for _, role := range roles {
		if !model.PersonaRole(role).IsValid() {
			return nil, fmt.Errorf("invalid role: %s", role)
		}
	}

	// Verify user exists
	user, err := s.queries.GetUserByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Delete existing roles and assign new ones
	if err := s.queries.DeleteRolesByUserID(ctx, userID); err != nil {
		return nil, fmt.Errorf("failed to clear roles: %w", err)
	}

	for _, role := range roles {
		_, err = s.queries.AssignRole(ctx, repository.AssignRoleParams{
			UserID:     userID,
			Role:       role,
			AssignedBy: assignedBy,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to assign role %s: %w", role, err)
		}
	}

	return &UserWithRoles{
		ID:        user.ID,
		Name:      user.Name,
		Email:     user.Email,
		Roles:     roles,
		IsActive:  user.IsActive,
		CreatedAt: user.CreatedAt.Format("2006-01-02T15:04:05Z"),
	}, nil
}

// TokenInfo represents an API token for display (no raw token or hash).
type TokenInfo struct {
	ID         uuid.UUID `json:"id"`
	Name       string    `json:"name"`
	LastUsedAt *string   `json:"last_used_at"`
	RevokedAt  *string   `json:"revoked_at"`
	CreatedAt  string    `json:"created_at"`
}

// ListTokens returns all API tokens for a user.
func (s *UserService) ListTokens(ctx context.Context, userID uuid.UUID) ([]TokenInfo, error) {
	tokens, err := s.queries.ListAPITokensByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to list tokens: %w", err)
	}

	result := make([]TokenInfo, 0, len(tokens))
	for _, t := range tokens {
		info := TokenInfo{
			ID:        t.ID,
			Name:      t.Name,
			CreatedAt: t.CreatedAt.Format("2006-01-02T15:04:05Z"),
		}
		if t.LastUsedAt.Valid {
			s := t.LastUsedAt.Time.Format("2006-01-02T15:04:05Z")
			info.LastUsedAt = &s
		}
		if t.RevokedAt.Valid {
			s := t.RevokedAt.Time.Format("2006-01-02T15:04:05Z")
			info.RevokedAt = &s
		}
		result = append(result, info)
	}

	return result, nil
}

// CreateTokenResult contains the result of creating a new API token.
type CreateTokenResult struct {
	ID    uuid.UUID `json:"id"`
	Name  string    `json:"name"`
	Token string    `json:"token"` // Raw token, shown only once
}

// CreateToken creates a new API token for a user.
func (s *UserService) CreateToken(ctx context.Context, userID uuid.UUID, name string) (*CreateTokenResult, error) {
	rawToken, hashedToken, err := GenerateToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	row, err := s.queries.CreateAPIToken(ctx, repository.CreateAPITokenParams{
		UserID:    userID,
		Name:      name,
		TokenHash: hashedToken,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create token: %w", err)
	}

	return &CreateTokenResult{
		ID:    row.ID,
		Name:  row.Name,
		Token: rawToken,
	}, nil
}

// RevokeToken revokes an API token.
func (s *UserService) RevokeToken(ctx context.Context, userID uuid.UUID, tokenID uuid.UUID) error {
	return s.queries.RevokeAPIToken(ctx, repository.RevokeAPITokenParams{
		ID:     tokenID,
		UserID: userID,
	})
}

// GetSetupState returns the current setup requirements for the given user.
func (s *UserService) GetSetupState(ctx context.Context, userID uuid.UUID) (*SetupState, error) {
	user, err := s.queries.GetUserByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to load user: %w", err)
	}

	setupPending := make([]string, 0, 2)
	if user.MustChangePassword {
		setupPending = append(setupPending, "password_change")
	}

	if user.ActiveKeyCount == 0 {
		setupPending = append(setupPending, "public_key_registration")
	}

	return &SetupState{
		RequiresSetup: len(setupPending) > 0,
		SetupPending:  setupPending,
	}, nil
}

// ChangePassword changes a user's password and clears the must_change_password flag.
func (s *UserService) ChangePassword(ctx context.Context, userID uuid.UUID, newPassword string) error {
	// Hash the new password
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), s.bcryptCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password in database
	err = s.queries.UpdatePassword(ctx, repository.UpdatePasswordParams{
		ID:           userID,
		PasswordHash: string(hash),
	})
	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}

// ReactivateUser sets a deactivated user back to active.
func (s *UserService) ReactivateUser(ctx context.Context, userID uuid.UUID) error {
	// Verify user exists
	_, err := s.queries.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	if err := s.queries.ReactivateUser(ctx, userID); err != nil {
		return fmt.Errorf("failed to reactivate user: %w", err)
	}
	return nil
}

// AdminResetPassword allows an admin to set a new password for a user.
// The user will be forced to change it on next login.
func (s *UserService) AdminResetPassword(ctx context.Context, userID uuid.UUID, newPassword string) error {
	// Verify user exists
	_, err := s.queries.GetUserByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// Hash the new password
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), s.bcryptCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	err = s.queries.AdminResetPassword(ctx, repository.AdminResetPasswordParams{
		ID:           userID,
		PasswordHash: string(hash),
	})
	if err != nil {
		return fmt.Errorf("failed to reset password: %w", err)
	}

	return nil
}
