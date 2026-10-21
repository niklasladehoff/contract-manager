package service

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
)

type userKeyStateQueries struct {
	repository.Querier
	user  repository.GetUserByIDRow
	users []repository.ListUsersRow
}

func (q *userKeyStateQueries) GetUserByID(context.Context, uuid.UUID) (repository.GetUserByIDRow, error) {
	return q.user, nil
}
func (q *userKeyStateQueries) ListUsers(context.Context) ([]repository.ListUsersRow, error) {
	return q.users, nil
}
func (q *userKeyStateQueries) GetRolesByUserID(context.Context, uuid.UUID) ([]repository.UserRole, error) {
	return []repository.UserRole{{Role: "VIEWER"}}, nil
}

func TestUserSetupUsesActiveKeys(t *testing.T) {
	for _, active := range []int64{0, 1, 2} {
		for _, passwordChange := range []bool{false, true} {
			q := &userKeyStateQueries{user: repository.GetUserByIDRow{ActiveKeyCount: active, MustChangePassword: passwordChange}}
			state, err := NewUserService(q, 4).GetSetupState(context.Background(), uuid.New())
			if err != nil {
				t.Fatal(err)
			}
			if state.RequiresSetup != (active == 0 || passwordChange) ||
				slices.Contains(state.SetupPending, "public_key_registration") != (active == 0) ||
				slices.Contains(state.SetupPending, "password_change") != passwordChange {
				t.Errorf("active=%d passwordChange=%t: %+v", active, passwordChange, state)
			}
		}
	}
}

func TestUserListIncludesActiveKeyCount(t *testing.T) {
	fp := "latest"
	expires := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	q := &userKeyStateQueries{users: []repository.ListUsersRow{{
		ID: uuid.New(), ActiveKeyCount: 2, PublicKeyFingerprint: &fp,
		PublicKeyExpiresAt: pgtype.Timestamptz{Time: expires, Valid: true},
	}}}
	users, err := NewUserService(q, 4).ListUsers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || users[0].ActiveKeyCount != 2 || users[0].PublicKeyFingerprint == nil || *users[0].PublicKeyFingerprint != fp ||
		users[0].PublicKeyExpiresAt == nil || *users[0].PublicKeyExpiresAt != expires.Format(time.RFC3339) {
		t.Errorf("incorrect user list: %+v", users)
	}
}
