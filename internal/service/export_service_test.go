package service

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/ibm-hyper-protect/contract-manager/internal/model"
	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
)

type acknowledgmentQueries struct {
	repository.Querier
	contractHash *string
}

func (q acknowledgmentQueries) GetBuildByID(context.Context, uuid.UUID) (repository.GetBuildByIDRow, error) {
	return repository.GetBuildByIDRow{
		Status: model.StatusFinalized.String(), ContractHash: q.contractHash,
	}, nil
}

func (q acknowledgmentQueries) GetAuditEventsByBuildID(context.Context, pgtype.UUID) ([]repository.GetAuditEventsByBuildIDRow, error) {
	return nil, nil
}

func TestAcknowledgeDownloadInvalidContractHash(t *testing.T) {
	storedHash := "stored-contract-hash"
	for _, tc := range []struct {
		name         string
		contractHash *string
		wantCode     string
	}{
		{name: "missing contract", wantCode: "INVALID_REQUEST"},
		{name: "different hash", contractHash: &storedHash, wantCode: "HASH_MISMATCH"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service := NewExportService(acknowledgmentQueries{contractHash: tc.contractHash}, nil, nil)
			err := service.AcknowledgeDownload(context.Background(), AcknowledgeDownloadInput{
				BuildID: uuid.New(), UserID: uuid.New(), ContractHash: "submitted-contract-hash",
			})
			var appErr *model.AppError
			if !errors.As(err, &appErr) {
				t.Fatalf("expected application error, got %v", err)
			}
			if appErr.Code != tc.wantCode || appErr.HTTPStatus != http.StatusBadRequest {
				t.Fatalf("got %s (HTTP %d), want %s (HTTP 400)", appErr.Code, appErr.HTTPStatus, tc.wantCode)
			}
			if tc.contractHash == nil && appErr.Message != "contract not available" {
				t.Fatalf("unexpected missing-contract message: %q", appErr.Message)
			}
		})
	}
}
