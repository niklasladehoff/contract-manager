package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/ibm-hyper-protect/contract-manager/internal/crypto"
	"github.com/ibm-hyper-protect/contract-manager/internal/model"
	"github.com/ibm-hyper-protect/contract-manager/internal/repository"
)

// AuditService handles the deterministic hash chain of build events.
type AuditService struct {
	queries repository.Querier
}

// NewAuditService creates a new AuditService.
func NewAuditService(queries repository.Querier) *AuditService {
	return &AuditService{queries: queries}
}

// LogEventInput contains data for a new audit event.
type LogEventInput struct {
	BuildID             uuid.UUID
	EventType           model.AuditEventType
	ActorUserID         uuid.UUID
	ActorPublicKey      *string
	ActorKeyFingerprint *string // SHA256 fingerprint of the actor's public key
	IpAddress           string
	DeviceMetadata      []byte
	EventData           any     // Will be marshaled to JSON
	Signature           *string // Signature of the EventHash by ActorPublicKey (optional for some events)
}

// LogEvent securely appends a new event to the build's audit hash chain.
func (s *AuditService) LogEvent(ctx context.Context, input LogEventInput) (*repository.AuditEvent, error) {
	// Marshal event data
	eventDataJSON, err := json.Marshal(input.EventData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal event data: %w", err)
	}

	// Determine sequence number and previous hash
	var seqNo int32 = 1
	var prevHash string

	// Convert uuid.UUID to pgtype.UUID
	buildIDPg := pgtype.UUID{
		Bytes: input.BuildID,
		Valid: true,
	}

	latest, err := s.queries.GetLatestAuditEvent(ctx, buildIDPg)
	if err != nil {
		if strings.Contains(err.Error(), "no rows in result set") {
			// First event in the chain: prevHash is the genesis hash
			prevHash = crypto.ComputeGenesisHash(input.BuildID.String())
		} else {
			return nil, fmt.Errorf("failed to get latest event: %w", err)
		}
	} else {
		seqNo = latest.SequenceNo + 1
		prevHash = latest.EventHash
	}

	// Prefer the key that actually signed this request.
	if input.ActorPublicKey == nil {
		key, ok := SigningKeyFromContext(ctx)

		// Background operations may have no signing key in their context.
		if !ok || key.UserID != input.ActorUserID {
			keys, err := s.queries.ListActiveUserPublicKeys(ctx, input.ActorUserID)
			if err != nil {
				return nil, fmt.Errorf("load actor public keys: %w", err)
			}

			ok = len(keys) > 0
			if ok {
				key = keys[0]
			}
		}

		if ok {
			input.ActorPublicKey = &key.PublicKey
			input.ActorKeyFingerprint = &key.Fingerprint
		}
	}

	// Derive a missing fingerprint from the explicitly supplied public key.
	if input.ActorPublicKey != nil && input.ActorKeyFingerprint == nil {
		fingerprint, err := crypto.ComputePublicKeyFingerprint(*input.ActorPublicKey)
		if err != nil {
			return nil, fmt.Errorf("compute actor key fingerprint: %w", err)
		}
		input.ActorKeyFingerprint = &fingerprint
	}

	// Compute new event hash
	eventHash := crypto.ComputeEventHash(eventDataJSON, prevHash)

	// Parse IP address
	var ip *netip.Addr
	if input.IpAddress != "" {
		parsedIP, err := netip.ParseAddr(input.IpAddress)
		if err == nil {
			ip = &parsedIP
		}
	}

	// Prepare device metadata
	var devMeta []byte
	if input.DeviceMetadata != nil {
		devMeta = input.DeviceMetadata
	} else {
		devMeta = []byte("{}")
	}

	// Insert into DB
	row, err := s.queries.CreateAuditEvent(ctx, repository.CreateAuditEventParams{
		BuildID:             buildIDPg,
		SequenceNo:          seqNo,
		EventType:           string(input.EventType),
		ActorUserID:         input.ActorUserID,
		ActorPublicKey:      input.ActorPublicKey,
		ActorKeyFingerprint: input.ActorKeyFingerprint,
		IpAddress:           ip,
		DeviceMetadata:      devMeta,
		EventData:           json.RawMessage(eventDataJSON),
		PreviousEventHash:   prevHash,
		EventHash:           eventHash,
		Signature:           input.Signature,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create audit event: %w", err)
	}

	// Convert Row to AuditEvent
	result := &repository.AuditEvent{
		ID:                  row.ID,
		BuildID:             row.BuildID,
		SequenceNo:          row.SequenceNo,
		EventType:           row.EventType,
		ActorUserID:         row.ActorUserID,
		ActorPublicKey:      row.ActorPublicKey,
		ActorKeyFingerprint: row.ActorKeyFingerprint,
		IpAddress:           row.IpAddress,
		DeviceMetadata:      row.DeviceMetadata,
		EventData:           row.EventData,
		PreviousEventHash:   row.PreviousEventHash,
		EventHash:           row.EventHash,
		Signature:           row.Signature,
		CreatedAt:           row.CreatedAt,
	}

	return result, nil
}

// EnrichedAuditEvent extends AuditEvent with actor display name.
type EnrichedAuditEvent struct {
	repository.AuditEvent
	ActorName string `json:"actor_name"`
}

// GetAuditTrail returns the full chronological audit trail for a build, enriched with actor names.
func (s *AuditService) GetAuditTrail(ctx context.Context, buildID uuid.UUID) ([]EnrichedAuditEvent, error) {
	// Convert uuid.UUID to pgtype.UUID
	buildIDPg := pgtype.UUID{
		Bytes: buildID,
		Valid: true,
	}

	rows, err := s.queries.GetAuditEventsByBuildID(ctx, buildIDPg)
	if err != nil {
		return nil, fmt.Errorf("failed to get audit events: %w", err)
	}

	// Cache user names to avoid repeated DB lookups
	userNames := make(map[uuid.UUID]string)

	events := make([]EnrichedAuditEvent, len(rows))
	for i, row := range rows {
		base := repository.AuditEvent{
			ID:                  row.ID,
			BuildID:             row.BuildID,
			SequenceNo:          row.SequenceNo,
			EventType:           row.EventType,
			ActorUserID:         row.ActorUserID,
			ActorPublicKey:      row.ActorPublicKey,
			ActorKeyFingerprint: row.ActorKeyFingerprint,
			IpAddress:           row.IpAddress,
			DeviceMetadata:      row.DeviceMetadata,
			EventData:           row.EventData,
			PreviousEventHash:   row.PreviousEventHash,
			EventHash:           row.EventHash,
			Signature:           row.Signature,
			CreatedAt:           row.CreatedAt,
		}

		// Resolve actor name
		actorName, ok := userNames[row.ActorUserID]
		if !ok {
			user, err := s.queries.GetUserByID(ctx, row.ActorUserID)
			if err == nil {
				actorName = user.Name
			} else {
				actorName = row.ActorUserID.String()
			}
			userNames[row.ActorUserID] = actorName
		}

		events[i] = EnrichedAuditEvent{
			AuditEvent: base,
			ActorName:  actorName,
		}
	}

	return events, nil
}
