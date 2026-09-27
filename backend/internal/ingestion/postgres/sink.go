// Package postgres implements the ingestion sink and repositories.
//
// This is the `edge` profile's IntakeSink. The same pipeline runs against
// NATS JetStream or Kafka by swapping this adapter — nothing above the port
// knows which is in use (docs/soar/08 §4).
package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/titas/soar/backend/internal/core/id"
	"github.com/titas/soar/backend/internal/ingestion"
	pg "github.com/titas/soar/backend/internal/platform/postgres"
)

type Sink struct{ tx *pg.TxManager }

func NewSink(tx *pg.TxManager) *Sink { return &Sink{tx: tx} }

// Accept does not return nil until the batch is committed.
//
// That is the whole contract of the port: `202 Accepted` means the events
// survive this process dying, not "I will get to it".
func (s *Sink) Accept(ctx context.Context, tenant id.TenantID, source id.SourceID,
	batch []ingestion.RawEvent) (ingestion.Receipt, error) {

	receipt := ingestion.Receipt{ID: uuid.NewString(), Received: len(batch)}
	if len(batch) == 0 {
		return receipt, nil
	}
	err := s.tx.InTx(ctx, func(ctx context.Context) error {
		db := s.tx.DB(ctx)
		for _, e := range batch {
			payload, err := json.Marshal(e.Payload)
			if err != nil {
				return fmt.Errorf("serializar evento %s: %w", e.ExternalID, err)
			}
			sum := sha256.Sum256(payload)
			tag, err := db.Exec(ctx, `
				INSERT INTO platform.raw_intake
				  (tenant_id, source_id, receipt_id, mode, payload, payload_sha256, size_bytes)
				VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7)`,
				tenant.UUID, source.UUID, receipt.ID, e.Mode,
				string(payload), sum[:], len(payload))
			if err != nil {
				return fmt.Errorf("aceitar evento: %w", err)
			}
			if tag.RowsAffected() > 0 {
				receipt.Accepted++
			}
		}
		return nil
	})
	return receipt, err
}

func (s *Sink) Watermark(ctx context.Context, tenant id.TenantID) (ingestion.Backlog, error) {
	var (
		pending int64
		oldest  *time.Time
	)
	err := s.tx.DB(ctx).QueryRow(ctx, `
		SELECT count(*), min(ingested_at)
		  FROM platform.raw_intake
		 WHERE tenant_id = $1 AND status = 'accepted'`, tenant.UUID).Scan(&pending, &oldest)
	if err != nil {
		return ingestion.Backlog{}, fmt.Errorf("medir backlog: %w", err)
	}
	b := ingestion.Backlog{Pending: pending}
	if oldest != nil {
		b.OldestAge = time.Since(*oldest)
	}
	return b, nil
}
