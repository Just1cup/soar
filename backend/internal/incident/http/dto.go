// Package http maps between the domain and the wire.
//
// The DTOs are separate types from the domain on purpose: adding a field to
// the aggregate must not silently change the public API, and renaming a domain
// field must not break a client. The mapping is explicit and boring, which is
// exactly what it should be.
package http

import (
	"time"

	"github.com/titas/soar/backend/internal/incident"
)

type incidentSummaryDTO struct {
	ID         string    `json:"id"`
	Key        string    `json:"key"`
	Title      string    `json:"title"`
	Status     string    `json:"status"`
	Severity   string    `json:"severity"`
	Priority   int       `json:"priority"`
	OwnerID    *string   `json:"owner_id"`
	OwnerName  *string   `json:"owner_name"`
	SourceRule *string   `json:"source_rule"`
	AlertCount int       `json:"alert_count"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	Version    int       `json:"version"`
}

type incidentDTO struct {
	incidentSummaryDTO
	TypeSlug         string     `json:"type_slug"`
	Description      *string    `json:"description"`
	Resolution       *string    `json:"resolution"`
	ClosedReason     *string    `json:"closed_reason"`
	ClosedAt         *time.Time `json:"closed_at"`
	FirstAckAt       *time.Time `json:"first_ack_at"`
	AttackTactics    []string   `json:"attack_tactics"`
	AttackTechniques []string   `json:"attack_techniques"`
	Tags             []string   `json:"tags"`
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func toSummary(i *incident.Incident) incidentSummaryDTO {
	d := incidentSummaryDTO{
		ID: i.ID.String(), Key: i.Key, Title: i.Title,
		Status: string(i.Status), Severity: string(i.Severity), Priority: i.Priority,
		SourceRule: nilIfEmpty(i.SourceRule),
		OwnerName:  nilIfEmpty(i.OwnerName),
		AlertCount: i.AlertCount, FirstSeen: i.FirstSeen, LastSeen: i.LastSeen,
		CreatedAt: i.CreatedAt, UpdatedAt: i.UpdatedAt, Version: i.Version,
	}
	if i.OwnerID != nil {
		s := i.OwnerID.String()
		d.OwnerID = &s
	}
	return d
}

func toDetail(i *incident.Incident) incidentDTO {
	// Slices are normalised to empty rather than null: a client that must
	// handle both null and [] for the same field will eventually handle one.
	tactics, techniques, tags := i.AttackTactics, i.AttackTechniques, i.Tags
	if tactics == nil {
		tactics = []string{}
	}
	if techniques == nil {
		techniques = []string{}
	}
	if tags == nil {
		tags = []string{}
	}
	return incidentDTO{
		incidentSummaryDTO: toSummary(i),
		TypeSlug:           i.TypeSlug,
		Description:        nilIfEmpty(i.Description),
		Resolution:         nilIfEmpty(string(i.Resolution)),
		ClosedReason:       nilIfEmpty(i.ClosedReason),
		ClosedAt:           i.ClosedAt,
		FirstAckAt:         i.FirstAckAt,
		AttackTactics:      tactics,
		AttackTechniques:   techniques,
		Tags:               tags,
	}
}

type timelineDTO struct {
	ID         string         `json:"id"`
	OccurredAt time.Time      `json:"occurred_at"`
	EventType  string         `json:"event_type"`
	ActorKind  string         `json:"actor_kind"`
	ActorLabel string         `json:"actor_label"`
	Title      string         `json:"title"`
	Detail     string         `json:"detail"`
	Payload    map[string]any `json:"payload"`
}
