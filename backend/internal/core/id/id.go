// Package id wraps UUIDs in named types.
//
// A bare uuid.UUID makes IncidentID and TenantID interchangeable, and the
// compiler will happily let you pass one where the other belongs. These types
// cost nothing at runtime and make that a build error.
package id

import (
	"fmt"

	"github.com/google/uuid"
)

type (
	TenantID   struct{ uuid.UUID }
	IncidentID struct{ uuid.UUID }
	UserID     struct{ uuid.UUID }
)

func ParseTenant(s string) (TenantID, error) {
	u, err := uuid.Parse(s)
	if err != nil {
		return TenantID{}, fmt.Errorf("invalid tenant id: %w", err)
	}
	return TenantID{u}, nil
}

func ParseIncident(s string) (IncidentID, error) {
	u, err := uuid.Parse(s)
	if err != nil {
		return IncidentID{}, fmt.Errorf("invalid incident id: %w", err)
	}
	return IncidentID{u}, nil
}

func ParseUser(s string) (UserID, error) {
	u, err := uuid.Parse(s)
	if err != nil {
		return UserID{}, fmt.Errorf("invalid user id: %w", err)
	}
	return UserID{u}, nil
}

type (
	AssetID      struct{ uuid.UUID }
	ApprovalID   struct{ uuid.UUID }
	ActionRunID  struct{ uuid.UUID }
	AlertID      struct{ uuid.UUID }
	SourceID     struct{ uuid.UUID }
	RuleID       struct{ uuid.UUID }
	AssessmentID struct{ uuid.UUID }
)

func ParseApproval(s string) (ApprovalID, error) {
	u, err := uuid.Parse(s)
	if err != nil {
		return ApprovalID{}, fmt.Errorf("invalid approval id: %w", err)
	}
	return ApprovalID{u}, nil
}

func NewActionRun() ActionRunID { return ActionRunID{uuid.New()} }
func NewApproval() ApprovalID   { return ApprovalID{uuid.New()} }

func NewAssessment() AssessmentID { return AssessmentID{uuid.New()} }

func ParseAssessment(s string) (AssessmentID, error) {
	u, err := uuid.Parse(s)
	if err != nil {
		return AssessmentID{}, fmt.Errorf("invalid assessment id: %w", err)
	}
	return AssessmentID{u}, nil
}
