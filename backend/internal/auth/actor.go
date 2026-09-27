// Package auth owns identity: who is making this request.
//
// It is deliberately separate from rbac (what they may do). Swapping local
// sessions for OIDC touches this package and nothing else, because the domain
// only ever sees an Actor.
package auth

import (
	"context"

	"github.com/titas/soar/backend/internal/core/errs"
	"github.com/titas/soar/backend/internal/core/id"
)

// Actor is the authenticated subject. System actors are first-class: a rule
// engine that closes an incident must appear in the trail as itself, never as
// the last human who happened to be logged in.
type Actor struct {
	Kind     string // user | automation | workflow | integration | system
	ID       string
	Label    string
	TenantID id.TenantID
	UserID   *id.UserID
	Perms    map[string]bool
}

func (a Actor) Can(permission string) bool { return a.Perms[permission] }

// SystemActor builds the identity a background engine acts under.
func SystemActor(name string, tenant id.TenantID, perms map[string]bool) Actor {
	return Actor{Kind: "system", ID: "system:" + name, Label: name, TenantID: tenant, Perms: perms}
}

type ctxKey struct{}

func WithActor(ctx context.Context, a Actor) context.Context {
	return context.WithValue(ctx, ctxKey{}, a)
}

// FromContext returns the actor, or an error. There is no anonymous fallback:
// a use case that cannot name who asked must refuse.
func FromContext(ctx context.Context) (Actor, error) {
	a, ok := ctx.Value(ctxKey{}).(Actor)
	if !ok {
		return Actor{}, errs.Coded(errs.ErrUnauthorized, "NOT_AUTHENTICATED",
			"requisição sem identidade")
	}
	return a, nil
}
