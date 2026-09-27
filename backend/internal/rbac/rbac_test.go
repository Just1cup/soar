package rbac

import (
	"context"
	"errors"
	"testing"

	"github.com/titas/soar/backend/internal/auth"
	"github.com/titas/soar/backend/internal/core/errs"
)

func TestRequire(t *testing.T) {
	cases := []struct {
		name    string
		ctx     context.Context
		perm    string
		wantErr error
	}{
		{"sem identidade", context.Background(), IncidentRead, errs.ErrUnauthorized},
		{"sem permissão", auth.WithActor(context.Background(), auth.Actor{Perms: map[string]bool{}}), IncidentClose, errs.ErrForbidden},
		{"com permissão", auth.WithActor(context.Background(), auth.Actor{Perms: map[string]bool{IncidentClose: true}}), IncidentClose, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := (Checker{}).Require(tc.ctx, tc.perm)
			if tc.wantErr == nil && err != nil {
				t.Fatalf("erro inesperado: %v", err)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("erro=%v, want %v", err, tc.wantErr)
			}
		})
	}
}
