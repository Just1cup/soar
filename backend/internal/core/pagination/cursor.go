// Package pagination implements the opaque, signed cursor used by every
// collection in the API.
//
// Signed, because an unsigned cursor is an invitation: a client that can edit
// it can walk the keyset in ways the query was never indexed for, which is a
// cheap denial of service. Opaque, because the day the sort key changes, no
// client should have depended on its contents.
package pagination

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/titas/soar/backend/internal/core/errs"
)

const (
	DefaultLimit = 50
	MaxLimit     = 200
)

// Key is the keyset position: the sort column plus a tiebreaker, because
// last_seen alone is not unique and OFFSET skips rows when data moves.
type Key struct {
	LastSeen time.Time
	ID       uuid.UUID
}

type Signer struct{ key []byte }

func NewSigner(secret string) *Signer { return &Signer{key: []byte(secret)} }

func (s *Signer) Encode(k Key) string {
	body := fmt.Sprintf("%d.%s", k.LastSeen.UTC().UnixNano(), k.ID)
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(body))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:16])
	return base64.RawURLEncoding.EncodeToString([]byte(body + "." + sig))
}

func (s *Signer) Decode(cursor string) (Key, error) {
	bad := func() (Key, error) {
		return Key{}, errs.Coded(errs.ErrValidation, "INVALID_CURSOR", "cursor inválido")
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return bad()
	}
	parts := strings.Split(string(raw), ".")
	if len(parts) != 3 {
		return bad()
	}
	body := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(body))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil)[:16])
	// Constant time: a timing oracle on a cursor signature is still an oracle.
	if !hmac.Equal([]byte(want), []byte(parts[2])) {
		return bad()
	}
	nanos, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return bad()
	}
	uid, err := uuid.Parse(parts[1])
	if err != nil {
		return bad()
	}
	return Key{LastSeen: time.Unix(0, nanos).UTC(), ID: uid}, nil
}

// ClampLimit keeps a client from asking for the whole table. The cap is not a
// nicety: one cluster in this environment holds 15 161 alerts.
func ClampLimit(requested int) int {
	switch {
	case requested <= 0:
		return DefaultLimit
	case requested > MaxLimit:
		return MaxLimit
	default:
		return requested
	}
}
