package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/titas/soar/backend/internal/core/clock"
	"github.com/titas/soar/backend/internal/core/errs"
	"github.com/titas/soar/backend/internal/core/id"
)

const (
	SessionTTL    = 12 * time.Hour
	sessionBytes  = 32
	SessionCookie = "soar_session"
	CSRFCookie    = "soar_csrf"
)

type User struct {
	ID           id.UserID
	TenantID     id.TenantID
	Email        string
	DisplayName  string
	PasswordHash string
	Disabled     bool
}

type Repository interface {
	FindUserByEmail(ctx context.Context, tenant id.TenantID, email string) (*User, error)
	CreateSession(ctx context.Context, s Session) error
	FindSession(ctx context.Context, tokenHash []byte) (*Session, *User, error)
	RevokeSession(ctx context.Context, tokenHash []byte) error
	PermissionsOf(ctx context.Context, userID id.UserID) (map[string]bool, error)
	RolePermissions(ctx context.Context, tenant id.TenantID, role string) (map[string]bool, error)
}

type Session struct {
	TenantID  id.TenantID
	UserID    id.UserID
	TokenHash []byte
	CSRFHash  []byte
	ExpiresAt time.Time
	SourceIP  string
	UserAgent string
}

type Service struct {
	Repo  Repository
	Clock clock.Clock
}

// HashToken keeps the plaintext session token out of the database: whoever
// reads the table cannot impersonate anyone.
func HashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// Login returns the session token. The error is deliberately identical for an
// unknown email and a wrong password — anything else is a user enumeration
// oracle on the login page of a security platform.
func (s *Service) Login(ctx context.Context, tenant id.TenantID, email, password, ip, ua string) (string, string, *User, error) {
	invalid := errs.Coded(errs.ErrUnauthorized, "INVALID_CREDENTIALS",
		"e-mail ou senha inválidos")

	user, err := s.Repo.FindUserByEmail(ctx, tenant, email)
	if err != nil || user == nil || user.Disabled || user.PasswordHash == "" {
		// Gasta o mesmo tempo mesmo sem usuário, para o tempo de resposta não
		// contar quem existe.
		_, _ = VerifyPassword(password, decoyHash)
		return "", "", nil, invalid
	}
	ok, err := VerifyPassword(password, user.PasswordHash)
	if err != nil || !ok {
		return "", "", nil, invalid
	}

	token, err := randomToken()
	if err != nil {
		return "", "", nil, err
	}
	csrf, err := randomToken()
	if err != nil {
		return "", "", nil, err
	}

	if err := s.Repo.CreateSession(ctx, Session{
		TenantID:  user.TenantID,
		UserID:    user.ID,
		TokenHash: HashToken(token),
		CSRFHash:  HashToken(csrf),
		ExpiresAt: s.Clock.Now().Add(SessionTTL),
		SourceIP:  ip,
		UserAgent: ua,
	}); err != nil {
		return "", "", nil, fmt.Errorf("criar sessão: %w", err)
	}
	return token, csrf, user, nil
}

func randomToken() (string, error) {
	raw := make([]byte, sessionBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("gerar token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// decoyHash is a real argon2id hash of a random value, used so that a login
// attempt against an unknown account still pays the KDF cost.
const decoyHash = "$argon2id$v=19$m=19456,t=2,p=1$Y2Fycm9zc2VyaWFkZWRlY29p$ZGVjb3lkZWNveWRlY295ZGVjb3lkZWNveWRlY295MDA"

func (s *Service) Authenticate(ctx context.Context, token string) (Actor, *Session, error) {
	session, user, err := s.Repo.FindSession(ctx, HashToken(token))
	if err != nil || session == nil || user == nil {
		return Actor{}, nil, errs.Coded(errs.ErrUnauthorized, "INVALID_SESSION", "sessão inválida")
	}
	if s.Clock.Now().After(session.ExpiresAt) {
		return Actor{}, nil, errs.Coded(errs.ErrUnauthorized, "SESSION_EXPIRED", "sessão expirada")
	}
	perms, err := s.Repo.PermissionsOf(ctx, user.ID)
	if err != nil {
		return Actor{}, nil, fmt.Errorf("carregar permissões: %w", err)
	}
	return Actor{
		Kind: "user", ID: user.ID.String(), Label: user.DisplayName,
		TenantID: user.TenantID, UserID: &user.ID, Perms: perms,
	}, session, nil
}

// ValidCSRF binds the readable double-submit token to the server-side session.
// Comparing only header == cookie would let a sibling subdomain plant both;
// the stored hash makes the token session-specific without persisting it in
// plaintext.
func ValidCSRF(session *Session, cookieToken, headerToken string) bool {
	if session == nil || cookieToken == "" || headerToken == "" || len(session.CSRFHash) == 0 {
		return false
	}
	cookieHash := HashToken(cookieToken)
	headerHash := HashToken(headerToken)
	return subtle.ConstantTimeCompare(cookieHash, headerHash) == 1 &&
		subtle.ConstantTimeCompare(cookieHash, session.CSRFHash) == 1
}

func (s *Service) Logout(ctx context.Context, token string) error {
	return s.Repo.RevokeSession(ctx, HashToken(token))
}
