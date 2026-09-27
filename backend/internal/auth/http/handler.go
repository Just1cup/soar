// Package http exposes login, logout and whoami, and the middleware that puts
// the actor in the context.
package http

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/titas/soar/backend/internal/auth"
	"github.com/titas/soar/backend/internal/core/errs"
	"github.com/titas/soar/backend/internal/core/id"
	"github.com/titas/soar/backend/internal/httpx"
)

type Handler struct {
	Service *auth.Service
	Tenant  id.TenantID
	Log     *slog.Logger
	// SecureCookie is false only over plaintext localhost. In any deployment
	// that serves TLS it must be true, and the config refuses otherwise.
	SecureCookie bool
	Limiter      *LoginLimiter
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/auth/login", h.login)
	mux.HandleFunc("POST /api/v1/auth/logout", h.logout)
	mux.HandleFunc("GET /api/v1/auth/me", h.me)
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		httpx.Fail(w, r, h.Log, errs.Coded(errs.ErrValidation, "INVALID_BODY", "corpo inválido"))
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		httpx.Fail(w, r, h.Log, errs.Coded(errs.ErrValidation, "INVALID_BODY", "corpo inválido"))
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" || len(req.Email) > 254 || req.Password == "" || len(req.Password) > 1024 {
		httpx.Fail(w, r, h.Log, errs.Coded(errs.ErrValidation, "INVALID_CREDENTIALS_FORMAT",
			"e-mail ou senha fora do formato aceito"))
		return
	}
	ip := clientIP(r)
	if h.Limiter != nil && !h.Limiter.Allow(ip, req.Email, time.Now()) {
		h.Log.Warn("auth.login.rate_limited", "source_ip", ip)
		httpx.Fail(w, r, h.Log, errs.Coded(errs.ErrRateLimited, "LOGIN_RATE_LIMITED",
			"muitas tentativas; aguarde antes de tentar novamente"))
		return
	}
	token, csrf, user, err := h.Service.Login(r.Context(), h.Tenant, req.Email, req.Password,
		ip, r.UserAgent())
	if err != nil {
		h.Log.Warn("auth.login.failed", "source_ip", ip)
		httpx.Fail(w, r, h.Log, err)
		return
	}
	if h.Limiter != nil {
		h.Limiter.ResetAccount(req.Email)
	}
	expires := time.Now().Add(auth.SessionTTL)
	http.SetCookie(w, &http.Cookie{
		Name:  auth.SessionCookie,
		Value: token,
		Path:  "/",
		// HttpOnly: o token nunca é legível por JavaScript, então um XSS não
		// vira roubo de sessão. SameSite=Strict é a base da defesa de CSRF,
		// somada ao token de duplo envio abaixo.
		HttpOnly: true,
		Secure:   h.SecureCookie,
		SameSite: http.SameSiteStrictMode,
		Expires:  expires,
		MaxAge:   int(auth.SessionTTL.Seconds()),
	})
	http.SetCookie(w, &http.Cookie{
		Name: auth.CSRFCookie, Value: csrf, Path: "/", HttpOnly: false,
		Secure: h.SecureCookie, SameSite: http.SameSiteStrictMode,
		Expires: expires, MaxAge: int(auth.SessionTTL.Seconds()),
	})
	h.Log.Info("auth.login.succeeded", "actor_id", user.ID.String(), "source_ip", ip)
	httpx.OK(w, r, http.StatusOK, map[string]any{
		"user_id": user.ID.String(), "email": user.Email, "display_name": user.DisplayName,
	}, nil)
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(auth.SessionCookie); err == nil {
		if err := h.Service.Logout(r.Context(), c.Value); err != nil {
			httpx.Fail(w, r, h.Log, err)
			return
		}
	}
	http.SetCookie(w, &http.Cookie{
		Name: auth.SessionCookie, Value: "", Path: "/", HttpOnly: true,
		Secure: h.SecureCookie, SameSite: http.SameSiteStrictMode, MaxAge: -1,
	})
	http.SetCookie(w, &http.Cookie{
		Name: auth.CSRFCookie, Value: "", Path: "/", HttpOnly: false,
		Secure: h.SecureCookie, SameSite: http.SameSiteStrictMode, MaxAge: -1,
	})
	httpx.OK(w, r, http.StatusOK, map[string]any{"status": "logged_out"}, nil)
}

func (h *Handler) me(w http.ResponseWriter, r *http.Request) {
	actor, err := auth.FromContext(r.Context())
	if err != nil {
		httpx.Fail(w, r, h.Log, err)
		return
	}
	perms := make([]string, 0, len(actor.Perms))
	for p := range actor.Perms {
		perms = append(perms, p)
	}
	sort.Strings(perms)
	httpx.OK(w, r, http.StatusOK, map[string]any{
		"actor_id": actor.ID, "kind": actor.Kind, "display_name": actor.Label,
		// O frontend usa isto para ESCONDER botão. Quem decide é o backend.
		"permissions": perms,
	}, nil)
}

// Middleware puts the actor in the context, or rejects.
//
// `public` are the paths that must work before there is a session. Everything
// else requires one: fail closed, and the list of exceptions is explicit and
// short enough to read.
func Middleware(service *auth.Service, log *slog.Logger, public ...string) func(http.Handler) http.Handler {
	isPublic := func(path string) bool {
		for _, p := range public {
			if path == p || strings.HasPrefix(path, p+"/") {
				return true
			}
		}
		return false
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isPublic(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			cookie, err := r.Cookie(auth.SessionCookie)
			if err != nil {
				httpx.Fail(w, r, log, errs.Coded(errs.ErrUnauthorized, "NOT_AUTHENTICATED",
					"autenticação necessária"))
				return
			}
			actor, session, err := service.Authenticate(r.Context(), cookie.Value)
			if err != nil {
				httpx.Fail(w, r, log, err)
				return
			}
			if unsafeMethod(r.Method) {
				csrfCookie, cookieErr := r.Cookie(auth.CSRFCookie)
				header := r.Header.Get("X-CSRF-Token")
				if cookieErr != nil || !auth.ValidCSRF(session, csrfCookie.Value, header) {
					httpx.Fail(w, r, log, errs.Coded(errs.ErrForbidden, "CSRF_INVALID",
						"token CSRF ausente ou inválido"))
					return
				}
			}
			next.ServeHTTP(w, r.WithContext(auth.WithActor(r.Context(), actor)))
		})
	}
}

func unsafeMethod(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	// O Nginx sobrescreve X-Real-IP. Só confiamos nele quando o peer imediato
	// é loopback/privado; um cliente público falando direto com a API não pode
	// escolher a chave do próprio rate limit.
	peer := net.ParseIP(host)
	if peer != nil && (peer.IsLoopback() || peer.IsPrivate()) {
		if forwarded := net.ParseIP(strings.TrimSpace(r.Header.Get("X-Real-IP"))); forwarded != nil {
			return forwarded.String()
		}
	}
	return host
}
