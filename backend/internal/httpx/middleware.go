package httpx

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/titas/soar/backend/internal/platform/telemetry"
)

type recorder struct {
	http.ResponseWriter
	status int
}

func (r *recorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// RequestID accepts a caller-supplied id only from a trusted header shape, and
// otherwise mints one. It also reads W3C traceparent, so a trace started in
// the browser survives to the database span.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rid := r.Header.Get("X-Request-Id")
		if rid == "" || len(rid) > 128 {
			rid = telemetry.NewRequestID()
		}
		ctx := telemetry.WithRequestID(r.Context(), rid)
		if tp := r.Header.Get("traceparent"); tp != "" {
			if parts := strings.Split(tp, "-"); len(parts) >= 3 {
				ctx = telemetry.WithTraceID(ctx, parts[1])
			}
		}
		w.Header().Set("X-Request-Id", rid)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func Logging(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &recorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			telemetry.LoggerFrom(r.Context(), log).Info("http",
				"method", r.Method, "path", r.URL.Path, "status", rec.status,
				"duration_ms", time.Since(start).Milliseconds())
		})
	}
}

// SecurityHeaders are cheap and apply to every response, including errors.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// LimitBody caps request size before any decoding happens. A parser is the
// wrong place to discover that the body is a gigabyte.
func LimitBody(max int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, max)
			next.ServeHTTP(w, r)
		})
	}
}

func Chain(h http.Handler, mw ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mw) - 1; i >= 0; i-- {
		h = mw[i](h)
	}
	return h
}
