// Package telemetry carries the request identity through the whole call, and
// makes the log machine-readable.
//
// Every log line gets request_id; every response gets it in the body. That is
// what turns "it failed for a user at some point" into one grep.
package telemetry

import (
	"context"
	"log/slog"
	"os"

	"github.com/google/uuid"
)

type ctxKey int

const (
	keyRequestID ctxKey = iota
	keyTraceID
)

func NewLogger(level string) *slog.Logger {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
}

func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, keyRequestID, requestID)
}

func RequestID(ctx context.Context) string {
	if v, ok := ctx.Value(keyRequestID).(string); ok {
		return v
	}
	return ""
}

func WithTraceID(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, keyTraceID, traceID)
}

func TraceID(ctx context.Context) string {
	if v, ok := ctx.Value(keyTraceID).(string); ok {
		return v
	}
	return ""
}

func NewRequestID() string { return uuid.NewString() }

// LoggerFrom returns a logger already tagged with the request identity, so a
// handler never has to remember to add it.
func LoggerFrom(ctx context.Context, base *slog.Logger) *slog.Logger {
	l := base
	if rid := RequestID(ctx); rid != "" {
		l = l.With("request_id", rid)
	}
	if tid := TraceID(ctx); tid != "" {
		l = l.With("trace_id", tid)
	}
	return l
}
