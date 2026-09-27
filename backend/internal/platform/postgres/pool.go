// Package postgres owns the connection pool and the migrations.
//
// The pool is bounded on purpose. The classic Kubernetes failure is
// pods × pool > max_connections with almost no real load; the fix costs
// nothing and belongs here rather than in a runbook.
package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func NewPool(ctx context.Context, url string, maxConns int32) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	cfg.MaxConns = maxConns
	cfg.MinConns = 1
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.MaxConnIdleTime = 5 * time.Minute
	cfg.HealthCheckPeriod = 30 * time.Second
	// Nada no código pode depender de estado de sessão: PgBouncer em
	// transaction pooling não suporta SET, LISTEN nem advisory lock de sessão
	// (docs/soar/07 §12). Preparar por statement mantém a compatibilidade.
	cfg.ConnConfig.DefaultQueryExecMode = queryExecModePrepareless

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("criar pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return pool, nil
}
