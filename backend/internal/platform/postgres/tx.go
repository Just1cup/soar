package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Querier is what repositories talk to. Both *pgxpool.Pool and pgx.Tx satisfy
// it, which is what lets the same repository code run inside or outside a
// transaction without knowing which.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconnCommandTag, error)
}

type txKey struct{}

// TxManager runs a function inside one transaction.
//
// The transaction travels in the context rather than as a parameter threaded
// through every call. That is a deliberate trade: it costs explicitness, and
// it buys the thing that matters here — a use case can call repository, audit
// writer and outbox without any of them knowing about the others, and all
// three land in the same COMMIT.
type TxManager struct{ pool *pgxpool.Pool }

func NewTxManager(pool *pgxpool.Pool) *TxManager { return &TxManager{pool: pool} }

// InTx commits when fn returns nil and rolls back otherwise. Nesting reuses
// the outer transaction: a use case calling another must not get a second,
// independent commit.
func (m *TxManager) InTx(ctx context.Context, fn func(context.Context) error) error {
	if _, ok := ctx.Value(txKey{}).(pgx.Tx); ok {
		return fn(ctx)
	}
	tx, err := m.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op depois de um commit bem-sucedido

	if err := fn(context.WithValue(ctx, txKey{}, tx)); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// DB returns the transaction bound to this context, or the pool.
//
// Nenhuma chamada HTTP externa pode acontecer entre o Begin e o Commit: uma
// transação aberta esperando um vendor por 15 segundos é o jeito mais rápido
// de esgotar o pool (docs/soar/07 §6.9).
func (m *TxManager) DB(ctx context.Context) Querier {
	if tx, ok := ctx.Value(txKey{}).(pgx.Tx); ok {
		return tx
	}
	return m.pool
}
