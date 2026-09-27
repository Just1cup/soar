package postgres

import "github.com/jackc/pgx/v5"

// queryExecModePrepareless avoids server-side prepared statement caching,
// which is what makes the same binary work behind PgBouncer in transaction
// pooling mode without surprises.
const queryExecModePrepareless = pgx.QueryExecModeExec
