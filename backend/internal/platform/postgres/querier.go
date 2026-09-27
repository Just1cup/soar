package postgres

import "github.com/jackc/pgx/v5/pgconn"

// pgconnCommandTag exists only so the Querier interface can name pgx's return
// type without every caller importing pgconn.
type pgconnCommandTag = pgconn.CommandTag
