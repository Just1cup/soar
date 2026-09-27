package postgres

import (
	"errors"
	"fmt"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/titas/soar/backend/migrations"
)

// migrationURL rewrites the scheme to the one golang-migrate's pgx/v5 driver
// registers itself under. The operator configures one DATABASE_URL and the
// translation happens here, rather than two URLs that can drift apart.
func migrationURL(databaseURL string) string {
	for _, scheme := range []string{"postgres://", "postgresql://"} {
		if strings.HasPrefix(databaseURL, scheme) {
			return "pgx5://" + strings.TrimPrefix(databaseURL, scheme)
		}
	}
	return databaseURL
}

func migrator(databaseURL string) (*migrate.Migrate, error) {
	src, err := iofs.New(migrations.FS, ".")
	if err != nil {
		return nil, fmt.Errorf("abrir migrations embarcadas: %w", err)
	}
	m, err := migrate.NewWithSourceInstance("iofs", src, migrationURL(databaseURL))
	if err != nil {
		return nil, fmt.Errorf("iniciar migrator: %w", err)
	}
	return m, nil
}

// Migrate applies every pending migration and reports whether anything moved.
func Migrate(databaseURL string) (bool, error) {
	m, err := migrator(databaseURL)
	if err != nil {
		return false, err
	}
	defer func() { _, _ = m.Close() }()

	switch err := m.Up(); {
	case err == nil:
		return true, nil
	case errors.Is(err, migrate.ErrNoChange):
		return false, nil
	default:
		return false, fmt.Errorf("aplicar migrations: %w", err)
	}
}

// Version reports the schema version. /health/ready uses it: an API serving
// against a schema it does not expect is not ready, it is dangerous.
func Version(databaseURL string) (version uint, dirty bool, err error) {
	m, err := migrator(databaseURL)
	if err != nil {
		return 0, false, err
	}
	defer func() { _, _ = m.Close() }()

	version, dirty, err = m.Version()
	if errors.Is(err, migrate.ErrNilVersion) {
		return 0, false, nil
	}
	return version, dirty, err
}
