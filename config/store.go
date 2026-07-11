package config

import (
	"fmt"
	"os"
	"strings"
)

// Store is the persistence backend for the whole Config document. The in-memory
// cfg model and every Get*/Update* accessor stay exactly as they are — only Load
// and Save delegate here, so swapping the backend never touches proxy/ or auth/.
//
// Implementations:
//   - jsonStore: the historical single-file backend (atomic write), default.
//   - sqlStore:  normalized tables over database/sql, agnostic across SQLite
//     (modernc.org/sqlite, pure-Go) and PostgreSQL (jackc/pgx stdlib).
//
// Save persists the FULL config each call (same semantics as the JSON backend
// always had — a full rewrite), so the existing accessors need no changes; the
// SQL backend just does it as one transaction over real tables.
type Store interface {
	// Load returns the persisted config. It returns (nil, nil) when the backend
	// is empty (fresh install) so the caller can seed a default.
	Load() (*Config, error)
	// Save persists the entire config atomically.
	Save(cfg *Config) error
	// Close releases backend resources (a no-op for the file backend).
	Close() error
	// Backend returns a short, secret-free label for startup logging
	// (e.g. "sqlite", "postgres", "json:/app/data/config.json").
	Backend() string
}

// storeBackendEnv selects the persistence backend. Unset/"json"/"file" keeps the
// historical single-file behaviour; "sqlite"/"postgres" (or a DATABASE_URL) opts
// into SQL. Kept as vars so tests can drive them directly.
const (
	envDBDriver = "DB_DRIVER"
	envDBURL    = "DATABASE_URL"
)

// newStore builds the persistence backend from the environment, falling back to
// the JSON file at jsonPath. Selection order:
//  1. DB_DRIVER=sqlite|postgres|json (explicit).
//  2. DATABASE_URL set → inferred from its scheme (postgres:// → postgres,
//     otherwise sqlite with the URL as the file path).
//  3. neither → JSON file (backwards compatible default).
func newStore(jsonPath string) (Store, error) {
	driver := strings.ToLower(strings.TrimSpace(os.Getenv(envDBDriver)))
	dbURL := strings.TrimSpace(os.Getenv(envDBURL))

	if driver == "" && dbURL != "" {
		if strings.HasPrefix(dbURL, "postgres://") || strings.HasPrefix(dbURL, "postgresql://") {
			driver = "postgres"
		} else {
			driver = "sqlite"
		}
	}

	switch driver {
	case "", "json", "file":
		return &jsonStore{path: jsonPath}, nil
	case "sqlite", "sqlite3":
		dsn := dbURL
		if dsn == "" {
			// Default to a DB file beside the JSON config so a bare DB_DRIVER=sqlite
			// still lands on the persistent data volume.
			dsn = defaultSQLitePath(jsonPath)
		}
		return newSQLStore("sqlite", dsn)
	case "postgres", "postgresql", "pgx":
		if dbURL == "" {
			return nil, fmt.Errorf("DB_DRIVER=postgres requires DATABASE_URL")
		}
		return newSQLStore("pgx", dbURL)
	default:
		return nil, fmt.Errorf("unknown DB_DRIVER %q (want json|sqlite|postgres)", driver)
	}
}

// defaultSQLitePath derives kiro.db next to the JSON config path so the SQLite
// file lives on the same persistent volume operators already mount for data.
func defaultSQLitePath(jsonPath string) string {
	if jsonPath == "" {
		return "kiro.db"
	}
	dir := jsonPath
	for i := len(dir) - 1; i >= 0; i-- {
		if dir[i] == '/' || dir[i] == '\\' {
			return dir[:i+1] + "kiro.db"
		}
	}
	return "kiro.db"
}
