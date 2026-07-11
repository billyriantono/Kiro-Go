package config

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib" // database/sql driver name "pgx"
	_ "modernc.org/sqlite"             // pure-Go driver name "sqlite" (CGO-free)
)

// sqlStore persists the config into normalized tables over database/sql. The
// same code drives SQLite (modernc.org/sqlite, pure-Go) and PostgreSQL (pgx
// stdlib); the only dialect difference is the bind-parameter placeholder
// (? vs $N, handled by rebind), otherwise absorbed by portable column types
// (TEXT / BIGINT / DOUBLE PRECISION / INTEGER-as-bool, all with the right
// affinity on both engines).
//
// Entities operators actually inspect — accounts, api_keys, prompt filter rules
// — are real column-per-field tables. Scalar server settings and global stats
// live in a key/value settings table (each a visible row), since they are
// configuration values, not an entity set.
type sqlStore struct {
	db     *sql.DB
	driver string // "sqlite" | "pgx"
}

func newSQLStore(driver, dsn string) (*sqlStore, error) {
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", driver, err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping %s: %w", driver, err)
	}
	// SQLite is single-writer; one connection avoids "database is locked" under
	// the config's concurrent Save() calls. Postgres pools normally.
	if driver == "sqlite" {
		db.SetMaxOpenConns(1)
		if _, err := db.Exec("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;"); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("sqlite pragma: %w", err)
		}
	}
	s := &sqlStore{db: db, driver: driver}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *sqlStore) Close() error { return s.db.Close() }

// Backend returns a secret-free label ("sqlite" / "postgres") for logging — the
// DSN is deliberately never included since it may carry credentials.
func (s *sqlStore) Backend() string {
	if s.driver == "pgx" {
		return "postgres"
	}
	return "sqlite"
}

// rebind converts "?" placeholders to "$1, $2, …" for the pgx driver; SQLite
// takes "?" as-is.
func (s *sqlStore) rebind(query string) string {
	if s.driver != "pgx" {
		return query
	}
	var b strings.Builder
	n := 0
	for i := 0; i < len(query); i++ {
		if query[i] == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
		} else {
			b.WriteByte(query[i])
		}
	}
	return b.String()
}

// accountColumns is the single source of truth for the accounts table column
// order. accountValues and scanAccount MUST list fields in exactly this order.
var accountColumns = []string{
	"id", "email", "user_id", "nickname",
	"access_token", "refresh_token", "client_id", "client_secret",
	"auth_method", "provider", "region", "start_url", "expires_at",
	"machine_id", "profile_arn", "token_endpoint", "issuer_url", "scopes",
	"proxy_url", "weight",
	"overage_status", "overage_capability", "overage_cap", "overage_rate", "current_overages", "overage_checked_at",
	"enabled", "ban_status", "ban_reason", "ban_time",
	"subscription_type", "subscription_title", "days_remaining",
	"usage_current", "usage_limit", "usage_percent", "next_reset_date", "last_refresh",
	"trial_usage_current", "trial_usage_limit", "trial_usage_percent", "trial_status", "trial_expires_at",
	"request_count", "error_count", "last_used", "total_tokens", "total_credits",
}

func accountValues(a *Account) []any {
	return []any{
		a.ID, a.Email, a.UserId, a.Nickname,
		a.AccessToken, a.RefreshToken, a.ClientID, a.ClientSecret,
		a.AuthMethod, a.Provider, a.Region, a.StartUrl, a.ExpiresAt,
		a.MachineId, a.ProfileArn, a.TokenEndpoint, a.IssuerURL, a.Scopes,
		a.ProxyURL, a.Weight,
		a.OverageStatus, a.OverageCapability, a.OverageCap, a.OverageRate, a.CurrentOverages, a.OverageCheckedAt,
		boolToInt(a.Enabled), a.BanStatus, a.BanReason, a.BanTime,
		a.SubscriptionType, a.SubscriptionTitle, a.DaysRemaining,
		a.UsageCurrent, a.UsageLimit, a.UsagePercent, a.NextResetDate, a.LastRefresh,
		a.TrialUsageCurrent, a.TrialUsageLimit, a.TrialUsagePercent, a.TrialStatus, a.TrialExpiresAt,
		a.RequestCount, a.ErrorCount, a.LastUsed, a.TotalTokens, a.TotalCredits,
	}
}

func scanAccount(rows *sql.Rows) (Account, error) {
	var a Account
	var enabled int
	dest := []any{
		&a.ID, &a.Email, &a.UserId, &a.Nickname,
		&a.AccessToken, &a.RefreshToken, &a.ClientID, &a.ClientSecret,
		&a.AuthMethod, &a.Provider, &a.Region, &a.StartUrl, &a.ExpiresAt,
		&a.MachineId, &a.ProfileArn, &a.TokenEndpoint, &a.IssuerURL, &a.Scopes,
		&a.ProxyURL, &a.Weight,
		&a.OverageStatus, &a.OverageCapability, &a.OverageCap, &a.OverageRate, &a.CurrentOverages, &a.OverageCheckedAt,
		&enabled, &a.BanStatus, &a.BanReason, &a.BanTime,
		&a.SubscriptionType, &a.SubscriptionTitle, &a.DaysRemaining,
		&a.UsageCurrent, &a.UsageLimit, &a.UsagePercent, &a.NextResetDate, &a.LastRefresh,
		&a.TrialUsageCurrent, &a.TrialUsageLimit, &a.TrialUsagePercent, &a.TrialStatus, &a.TrialExpiresAt,
		&a.RequestCount, &a.ErrorCount, &a.LastUsed, &a.TotalTokens, &a.TotalCredits,
	}
	if err := rows.Scan(dest...); err != nil {
		return Account{}, err
	}
	a.Enabled = enabled != 0
	return a, nil
}

var apiKeyColumns = []string{
	"id", "name", "key", "enabled", "migrated", "created_at", "last_used_at",
	"token_limit", "credit_limit", "tokens_used", "credits_used", "requests_count",
}

func apiKeyValues(k *ApiKeyEntry) []any {
	return []any{
		k.ID, k.Name, k.Key, boolToInt(k.Enabled), boolToInt(k.Migrated), k.CreatedAt, k.LastUsedAt,
		k.TokenLimit, k.CreditLimit, k.TokensUsed, k.CreditsUsed, k.RequestsCount,
	}
}

func scanApiKey(rows *sql.Rows) (ApiKeyEntry, error) {
	var k ApiKeyEntry
	var enabled, migrated int
	if err := rows.Scan(
		&k.ID, &k.Name, &k.Key, &enabled, &migrated, &k.CreatedAt, &k.LastUsedAt,
		&k.TokenLimit, &k.CreditLimit, &k.TokensUsed, &k.CreditsUsed, &k.RequestsCount,
	); err != nil {
		return ApiKeyEntry{}, err
	}
	k.Enabled = enabled != 0
	k.Migrated = migrated != 0
	return k, nil
}

// migrate creates the schema if absent. The DDL uses only types with consistent
// affinity across SQLite and Postgres (TEXT, BIGINT, DOUBLE PRECISION, INTEGER).
func (s *sqlStore) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS settings (
			key   TEXT PRIMARY KEY,
			value TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS accounts (
			id TEXT PRIMARY KEY,
			email TEXT, user_id TEXT, nickname TEXT,
			access_token TEXT, refresh_token TEXT, client_id TEXT, client_secret TEXT,
			auth_method TEXT, provider TEXT, region TEXT, start_url TEXT, expires_at BIGINT,
			machine_id TEXT, profile_arn TEXT, token_endpoint TEXT, issuer_url TEXT, scopes TEXT,
			proxy_url TEXT, weight BIGINT,
			overage_status TEXT, overage_capability TEXT, overage_cap DOUBLE PRECISION,
			overage_rate DOUBLE PRECISION, current_overages DOUBLE PRECISION, overage_checked_at BIGINT,
			enabled INTEGER, ban_status TEXT, ban_reason TEXT, ban_time BIGINT,
			subscription_type TEXT, subscription_title TEXT, days_remaining BIGINT,
			usage_current DOUBLE PRECISION, usage_limit DOUBLE PRECISION, usage_percent DOUBLE PRECISION,
			next_reset_date TEXT, last_refresh BIGINT,
			trial_usage_current DOUBLE PRECISION, trial_usage_limit DOUBLE PRECISION,
			trial_usage_percent DOUBLE PRECISION, trial_status TEXT, trial_expires_at BIGINT,
			request_count BIGINT, error_count BIGINT, last_used BIGINT, total_tokens BIGINT, total_credits DOUBLE PRECISION,
			position BIGINT
		)`,
		`CREATE TABLE IF NOT EXISTS api_keys (
			id TEXT PRIMARY KEY,
			name TEXT, key TEXT, enabled INTEGER, migrated INTEGER,
			created_at BIGINT, last_used_at BIGINT,
			token_limit BIGINT, credit_limit DOUBLE PRECISION,
			tokens_used BIGINT, credits_used DOUBLE PRECISION, requests_count BIGINT,
			position BIGINT
		)`,
		`CREATE TABLE IF NOT EXISTS prompt_filter_rules (
			id TEXT PRIMARY KEY,
			name TEXT, type TEXT, match TEXT, replace TEXT, enabled INTEGER,
			position BIGINT
		)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	return nil
}

// Load reconstructs the Config from the tables. It returns (nil, nil) when the
// store is empty (no settings row) so the caller seeds a default / migrates.
func (s *sqlStore) Load() (*Config, error) {
	settings, err := s.loadSettings()
	if err != nil {
		return nil, err
	}
	if len(settings) == 0 {
		return nil, nil // fresh backend
	}
	c := &Config{}
	applySettings(c, settings)

	if c.Accounts, err = s.loadAccounts(); err != nil {
		return nil, err
	}
	if c.ApiKeys, err = s.loadApiKeys(); err != nil {
		return nil, err
	}
	if c.PromptFilterRules, err = s.loadRules(); err != nil {
		return nil, err
	}
	return c, nil
}

func (s *sqlStore) loadSettings() (map[string]string, error) {
	rows, err := s.db.Query(`SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

func (s *sqlStore) loadAccounts() ([]Account, error) {
	q := `SELECT ` + strings.Join(accountColumns, ", ") + ` FROM accounts ORDER BY position ASC`
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	accounts := []Account{}
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, a)
	}
	return accounts, rows.Err()
}

func (s *sqlStore) loadApiKeys() ([]ApiKeyEntry, error) {
	q := `SELECT ` + strings.Join(apiKeyColumns, ", ") + ` FROM api_keys ORDER BY position ASC`
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []ApiKeyEntry
	for rows.Next() {
		k, err := scanApiKey(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

func (s *sqlStore) loadRules() ([]PromptFilterRule, error) {
	rows, err := s.db.Query(`SELECT id, name, type, match, replace, enabled FROM prompt_filter_rules ORDER BY position ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []PromptFilterRule
	for rows.Next() {
		var r PromptFilterRule
		var enabled int
		if err := rows.Scan(&r.ID, &r.Name, &r.Type, &r.Match, &r.Replace, &enabled); err != nil {
			return nil, err
		}
		r.Enabled = enabled != 0
		rules = append(rules, r)
	}
	return rules, rows.Err()
}

// Save persists the whole config in one transaction: entity tables are replaced
// wholesale (bounded small sets — a handful of accounts/keys), settings upserted.
// The transaction makes the write atomic, so a crash can never leave a partially
// written config.
func (s *sqlStore) Save(cfg *Config) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	rb := s.rebind

	for k, v := range settingsFrom(cfg) {
		if _, err := tx.Exec(rb(`INSERT INTO settings (key, value) VALUES (?, ?)
			ON CONFLICT (key) DO UPDATE SET value = excluded.value`), k, v); err != nil {
			return fmt.Errorf("save setting %s: %w", k, err)
		}
	}

	if _, err := tx.Exec(`DELETE FROM accounts`); err != nil {
		return err
	}
	insAcc := rb(`INSERT INTO accounts (` + strings.Join(accountColumns, ", ") + `, position) VALUES (` +
		placeholders(len(accountColumns)+1) + `)`)
	for i := range cfg.Accounts {
		args := append(accountValues(&cfg.Accounts[i]), i)
		if _, err := tx.Exec(insAcc, args...); err != nil {
			return fmt.Errorf("save account %s: %w", cfg.Accounts[i].ID, err)
		}
	}

	if _, err := tx.Exec(`DELETE FROM api_keys`); err != nil {
		return err
	}
	insKey := rb(`INSERT INTO api_keys (` + strings.Join(apiKeyColumns, ", ") + `, position) VALUES (` +
		placeholders(len(apiKeyColumns)+1) + `)`)
	for i := range cfg.ApiKeys {
		args := append(apiKeyValues(&cfg.ApiKeys[i]), i)
		if _, err := tx.Exec(insKey, args...); err != nil {
			return fmt.Errorf("save api key %s: %w", cfg.ApiKeys[i].ID, err)
		}
	}

	if _, err := tx.Exec(`DELETE FROM prompt_filter_rules`); err != nil {
		return err
	}
	insRule := rb(`INSERT INTO prompt_filter_rules (id, name, type, match, replace, enabled, position)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)
	for i := range cfg.PromptFilterRules {
		r := &cfg.PromptFilterRules[i]
		if _, err := tx.Exec(insRule, r.ID, r.Name, r.Type, r.Match, r.Replace, boolToInt(r.Enabled), i); err != nil {
			return fmt.Errorf("save filter rule %s: %w", r.ID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// placeholders returns "?, ?, …" with n entries (rebind maps them to $N for pgx).
func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.Repeat("?, ", n-1) + "?"
}
