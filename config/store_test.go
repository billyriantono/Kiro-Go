package config

import (
	"path/filepath"
	"testing"
)

// sampleConfig builds a Config exercising every persisted surface: scalar
// settings, a fully-populated account, an API key, and a prompt filter rule.
func sampleConfig() *Config {
	fallback := false
	return &Config{
		Password:          "s3cret",
		Port:              9090,
		Host:              "127.0.0.1",
		RequireApiKey:     true,
		KiroVersion:       "0.11.107",
		ThinkingSuffix:    "-thinking",
		PreferredEndpoint: "kiro",
		EndpointFallback:  &fallback,
		AllowOverUsage:    true,
		FilterClaudeCode:  true,
		ProxyURL:          "socks5://127.0.0.1:1080",
		LogLevel:          "debug",
		TotalRequests:     42,
		SuccessRequests:   40,
		FailedRequests:    2,
		TotalTokens:       12345,
		TotalCredits:      3.5,
		Accounts: []Account{{
			ID:            "acc-1",
			Email:         "user@corp.com",
			AuthMethod:    "external_idp",
			Provider:      "AzureAD",
			Region:        "eu-central-1",
			AccessToken:   "at",
			RefreshToken:  "rt",
			ClientID:      "cid",
			TokenEndpoint: "https://login.microsoftonline.com/t/oauth2/v2.0/token",
			IssuerURL:     "https://login.microsoftonline.com/t/v2.0",
			Scopes:        "api://cid/x offline_access",
			ExpiresAt:     1900000000,
			Enabled:       true,
			Weight:        2,
			OverageStatus: "ENABLED",
			OverageCap:    10.5,
			UsageCurrent:  1.25,
			TotalCredits:  9.9,
		}},
		ApiKeys: []ApiKeyEntry{{
			ID: "key-1", Name: "default", Key: "sk-abc", Enabled: true,
			CreatedAt: 1700000000, TokenLimit: 1000, CreditLimit: 5.0, TokensUsed: 100,
		}},
		PromptFilterRules: []PromptFilterRule{{
			ID: "rule-1", Name: "strip", Type: "regex", Match: "foo", Replace: "bar", Enabled: true,
		}},
	}
}

func assertConfigEqual(t *testing.T, want, got *Config) {
	t.Helper()
	if got.Password != want.Password || got.Port != want.Port || got.Host != want.Host {
		t.Fatalf("scalar mismatch: got %+v", got)
	}
	if got.RequireApiKey != want.RequireApiKey || got.AllowOverUsage != want.AllowOverUsage ||
		got.FilterClaudeCode != want.FilterClaudeCode || got.LogLevel != want.LogLevel ||
		got.ProxyURL != want.ProxyURL || got.PreferredEndpoint != want.PreferredEndpoint {
		t.Fatalf("settings mismatch: got %+v", got)
	}
	if got.EndpointFallback == nil || *got.EndpointFallback != *want.EndpointFallback {
		t.Fatalf("endpoint fallback tri-state not preserved: got %v", got.EndpointFallback)
	}
	if got.TotalRequests != want.TotalRequests || got.TotalCredits != want.TotalCredits {
		t.Fatalf("stats mismatch: got requests=%d credits=%v", got.TotalRequests, got.TotalCredits)
	}
	if len(got.Accounts) != 1 {
		t.Fatalf("want 1 account, got %d", len(got.Accounts))
	}
	a, wa := got.Accounts[0], want.Accounts[0]
	if a.ID != wa.ID || a.Email != wa.Email || a.AuthMethod != wa.AuthMethod ||
		a.RefreshToken != wa.RefreshToken || a.TokenEndpoint != wa.TokenEndpoint ||
		a.Region != wa.Region || a.Enabled != wa.Enabled || a.Weight != wa.Weight ||
		a.OverageStatus != wa.OverageStatus || a.OverageCap != wa.OverageCap ||
		a.ExpiresAt != wa.ExpiresAt || a.TotalCredits != wa.TotalCredits {
		t.Fatalf("account mismatch:\n got  %+v\n want %+v", a, wa)
	}
	if len(got.ApiKeys) != 1 || got.ApiKeys[0].Key != want.ApiKeys[0].Key ||
		got.ApiKeys[0].Enabled != want.ApiKeys[0].Enabled || got.ApiKeys[0].TokenLimit != want.ApiKeys[0].TokenLimit {
		t.Fatalf("api key mismatch: got %+v", got.ApiKeys)
	}
	if len(got.PromptFilterRules) != 1 || got.PromptFilterRules[0].Match != want.PromptFilterRules[0].Match ||
		!got.PromptFilterRules[0].Enabled {
		t.Fatalf("filter rule mismatch: got %+v", got.PromptFilterRules)
	}
}

// TestSQLiteStoreRoundTrip persists and reloads a full Config through the SQLite
// backend, asserting every surface survives (real columns + settings KV).
func TestSQLiteStoreRoundTrip(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "kiro.db")
	st, err := newSQLStore("sqlite", dbPath)
	if err != nil {
		t.Fatalf("newSQLStore: %v", err)
	}
	defer st.Close()

	// Fresh backend reports empty.
	if c, err := st.Load(); err != nil || c != nil {
		t.Fatalf("fresh store: want (nil,nil), got (%v,%v)", c, err)
	}

	want := sampleConfig()
	if err := st.Save(want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := st.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	assertConfigEqual(t, want, got)

	// Re-saving must not duplicate rows (wholesale replace).
	if err := st.Save(want); err != nil {
		t.Fatalf("re-Save: %v", err)
	}
	got2, _ := st.Load()
	if len(got2.Accounts) != 1 || len(got2.ApiKeys) != 1 {
		t.Fatalf("re-save duplicated rows: accounts=%d keys=%d", len(got2.Accounts), len(got2.ApiKeys))
	}
}

// TestSQLiteStorePersistsAcrossReopen verifies the data survives closing and
// reopening the DB file (the actual durability guarantee operators care about).
func TestSQLiteStorePersistsAcrossReopen(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "kiro.db")
	st, err := newSQLStore("sqlite", dbPath)
	if err != nil {
		t.Fatalf("newSQLStore: %v", err)
	}
	want := sampleConfig()
	if err := st.Save(want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	st.Close()

	st2, err := newSQLStore("sqlite", dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()
	got, err := st2.Load()
	if err != nil {
		t.Fatalf("Load after reopen: %v", err)
	}
	assertConfigEqual(t, want, got)
}

// TestJSONStoreAtomicRoundTrip covers the default file backend, including the
// atomic write path.
func TestJSONStoreAtomicRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	st := &jsonStore{path: path}

	if c, err := st.Load(); err != nil || c != nil {
		t.Fatalf("missing file: want (nil,nil), got (%v,%v)", c, err)
	}
	want := sampleConfig()
	if err := st.Save(want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := st.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	assertConfigEqual(t, want, got)
}

// TestNewStoreSelection pins the backend selection from env-style inputs.
func TestNewStoreSelection(t *testing.T) {
	t.Setenv(envDBDriver, "")
	t.Setenv(envDBURL, "")
	if st, err := newStore("/tmp/config.json"); err != nil {
		t.Fatalf("default: %v", err)
	} else if _, ok := st.(*jsonStore); !ok {
		t.Fatalf("default backend should be jsonStore, got %T", st)
	}

	t.Setenv(envDBDriver, "postgres")
	t.Setenv(envDBURL, "")
	if _, err := newStore("/tmp/config.json"); err == nil {
		t.Fatalf("postgres without DATABASE_URL must error")
	}

	t.Setenv(envDBDriver, "bogus")
	if _, err := newStore("/tmp/config.json"); err == nil {
		t.Fatalf("unknown driver must error")
	}
}

// TestDefaultSQLitePath verifies the SQLite file is derived next to the config.
func TestDefaultSQLitePath(t *testing.T) {
	if got := defaultSQLitePath("/app/data/config.json"); got != "/app/data/kiro.db" {
		t.Fatalf("defaultSQLitePath = %q", got)
	}
	if got := defaultSQLitePath("config.json"); got != "kiro.db" {
		t.Fatalf("defaultSQLitePath(bare) = %q", got)
	}
}
