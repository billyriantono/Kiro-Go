package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// resetGlobals clears package-level state so each test's Init starts clean.
func resetGlobals(t *testing.T) {
	t.Helper()
	cfgLock.Lock()
	cfg = nil
	cfgPath = ""
	if store != nil {
		_ = store.Close()
	}
	store = nil
	cfgLock.Unlock()
}

// TestInitFreshIsUnconfigured verifies a brand-new install seeds an EMPTY
// password (setup required) rather than a known default.
func TestInitFreshIsUnconfigured(t *testing.T) {
	resetGlobals(t)
	defer resetGlobals(t)
	path := filepath.Join(t.TempDir(), "config.json")
	if err := Init(path); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if IsConfigured() {
		t.Fatalf("fresh install must be unconfigured (empty password)")
	}
	if GetPassword() != "" {
		t.Fatalf("fresh install password must be empty, got %q", GetPassword())
	}
}

// TestCompleteSetupOnce verifies setup sets the password and refuses to overwrite
// a configured instance.
func TestCompleteSetupOnce(t *testing.T) {
	resetGlobals(t)
	defer resetGlobals(t)
	if err := Init(filepath.Join(t.TempDir(), "config.json")); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := CompleteSetup("hunter2!"); err != nil {
		t.Fatalf("CompleteSetup: %v", err)
	}
	if !IsConfigured() || GetPassword() != "hunter2!" {
		t.Fatalf("setup did not persist password")
	}
	if err := CompleteSetup("other"); err == nil {
		t.Fatalf("second CompleteSetup must be refused")
	}
	if GetPassword() != "hunter2!" {
		t.Fatalf("password must be unchanged after refused setup, got %q", GetPassword())
	}
}

// TestInitSQLiteMigratesFromJSON is the critical migration guarantee: switching
// to a SQL backend imports an existing config.json exactly once, then reads from
// the DB thereafter.
func TestInitSQLiteMigratesFromJSON(t *testing.T) {
	resetGlobals(t)
	defer resetGlobals(t)

	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "config.json")
	dbPath := filepath.Join(dir, "kiro.db")

	// Seed a legacy config.json with a password + one account.
	legacy := sampleConfig()
	data, _ := json.MarshalIndent(legacy, "", "  ")
	if err := os.WriteFile(jsonPath, data, 0600); err != nil {
		t.Fatalf("seed json: %v", err)
	}

	t.Setenv(envDBDriver, "sqlite")
	t.Setenv(envDBURL, dbPath)

	if err := Init(jsonPath); err != nil {
		t.Fatalf("Init sqlite: %v", err)
	}
	// The account + password must have migrated into the DB.
	if GetPassword() != legacy.Password {
		t.Fatalf("password not migrated: got %q", GetPassword())
	}
	accs := GetAccounts()
	if len(accs) != 1 || accs[0].ID != "acc-1" || accs[0].TokenEndpoint != legacy.Accounts[0].TokenEndpoint {
		t.Fatalf("account not migrated: %+v", accs)
	}

	// The DB file must now exist and be the source of truth on re-init (even if the
	// JSON is subsequently removed).
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("sqlite db not created: %v", err)
	}
	_ = os.Remove(jsonPath)
	resetGlobals(t)
	t.Setenv(envDBDriver, "sqlite")
	t.Setenv(envDBURL, dbPath)
	if err := Init(jsonPath); err != nil {
		t.Fatalf("re-Init sqlite: %v", err)
	}
	if len(GetAccounts()) != 1 {
		t.Fatalf("account lost after reopen from DB: %d", len(GetAccounts()))
	}
}

// TestInitSQLitePersistsUpdates verifies an accessor write (AddAccount) lands in
// the DB and survives a reopen — the end-to-end accessors→store path.
func TestInitSQLitePersistsUpdates(t *testing.T) {
	resetGlobals(t)
	defer resetGlobals(t)

	dir := t.TempDir()
	jsonPath := filepath.Join(dir, "config.json")
	dbPath := filepath.Join(dir, "kiro.db")
	t.Setenv(envDBDriver, "sqlite")
	t.Setenv(envDBURL, dbPath)

	if err := Init(jsonPath); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := CompleteSetup("hunter2!"); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := AddAccount(Account{ID: "x1", Email: "a@b.com", Enabled: true, AuthMethod: "social"}); err != nil {
		t.Fatalf("AddAccount: %v", err)
	}

	resetGlobals(t)
	t.Setenv(envDBDriver, "sqlite")
	t.Setenv(envDBURL, dbPath)
	if err := Init(jsonPath); err != nil {
		t.Fatalf("re-Init: %v", err)
	}
	accs := GetAccounts()
	if len(accs) != 1 || accs[0].ID != "x1" {
		t.Fatalf("added account not persisted to DB: %+v", accs)
	}
}

// TestRelayGating verifies the relay only activates when selected as the outbound
// mode: a stored URL alone leaves ActiveRelay empty until SetRelayEnabled(true),
// and enabling the relay clears any socks/http proxy (mutually exclusive).
func TestRelayGating(t *testing.T) {
	resetGlobals(t)
	defer resetGlobals(t)
	if err := Init(filepath.Join(t.TempDir(), "config.json")); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Configure a relay URL/secret but leave the mode unselected.
	if err := UpdateRelaySettings("https://r.example.workers.dev", "sekret"); err != nil {
		t.Fatalf("UpdateRelaySettings: %v", err)
	}
	if u, _ := ActiveRelay(); u != "" {
		t.Fatalf("relay must stay dormant until selected, got active %q", u)
	}
	if IsRelayEnabled() {
		t.Fatal("relay should not be enabled yet")
	}

	// Set a proxy, then enable the relay — enabling must clear the proxy.
	if err := UpdateProxySettings("socks5://127.0.0.1:1080"); err != nil {
		t.Fatalf("UpdateProxySettings: %v", err)
	}
	if err := SetRelayEnabled(true); err != nil {
		t.Fatalf("SetRelayEnabled: %v", err)
	}
	if u, s := ActiveRelay(); u != "https://r.example.workers.dev" || s != "sekret" {
		t.Fatalf("active relay = %q/%q", u, s)
	}
	if GetProxyURL() != "" {
		t.Fatalf("enabling relay must clear the proxy URL, got %q", GetProxyURL())
	}

	// Deselecting the relay makes it dormant again while keeping its stored config.
	if err := SetRelayEnabled(false); err != nil {
		t.Fatalf("SetRelayEnabled(false): %v", err)
	}
	if u, _ := ActiveRelay(); u != "" {
		t.Fatalf("relay should be dormant after deselect, got %q", u)
	}
	if url, _ := GetRelaySettings(); url != "https://r.example.workers.dev" {
		t.Fatalf("stored relay URL must be retained, got %q", url)
	}
}
