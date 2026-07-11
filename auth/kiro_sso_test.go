package auth

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestKiroCallbackBindAddrs locks in the secure default (loopback-only) and the
// KIRO_SSO_CALLBACK_BIND override used for containerized deployments.
func TestKiroCallbackBindAddrs(t *testing.T) {
	// Unset/blank -> loopback v4 (mandatory) + v6 (best-effort).
	t.Setenv("KIRO_SSO_CALLBACK_BIND", "")
	if got, want := kiroCallbackBindAddrs(), []string{"127.0.0.1:3128", "[::1]:3128"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("default bind addrs = %v, want %v", got, want)
	}
	// Whitespace is treated as unset (still the secure default).
	t.Setenv("KIRO_SSO_CALLBACK_BIND", "   ")
	if got := kiroCallbackBindAddrs(); len(got) != 2 {
		t.Fatalf("whitespace should fall back to loopback default, got %v", got)
	}
	// IPv4 wildcard override -> single mandatory bind.
	t.Setenv("KIRO_SSO_CALLBACK_BIND", "0.0.0.0")
	if got, want := kiroCallbackBindAddrs(), []string{"0.0.0.0:3128"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("0.0.0.0 bind addrs = %v, want %v", got, want)
	}
	// IPv6 wildcard override -> bracketed host:port.
	t.Setenv("KIRO_SSO_CALLBACK_BIND", "::")
	if got, want := kiroCallbackBindAddrs(), []string{"[::]:3128"}; !reflect.DeepEqual(got, want) {
		t.Fatalf(":: bind addrs = %v, want %v", got, want)
	}
}

// makeJWT builds an unsigned JWT-shaped string whose payload encodes claims, for
// testing the best-effort claim extraction (the signature is never verified).
func makeJWT(claims map[string]string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payloadBytes, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	return header + "." + payload + ".sig"
}

func TestExtractEmailFromJWT(t *testing.T) {
	cases := []struct {
		name   string
		claims map[string]string
		want   string
	}{
		{"email claim", map[string]string{"email": "a@b.com"}, "a@b.com"},
		// Azure AD v2.0 tokens usually omit "email" and carry preferred_username.
		{"preferred_username fallback", map[string]string{"preferred_username": "user@tenant.onmicrosoft.com"}, "user@tenant.onmicrosoft.com"},
		{"upn fallback", map[string]string{"upn": "u@corp.com"}, "u@corp.com"},
		{"none", map[string]string{"sub": "xyz"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExtractEmailFromJWT(makeJWT(tc.claims)); got != tc.want {
				t.Fatalf("ExtractEmailFromJWT = %q, want %q", got, tc.want)
			}
		})
	}
	if got := ExtractEmailFromJWT("not-a-jwt"); got != "" {
		t.Fatalf("malformed token should yield empty email, got %q", got)
	}
}

func TestValidateExternalIdpEndpoint(t *testing.T) {
	valid := []string{
		"https://login.microsoftonline.com/5fbc183e/v2.0",
		"https://login.microsoftonline.us/tenant/v2.0",
		"https://login.microsoftonline.cn/tenant/oauth2/v2.0/token",
	}
	for _, u := range valid {
		if err := validateExternalIdpEndpoint(u); err != nil {
			t.Fatalf("expected %q to be allowed, got %v", u, err)
		}
	}
	invalid := []string{
		"http://login.microsoftonline.com/x",      // not https
		"https://evil-microsoftonline.com/x",       // suffix not anchored to a subdomain boundary
		"https://login.microsoftonline.com.evil.co", // not an allowed suffix
		"https://10.0.0.5/x",                        // IP literal
		"https://accounts.google.com/x",             // not allow-listed
		"https:///x",                                // no host
	}
	for _, u := range invalid {
		if err := validateExternalIdpEndpoint(u); err == nil {
			t.Fatalf("expected %q to be rejected", u)
		}
	}
}

func TestExternalIdpAuthorizeURL(t *testing.T) {
	raw := externalIdpAuthorizeURL(
		"https://login.microsoftonline.com/t/oauth2/v2.0/authorize",
		"client-123",
		"http://localhost:3128/oauth/callback",
		"api://client-123/codewhisperer:conversations offline_access",
		"challenge-abc",
		"state-xyz",
		"user@corp.com",
	)
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	q := u.Query()
	checks := map[string]string{
		"client_id":             "client-123",
		"response_type":         "code",
		"redirect_uri":          "http://localhost:3128/oauth/callback",
		"code_challenge":        "challenge-abc",
		"code_challenge_method": "S256",
		"response_mode":         "query",
		"state":                 "state-xyz",
		"login_hint":            "user@corp.com",
	}
	for k, want := range checks {
		if got := q.Get(k); got != want {
			t.Fatalf("authorize url param %q = %q, want %q", k, got, want)
		}
	}
	if !strings.Contains(q.Get("scope"), "offline_access") {
		t.Fatalf("expected offline_access in scope, got %q", q.Get("scope"))
	}
}

// TestExternalIdpAuthorizeURLOmitsEmptyLoginHint ensures we don't emit an empty
// login_hint parameter when the portal supplied none.
func TestExternalIdpAuthorizeURLOmitsEmptyLoginHint(t *testing.T) {
	raw := externalIdpAuthorizeURL("https://login.microsoftonline.com/t/authorize", "c", "http://localhost:3128/oauth/callback", "s", "ch", "st", "")
	u, _ := url.Parse(raw)
	if _, ok := u.Query()["login_hint"]; ok {
		t.Fatalf("login_hint should be omitted when empty")
	}
}

// TestRefreshExternalIdpToken drives the refresh_token grant against a stub IdP
// token endpoint and asserts the form encoding and response mapping.
func TestRefreshExternalIdpToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if r.Form.Get("grant_type") != "refresh_token" {
			t.Fatalf("grant_type = %q", r.Form.Get("grant_type"))
		}
		if r.Form.Get("client_id") != "azure-client" {
			t.Fatalf("client_id = %q", r.Form.Get("client_id"))
		}
		if r.Form.Get("refresh_token") != "old-refresh" {
			t.Fatalf("refresh_token = %q", r.Form.Get("refresh_token"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600}`))
	}))
	defer srv.Close()

	// The POST boundary re-validates tokenEndpoint against the allow-list, which rejects
	// the httptest URL (http + 127.0.0.1). Install a permissive validator for the test.
	restore := SetExternalIdpValidatorForTest(func(string) error { return nil })
	defer SetExternalIdpValidatorForTest(restore)

	access, refresh, expiresAt, profileArn, err := refreshExternalIdpToken(
		"old-refresh", "azure-client", srv.URL, "api://x/codewhisperer:conversations offline_access", srv.Client(),
	)
	if err != nil {
		t.Fatalf("refreshExternalIdpToken: %v", err)
	}
	if access != "new-access" {
		t.Fatalf("access = %q", access)
	}
	if refresh != "new-refresh" {
		t.Fatalf("refresh = %q", refresh)
	}
	if profileArn != "" {
		t.Fatalf("external IdP refresh should not return a profileArn, got %q", profileArn)
	}
	if expiresAt == 0 {
		t.Fatalf("expected a non-zero absolute expiry")
	}
}

// TestRefreshExternalIdpTokenKeepsRefreshTokenWhenOmitted verifies the existing
// refresh token is retained when the IdP response omits a rotated one.
func TestRefreshExternalIdpTokenKeepsRefreshTokenWhenOmitted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"a2","expires_in":1200}`))
	}))
	defer srv.Close()

	// See TestRefreshExternalIdpToken: relax the allow-list for the httptest endpoint.
	restore := SetExternalIdpValidatorForTest(func(string) error { return nil })
	defer SetExternalIdpValidatorForTest(restore)

	_, refresh, _, _, err := refreshExternalIdpToken("keep-me", "c", srv.URL, "", srv.Client())
	if err != nil {
		t.Fatalf("refreshExternalIdpToken: %v", err)
	}
	if refresh != "keep-me" {
		t.Fatalf("expected refresh token to be retained, got %q", refresh)
	}
}

// TestRefreshExternalIdpTokenRequiresClientAndEndpoint guards the precondition
// that distinguishes the external-IdP branch from the AWS OIDC branch.
func TestRefreshExternalIdpTokenRequiresClientAndEndpoint(t *testing.T) {
	if _, _, _, _, err := refreshExternalIdpToken("r", "", "https://login.microsoftonline.com/t/token", "", http.DefaultClient); err == nil {
		t.Fatalf("expected error when clientID is empty")
	}
	if _, _, _, _, err := refreshExternalIdpToken("r", "c", "", "", http.DefaultClient); err == nil {
		t.Fatalf("expected error when tokenEndpoint is empty")
	}
}

// TestValidateExternalIdpEndpointAcceptsAllowListed verifies the exported validator
// accepts real Azure / Microsoft 365 token endpoints (commercial, us-gov, china).
func TestValidateExternalIdpEndpointAcceptsAllowListed(t *testing.T) {
	for _, raw := range []string{
		"https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
		"https://login.microsoftonline.us/tenant/v2.0",
		"https://login.partner.microsoftonline.cn/tenant/oauth2/v2.0/token",
	} {
		if err := ValidateExternalIdpEndpoint(raw); err != nil {
			t.Errorf("expected %q accepted, got %v", raw, err)
		}
	}
}

// TestValidateExternalIdpEndpointRejectsUnsafe verifies the validator rejects the
// SSRF shapes a pasted credential JSON could carry: cleartext http, IP literals,
// and non-allow-listed hosts.
func TestValidateExternalIdpEndpointRejectsUnsafe(t *testing.T) {
	for _, raw := range []string{
		"http://login.microsoftonline.com/x",  // not https
		"https://127.0.0.1/oauth/token",       // IP literal
		"https://evil.example.com/oauth/token", // not allow-listed
	} {
		if err := ValidateExternalIdpEndpoint(raw); err == nil {
			t.Errorf("expected %q rejected, got nil", raw)
		}
	}
}

// TestSetExternalIdpValidatorForTestSwapsAndRestores verifies the test seam lets a
// test override (and restore) the validator so happy-path import tests can POST
// against an httptest server (http + 127.0.0.1) that the real allow-list rejects.
func TestSetExternalIdpValidatorForTestSwapsAndRestores(t *testing.T) {
	restore := SetExternalIdpValidatorForTest(func(string) error { return nil })
	defer SetExternalIdpValidatorForTest(restore)
	if err := ValidateExternalIdpEndpoint("https://evil.example.com/x"); err != nil {
		t.Fatalf("expected swapped no-op validator to accept, got %v", err)
	}
}

// TestDeriveExternalIdpEndpoints verifies the endpoints+scopes are reconstructed
// from userId (Kiro export) OR the accessToken JWT issuer (bare blobs), plus the
// Kiro client ID. This is what lets the import path accept shapes that omit
// tokenEndpoint/issuerUrl/scopes.
func TestDeriveExternalIdpEndpoints(t *testing.T) {
	const userID = "https://login.microsoftonline.com/5fbc183e-3d09-4043-b36f-0c49d3665977/v2.0.8db0e2eb-d491-4a1a-98f1-cbdc12bb60a0"
	const clientID = "fa6d79bf-cdaa-495e-8359-78aab7c7cd9b"
	const wantTE = "https://login.microsoftonline.com/5fbc183e-3d09-4043-b36f-0c49d3665977/oauth2/v2.0/token"
	const wantIss = "https://login.microsoftonline.com/5fbc183e-3d09-4043-b36f-0c49d3665977/v2.0"

	// From userId (Kiro export carries it at account level).
	te, iss, sc := DeriveExternalIdpEndpoints(userID, clientID, "")
	if te != wantTE || iss != wantIss {
		t.Fatalf("from userId: te=%q iss=%q (want %q / %q)", te, iss, wantTE, wantIss)
	}
	if !strings.Contains(sc, "api://"+clientID+"/codewhisperer:conversations") || !strings.Contains(sc, "offline_access") {
		t.Fatalf("scopes: got %q", sc)
	}

	// From the accessToken JWT issuer (bare blobs carry no userId).
	jwt := "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"`+userID+`"}`)) + "."
	te2, iss2, sc2 := DeriveExternalIdpEndpoints("", clientID, jwt)
	if te2 != wantTE || iss2 != wantIss {
		t.Fatalf("from accessToken JWT: te=%q iss=%q (want %q / %q)", te2, iss2, wantTE, wantIss)
	}
	if sc2 == "" {
		t.Fatalf("scopes from JWT path: got empty")
	}

	// Neither source → all-empty (caller falls back to its 400).
	if te3, iss3, sc3 := DeriveExternalIdpEndpoints("", clientID, ""); te3 != "" || iss3 != "" || sc3 != "" {
		t.Fatalf("empty sources should yield all-empty, got %q %q %q", te3, iss3, sc3)
	}
	// userId takes precedence over accessToken.
	if te4, _, _ := DeriveExternalIdpEndpoints(userID, clientID, jwt); te4 != wantTE {
		t.Fatalf("userId should take precedence over accessToken, got %q", te4)
	}
}

// newTestKiroSsoSession builds a session for driving handleCallback directly,
// without binding the loopback listener.
func newTestKiroSsoSession() *KiroSsoSession {
	return &KiroSsoSession{
		ID:        "test-session",
		Verifier:  generateCodeVerifier(),
		State:     "portal-state",
		Region:    "us-east-1",
		ExpiresAt: time.Now().Add(time.Minute),
		resultCh:  make(chan kiroSsoCapture, 1),
	}
}

// TestEnterpriseLeg1RejectsMissingOrMismatchedState pins the anti-CSRF gate on
// the enterprise descriptor: without it, any caller able to reach the listener
// could inject a forged descriptor and pre-empt the single-shot leg-2.
func TestEnterpriseLeg1RejectsMissingOrMismatchedState(t *testing.T) {
	for _, tc := range []struct {
		name  string
		query string
	}{
		{"missing state", "login_option=external_idp&issuer_url=https://login.microsoftonline.com/t/v2.0&client_id=cid"},
		{"mismatched state", "login_option=external_idp&issuer_url=https://login.microsoftonline.com/t/v2.0&client_id=cid&state=wrong"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestKiroSsoSession()
			rec := httptest.NewRecorder()
			s.handleCallback(rec, httptest.NewRequest(http.MethodGet, "/?"+tc.query, nil))
			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
			}
			s.mu.Lock()
			leg2 := s.leg2
			s.mu.Unlock()
			if leg2 != nil {
				t.Fatalf("forged descriptor must not start leg-2")
			}
			select {
			case c := <-s.resultCh:
				t.Fatalf("forged descriptor must not consume the one-shot capture, got %+v", c)
			default:
			}
		})
	}
}

// TestEnterpriseTwoLegFlow drives the full enterprise state machine through
// handleCallback: portal descriptor (leg-1, state-matched) -> 302 to the IdP
// authorize URL -> IdP code redirect (leg-2, state2-matched) -> capture with the
// discovered token endpoint and the leg-2 PKCE verifier.
func TestEnterpriseTwoLegFlow(t *testing.T) {
	var disc *httptest.Server
	disc = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authorization_endpoint":"` + disc.URL + `/authorize","token_endpoint":"` + disc.URL + `/token"}`))
	}))
	defer disc.Close()

	// The discovery issuer/endpoints are httptest URLs (http + 127.0.0.1) the real
	// allow-list rejects; relax it through the seam like the refresh tests do.
	restore := SetExternalIdpValidatorForTest(func(string) error { return nil })
	defer SetExternalIdpValidatorForTest(restore)

	s := newTestKiroSsoSession()

	// Leg-1: portal descriptor with the matching portal state.
	q := url.Values{}
	q.Set("login_option", "external_idp")
	q.Set("issuer_url", disc.URL)
	q.Set("client_id", "cid-123")
	q.Set("scopes", "api://cid-123/codewhisperer:conversations offline_access")
	q.Set("state", s.State)
	rec := httptest.NewRecorder()
	s.handleCallback(rec, httptest.NewRequest(http.MethodGet, "/?"+q.Encode(), nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("leg-1 status = %d, want 302 (body: %s)", rec.Code, rec.Body.String())
	}
	authURL, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse authorize redirect: %v", err)
	}
	state2 := authURL.Query().Get("state")
	if state2 == "" || state2 == s.State {
		t.Fatalf("leg-2 must use a fresh state, got %q", state2)
	}
	if got := authURL.Query().Get("client_id"); got != "cid-123" {
		t.Fatalf("authorize client_id = %q", got)
	}

	// A second descriptor must not reset the in-flight leg-2 (single-shot).
	rec2 := httptest.NewRecorder()
	s.handleCallback(rec2, httptest.NewRequest(http.MethodGet, "/?"+q.Encode(), nil))
	if rec2.Code != http.StatusNoContent {
		t.Fatalf("second descriptor status = %d, want 204", rec2.Code)
	}

	// Leg-2: a code with the wrong state is ignored...
	rec3 := httptest.NewRecorder()
	s.handleCallback(rec3, httptest.NewRequest(http.MethodGet, kiroOAuthCallbackPath+"?code=abc&state=wrong", nil))
	if rec3.Code != http.StatusNoContent {
		t.Fatalf("wrong-state leg-2 status = %d, want 204", rec3.Code)
	}

	// ...and the matching state delivers the capture.
	rec4 := httptest.NewRecorder()
	s.handleCallback(rec4, httptest.NewRequest(http.MethodGet, kiroOAuthCallbackPath+"?code=auth-code&state="+state2, nil))
	if rec4.Code != http.StatusOK {
		t.Fatalf("leg-2 status = %d, want 200", rec4.Code)
	}
	select {
	case capture := <-s.resultCh:
		if capture.err != nil {
			t.Fatalf("capture error: %v", capture.err)
		}
		if capture.kind != "external_idp" || capture.code != "auth-code" {
			t.Fatalf("capture = %+v", capture)
		}
		if capture.tokenEndpoint != disc.URL+"/token" {
			t.Fatalf("capture tokenEndpoint = %q, want %q", capture.tokenEndpoint, disc.URL+"/token")
		}
		if capture.clientID != "cid-123" || capture.codeVerifier == "" {
			t.Fatalf("capture missing leg-2 context: %+v", capture)
		}
	default:
		t.Fatalf("expected a delivered capture after leg-2")
	}
}

// TestRelayKiroSsoCallback drives the remote-browser path: the operator pastes
// the failed localhost redirect URLs into the admin panel and they are fed
// through the same state machine — leg-1 returns the IdP authorize URL, leg-2
// completes the capture, and a wrong-state URL is rejected.
func TestRelayKiroSsoCallback(t *testing.T) {
	var disc *httptest.Server
	disc = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"authorization_endpoint":"` + disc.URL + `/authorize","token_endpoint":"` + disc.URL + `/token"}`))
	}))
	defer disc.Close()
	restore := SetExternalIdpValidatorForTest(func(string) error { return nil })
	defer SetExternalIdpValidatorForTest(restore)

	s := newTestKiroSsoSession()
	kiroSsoSessionsMu.Lock()
	kiroSsoSessions[s.ID] = s
	kiroSsoSessionsMu.Unlock()
	defer removeKiroSsoSession(s.ID)

	if _, _, err := RelayKiroSsoCallback("no-such-session", "http://localhost:3128/?code=x"); err == nil {
		t.Fatalf("unknown session must be rejected")
	}
	if _, _, err := RelayKiroSsoCallback(s.ID, "http://localhost:3128/"); err == nil {
		t.Fatalf("URL without query parameters must be rejected")
	}

	// Leg-1 descriptor with a mismatched state must not start leg-2.
	if _, _, err := RelayKiroSsoCallback(s.ID,
		"http://localhost:3128/?login_option=external_idp&issuer_url="+url.QueryEscape(disc.URL)+"&client_id=cid&state=wrong"); err == nil {
		t.Fatalf("mismatched-state descriptor must be rejected")
	}

	// Leg-1 descriptor with the portal state returns the IdP authorize URL.
	authorizeURL, done, err := RelayKiroSsoCallback(s.ID,
		"http://localhost:3128/?login_option=external_idp&issuer_url="+url.QueryEscape(disc.URL)+"&client_id=cid&state="+s.State)
	if err != nil || done || authorizeURL == "" {
		t.Fatalf("leg-1 relay: url=%q done=%v err=%v", authorizeURL, done, err)
	}
	parsed, err := url.Parse(authorizeURL)
	if err != nil {
		t.Fatalf("parse authorize URL: %v", err)
	}
	state2 := parsed.Query().Get("state")

	// Leg-2 code redirect completes the capture (poll picks the outcome up).
	_, done, err = RelayKiroSsoCallback(s.ID, "http://localhost:3128"+kiroOAuthCallbackPath+"?code=auth-code&state="+state2)
	if err != nil || !done {
		t.Fatalf("leg-2 relay: done=%v err=%v", done, err)
	}
	select {
	case capture := <-s.resultCh:
		if capture.err != nil || capture.kind != "external_idp" || capture.code != "auth-code" {
			t.Fatalf("capture = %+v", capture)
		}
	default:
		t.Fatalf("expected a delivered capture after leg-2 relay")
	}
}

// TestExpFromAccessTokenJWT pins the exp extraction used for trust-on-import.
func TestExpFromAccessTokenJWT(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"x","exp":2000000000}`))
	jwt := "eyJhbGciOiJub25lIn0." + payload + "."
	if got := ExpFromAccessTokenJWT(jwt); got != 2000000000 {
		t.Fatalf("ExpFromAccessTokenJWT: got %d, want 2000000000", got)
	}
	if got := ExpFromAccessTokenJWT(""); got != 0 {
		t.Fatalf("empty → 0, got %d", got)
	}
	if got := ExpFromAccessTokenJWT("not-a-jwt"); got != 0 {
		t.Fatalf("non-JWT → 0, got %d", got)
	}
}
