package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeRelay emulates a deployed relay: it checks the secret, answers the ping,
// and otherwise "forwards" by returning the status configured in forwardStatus
// (simulating what an upstream like AWS would return).
func fakeRelay(secret string, forwardStatus int, forwardBody string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if secret != "" && r.Header.Get("X-Relay-Key") != secret {
			w.WriteHeader(401)
			_, _ = w.Write([]byte("unauthorized"))
			return
		}
		if r.Header.Get("X-Relay-Ping") != "" {
			w.WriteHeader(200)
			_, _ = w.Write([]byte("relay-ok"))
			return
		}
		w.WriteHeader(forwardStatus)
		_, _ = w.Write([]byte(forwardBody))
	}))
}

func callTestRelay(t *testing.T, relayURL, secret string) map[string]interface{} {
	t.Helper()
	h := &Handler{}
	body, _ := json.Marshal(map[string]string{"relayUrl": relayURL, "relaySecret": secret})
	req := httptest.NewRequest("POST", "/admin/api/relay/test", strings.NewReader(string(body)))
	rec := httptest.NewRecorder()
	h.apiTestRelay(rec, req)
	var out map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, rec.Body.String())
	}
	return out
}

// TestApiTestRelayPingAware verifies a ping-aware relay with the right secret
// reports success.
func TestApiTestRelayPingAware(t *testing.T) {
	srv := fakeRelay("s3cret", 200, "")
	defer srv.Close()
	out := callTestRelay(t, srv.URL, "s3cret")
	if out["ok"] != true {
		t.Fatalf("ping-aware relay should be ok, got %+v", out)
	}
}

// TestApiTestRelayForwardingUpstream403 verifies that an upstream 403 forwarded
// through the relay is NOT mistaken for a relay rejection (the original bug).
func TestApiTestRelayForwardingUpstream403(t *testing.T) {
	// A relay that ignores ping and forwards, upstream answering 403 (like AWS
	// OIDC to a bare GET). Simulate a non-ping relay by using a server that
	// always forwards regardless of the ping header.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Relay-Key") != "s3cret" {
			w.WriteHeader(401)
			_, _ = w.Write([]byte("unauthorized"))
			return
		}
		w.WriteHeader(403)
		_, _ = w.Write([]byte(`{"__type":"AccessDeniedException"}`))
	}))
	defer srv.Close()
	out := callTestRelay(t, srv.URL, "s3cret")
	if out["ok"] != true {
		t.Fatalf("upstream 403 through relay must report ok=true, got %+v", out)
	}
}

// TestApiTestRelayWrongSecret verifies a relay-level 401 is reported as failure.
func TestApiTestRelayWrongSecret(t *testing.T) {
	srv := fakeRelay("correct", 200, "")
	defer srv.Close()
	out := callTestRelay(t, srv.URL, "wrong")
	if out["ok"] != false {
		t.Fatalf("wrong secret must report ok=false, got %+v", out)
	}
}

// TestApiTestRelayUnreachable verifies a dead relay URL is reported as unreachable.
func TestApiTestRelayUnreachable(t *testing.T) {
	out := callTestRelay(t, "http://127.0.0.1:1/", "x")
	if out["ok"] != false {
		t.Fatalf("unreachable relay must report ok=false, got %+v", out)
	}
}
