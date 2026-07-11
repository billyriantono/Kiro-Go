package egress

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// stubRT records the request it received and returns a canned response.
type stubRT struct {
	got *http.Request
}

func (s *stubRT) RoundTrip(req *http.Request) (*http.Response, error) {
	s.got = req
	return &http.Response{StatusCode: 299, Body: http.NoBody, Header: make(http.Header)}, nil
}

// TestRelayRewrite verifies the transport rewrites an upstream request to the
// relay, carrying the real target and secret in headers, and streams the relay
// response back.
func TestRelayRewrite(t *testing.T) {
	var gotTarget, gotKey, gotMethod string
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTarget = r.Header.Get(HeaderTarget)
		gotKey = r.Header.Get(HeaderKey)
		gotMethod = r.Method
		w.WriteHeader(200)
		_, _ = io.WriteString(w, "relayed-ok")
	}))
	defer relay.Close()

	client := &http.Client{Transport: NewRelayTransportWith(http.DefaultTransport, relay.URL, "sekret")}
	resp, err := client.Get("https://codewhisperer.us-east-1.amazonaws.com/foo?x=1")
	if err != nil {
		t.Fatalf("relayed request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if gotTarget != "https://codewhisperer.us-east-1.amazonaws.com/foo?x=1" {
		t.Fatalf("relay target header = %q", gotTarget)
	}
	if gotKey != "sekret" {
		t.Fatalf("relay key header = %q", gotKey)
	}
	if gotMethod != http.MethodGet {
		t.Fatalf("method not preserved: %q", gotMethod)
	}
	if string(body) != "relayed-ok" {
		t.Fatalf("relay response not streamed back: %q", body)
	}
}

// TestRelayPassthroughWhenUnset verifies that with no relay URL the request is
// delegated to the inner transport UNCHANGED (no rewrite, no relay headers).
func TestRelayPassthroughWhenUnset(t *testing.T) {
	stub := &stubRT{}
	rt := NewRelayTransportWith(stub, "", "")
	req, _ := http.NewRequest("POST", "https://q.us-east-1.amazonaws.com/generateAssistantResponse", nil)
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if stub.got == nil {
		t.Fatal("inner transport was not called")
	}
	if stub.got.URL.Host != "q.us-east-1.amazonaws.com" {
		t.Fatalf("request was rewritten despite no relay: host=%s", stub.got.URL.Host)
	}
	if stub.got.Header.Get(HeaderTarget) != "" {
		t.Fatalf("relay header leaked on passthrough")
	}
}

// TestRelayInvalidURLFailsClosed verifies a misconfigured relay fails closed so
// traffic never silently leaks from the real IP.
func TestRelayInvalidURLFailsClosed(t *testing.T) {
	stub := &stubRT{}
	rt := NewRelayTransportWith(stub, "not a url", "")
	req, _ := http.NewRequest("GET", "https://codewhisperer.us-east-1.amazonaws.com/", nil)
	if _, err := rt.RoundTrip(req); err == nil {
		t.Fatal("expected error for invalid relay URL (fail closed)")
	}
	if stub.got != nil {
		t.Fatal("inner transport must not be called when relay URL is invalid")
	}
}
