// Package egress provides an outbound "relay" transport: when a relay is
// configured, every upstream request (AWS Kiro/CodeWhisperer, OIDC, IdP token
// endpoints) is rewritten to go through a small serverless forwarder deployed on
// Cloudflare Workers / Vercel / Deno. Upstream then sees the relay's IP instead
// of the server's — useful when the server's IP is rate-limited or geo-blocked.
//
// The relay is an alternative to the socks5/http ProxyURL: the real target is
// carried in the X-Relay-Target header and a shared secret in X-Relay-Key; the
// forwarder validates the secret, checks the target host against its allow-list,
// forwards the request, and streams the response straight back (so SSE keeps
// working). See the relay source under relay/ for the server side.
package egress

import (
	"net/http"
	"net/url"

	"kiro-go/config"
)

// Header names the relay forwarder reads. Kept in one place so the Go client and
// the JS/TS relay sources agree.
const (
	HeaderTarget = "X-Relay-Target" // full upstream URL the relay must forward to
	HeaderKey    = "X-Relay-Key"    // shared secret authenticating the caller
)

// relayTransport wraps an inner RoundTripper. On each request it reads the live
// relay config; when a relay URL is set it rewrites the request to the relay,
// otherwise it delegates unchanged (so toggling the relay needs no client
// rebuild).
type relayTransport struct {
	inner http.RoundTripper

	// fixed pins the relay to explicit values (test flow) instead of live config.
	fixed       bool
	fixedURL    string
	fixedSecret string
}

// NewRelayTransport wraps inner so outbound requests are routed through the
// configured relay when one is set. inner must not be nil.
func NewRelayTransport(inner http.RoundTripper) http.RoundTripper {
	return &relayTransport{inner: inner}
}

// NewRelayTransportWith wraps inner with a FIXED relay URL/secret rather than the
// live config. Used by the admin "test relay" flow to verify unsaved settings.
func NewRelayTransportWith(inner http.RoundTripper, relayURL, secret string) http.RoundTripper {
	return &relayTransport{inner: inner, fixedURL: relayURL, fixedSecret: secret, fixed: true}
}

func (rt *relayTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// ActiveRelay returns a URL only when the relay is the SELECTED outbound mode;
	// a stored-but-unselected relay stays dormant (passthrough below).
	relayURL, secret := config.ActiveRelay()
	if rt.fixed {
		relayURL, secret = rt.fixedURL, rt.fixedSecret
	}
	if relayURL == "" {
		return rt.inner.RoundTrip(req)
	}
	ru, err := url.Parse(relayURL)
	if err != nil || (ru.Scheme != "http" && ru.Scheme != "https") {
		// Misconfigured relay: fail closed so requests don't silently leak from the
		// real IP the operator intended to hide.
		return nil, &url.Error{Op: "relay", URL: relayURL, Err: errInvalidRelay}
	}
	// Never relay a request already aimed at the relay host (avoids an infinite
	// loop if some caller targets the relay directly).
	if req.URL.Host == ru.Host {
		return rt.inner.RoundTrip(req)
	}

	target := req.URL.String()
	out := req.Clone(req.Context())
	out.URL = ru
	out.Host = ru.Host
	// req.Clone already deep-copied Header; set the routing headers on the copy.
	out.Header.Set(HeaderTarget, target)
	if secret != "" {
		out.Header.Set(HeaderKey, secret)
	}
	// The relay terminates TLS to the target itself; we speak plain HTTP semantics
	// to the relay endpoint (which is itself https). Strip hop-by-hop headers that
	// would confuse the forwarder.
	out.Header.Del("Connection")
	return rt.inner.RoundTrip(out)
}

type relayError string

func (e relayError) Error() string { return string(e) }

const errInvalidRelay relayError = "relay URL is not a valid http(s) URL"
