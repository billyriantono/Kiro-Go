// Package relay embeds the egress-relay source for each supported platform so
// the admin panel can display / offer it for download. The Go proxy itself does
// not run these; they are deployed by the operator to Cloudflare Workers, Vercel,
// or Deno Deploy and referenced back via the Egress Relay settings.
package relay

import _ "embed"

//go:embed cloudflare-worker.js
var cloudflareWorker string

//go:embed vercel-edge.js
var vercelEdge string

//go:embed deno-deploy.ts
var denoDeploy string

// Source describes one deployable relay variant.
type Source struct {
	Platform string `json:"platform"` // "cloudflare" | "vercel" | "deno"
	Filename string `json:"filename"` // suggested file name at the destination
	Language string `json:"language"` // for syntax highlighting in the UI
	Code     string `json:"code"`     // the full source
}

// SourceFor returns the embedded relay source for a platform, or ok=false when
// the platform is unknown.
func SourceFor(platform string) (Source, bool) {
	switch platform {
	case "cloudflare":
		return Source{Platform: "cloudflare", Filename: "worker.js", Language: "javascript", Code: cloudflareWorker}, true
	case "vercel":
		return Source{Platform: "vercel", Filename: "api/relay.js", Language: "javascript", Code: vercelEdge}, true
	case "deno":
		return Source{Platform: "deno", Filename: "main.ts", Language: "typescript", Code: denoDeploy}, true
	default:
		return Source{}, false
	}
}
