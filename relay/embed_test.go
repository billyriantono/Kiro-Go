package relay

import (
	"strings"
	"testing"
)

// TestSourcesCarryPlaceholder ensures every embedded relay source contains the
// __RELAY_KEY__ placeholder the admin handler replaces with the baked-in secret.
// A missing placeholder would silently ship a relay that rejects every request.
func TestSourcesCarryPlaceholder(t *testing.T) {
	for _, platform := range []string{"cloudflare", "vercel", "deno"} {
		src, ok := SourceFor(platform)
		if !ok {
			t.Fatalf("SourceFor(%q) not found", platform)
		}
		if !strings.Contains(src.Code, "__RELAY_KEY__") {
			t.Fatalf("%s source missing __RELAY_KEY__ placeholder", platform)
		}
		if src.Filename == "" || src.Language == "" {
			t.Fatalf("%s source metadata incomplete: %+v", platform, src)
		}
	}
	if _, ok := SourceFor("unknown"); ok {
		t.Fatal("SourceFor(unknown) should return ok=false")
	}
}
