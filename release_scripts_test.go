package bbox

import (
	"os"
	"strings"
	"testing"
)

func TestReleaseScriptsPinGoReleaserVersion(t *testing.T) {
	t.Parallel()

	scripts := []string{
		"scripts/release-snapshot.sh",
		"scripts/release-multiarch-snapshot.sh",
	}

	for _, path := range scripts {
		path := path
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			content, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}

			text := string(content)
			if strings.Contains(text, "github.com/goreleaser/goreleaser/v2@latest") {
				t.Fatalf("%s must pin a goreleaser version instead of using @latest", path)
			}
			if !strings.Contains(text, `GORELEASER_VERSION:-v`) {
				t.Fatalf("%s must define a pinned default GORELEASER_VERSION", path)
			}
			if !strings.Contains(text, `github.com/goreleaser/goreleaser/v2@"$goreleaser_version"`) {
				t.Fatalf("%s must invoke the pinned goreleaser module version", path)
			}
		})
	}
}
