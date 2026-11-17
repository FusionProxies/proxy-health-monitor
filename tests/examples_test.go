package tests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/FusionProxies/proxy-health-monitor/internal/config"
	"github.com/FusionProxies/proxy-health-monitor/internal/redact"
)

// Every example configuration in the repository must load and validate.
func TestExampleConfigsAreValid(t *testing.T) {
	defer redact.Reset()
	env := map[string]string{
		"FUSION_USER": "example-user", "FUSION_PASS": "example-pass",
		"PROXY_MONITOR_TOKEN": "0123456789abcdef0123", "PROXY_USER": "u", "PROXY_PASS": "p",
	}
	lookup := func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	var n int
	err := filepath.WalkDir("../examples", func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".yaml") {
			return err
		}
		n++
		if _, err := config.LoadWithEnv(p, lookup); err != nil {
			t.Errorf("%s: %v", p, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n < 3 {
		t.Fatalf("expected the example configurations, found %d", n)
	}
}
