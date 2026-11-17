// Package version holds the build version, set at link time:
//
//	go build -ldflags "-X github.com/FusionProxies/proxy-health-monitor/internal/version.Version=v0.1.0"
package version

// Version is the release tag, or "dev" for local builds.
var Version = "dev"

// UserAgent identifies the monitor in requests to targets and webhooks.
func UserAgent() string {
	return "proxy-health-monitor/" + Version + " (+https://github.com/FusionProxies/proxy-health-monitor)"
}
