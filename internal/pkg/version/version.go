package version

import (
	"fmt"
	"runtime"
)

var (
	// Version is the semantic version (injected at build time via ldflags)
	Version = "dev"

	// GitCommit is the git commit hash (injected at build time via ldflags)
	GitCommit = "unknown"

	// BuildDate is the build date (injected at build time via ldflags)
	BuildDate = "unknown"

	// GoVersion is the Go compiler version
	GoVersion = runtime.Version()
)

// GetVersion returns the full version string
func GetVersion() string {
	return Version
}

// GetFullVersion returns a detailed version string with build info
func GetFullVersion() string {
	return fmt.Sprintf("%s (commit: %s, built: %s, %s %s/%s)",
		Version, GitCommit, BuildDate, GoVersion, runtime.GOOS, runtime.GOARCH)
}

// GetShortVersion returns a short version string
func GetShortVersion() string {
	if GitCommit != "unknown" && len(GitCommit) > 7 {
		return fmt.Sprintf("%s-%s", Version, GitCommit[:7])
	}
	return Version
}
