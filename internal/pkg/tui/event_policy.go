//go:build tui || all

package tui

import (
	"strings"

	"github.com/endorses/lippycat/internal/pkg/eventconfig"
	"github.com/endorses/lippycat/internal/pkg/events"
)

// selectLocalEventOptions is safe in workers: missing explicit options use
// defaults, never mutable global configuration. Owners freeze Viper beforehand.
func selectLocalEventOptions(filter string, supplied []LocalEventAnalysisOptions) LocalEventAnalysisOptions {
	options := LocalEventAnalysisOptions{NodeID: "watch-local"}
	if len(supplied) > 0 {
		options = supplied[0]
	}
	if strings.TrimSpace(filter) != "" {
		options.CaptureScope, options.Partial = events.CaptureScopeFiltered, true
	}
	return options
}

func resolveLocalEventOptions(options LocalEventAnalysisOptions) (LocalEventAnalysisOptions, error) {
	policy, err := eventconfig.Resolve(options.Policy)
	if err != nil {
		return LocalEventAnalysisOptions{}, err
	}
	options.Policy = policy
	options.SourceOrdering = append([]string(nil), options.SourceOrdering...)
	if options.AnalysisProfile == "" {
		options.AnalysisProfile = "watch-eventanalysis-v1"
	}
	suffix := "|policy=" + policy.Fingerprint()
	if !strings.HasSuffix(options.AnalysisProfile, suffix) {
		options.AnalysisProfile += suffix
	}
	return options, nil
}
