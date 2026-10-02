//go:build tui || all

package components

import (
	"strconv"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/tui/components/nodesview"
	"github.com/spf13/viper"
)

func nodeResourceThresholds(config *viper.Viper) nodesview.ResourceThresholds {
	thresholds := nodesview.DefaultResourceThresholds()
	if config.IsSet("watch.nodes_resources.elevated") {
		thresholds.Elevated = config.GetFloat64("watch.nodes_resources.elevated")
	}
	if config.IsSet("watch.nodes_resources.high") {
		thresholds.High = config.GetFloat64("watch.nodes_resources.high")
	}
	if err := thresholds.Validate(); err != nil {
		logger.Warn("Invalid node resource thresholds; using defaults", "error", err,
			"elevated", strconv.FormatFloat(thresholds.Elevated, 'g', -1, 64),
			"high", strconv.FormatFloat(thresholds.High, 'g', -1, 64))
		return nodesview.DefaultResourceThresholds()
	}
	return thresholds
}

func newNodeChangeTracker() *nodesview.ChangeTracker {
	return &nodesview.ChangeTracker{Thresholds: nodeResourceThresholds(viper.GetViper())}
}
