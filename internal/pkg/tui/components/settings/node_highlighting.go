//go:build tui || all

package settings

import (
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/spf13/viper"
)

// UpdateNodesHighlightingMsg changes remote Nodes presentation without restarting capture.
type UpdateNodesHighlightingMsg struct{ Mode string }

// LoadNodesHighlightingPreference returns a validated presentation preference.
// Configuration parsing errors are handled by the command's configuration loader.
func LoadNodesHighlightingPreference() string {
	mode := viper.GetString("watch.nodes_highlighting")
	switch mode {
	case "quiet", "normal":
		return mode
	case "":
		return "normal"
	default:
		logger.Warn("Invalid Nodes highlighting preference; using normal", "key", "watch.nodes_highlighting", "value", mode)
		return "normal"
	}
}
