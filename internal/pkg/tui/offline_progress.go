//go:build tui || all

package tui

import (
	"fmt"
	"strings"
	"time"
)

const offlineProgressModalWidth = 48

// offlineProgressBar is pure rendering. Unknown totals show activity rather
// than a percentage; known totals describe this phase, not the whole open.
func offlineProgressBar(done, total uint64, known bool, elapsed time.Duration) string {
	const width = 26
	if !known {
		position := int(max(elapsed, 0)/(200*time.Millisecond)) % (width - 2)
		return "[" + strings.Repeat(" ", position) + "..." + strings.Repeat(" ", width-position-3) + "]"
	}
	fraction := 1.0
	if total != 0 {
		fraction = float64(min(done, total)) / float64(total)
	}
	filled := int(fraction * width)
	percent := int(fraction * 100)
	if done < total {
		percent = min(percent, 99)
	}
	return fmt.Sprintf("[%s%s] %3d%%", strings.Repeat("=", filled), strings.Repeat(" ", width-filled), percent)
}
