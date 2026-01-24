//go:build tui || all

package components

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
)

// VoIPStatsProvider implements ProtocolStatsProvider for VoIP (SIP/RTP) traffic.
type VoIPStatsProvider struct {
	mu    sync.RWMutex
	theme themes.Theme

	// Call statistics
	calls []Call // Reference to current calls

	// Cached metrics (updated when calls change)
	totalCalls     int
	activeCalls    int
	completedCalls int
	failedCalls    int
	ringingCalls   int
	rtpOnlyCalls   int

	// Quality metrics (aggregated from completed calls)
	avgMOS        float64
	avgJitter     float64
	avgPacketLoss float64
	avgDuration   float64 // in seconds

	// Codec distribution
	codecCounts map[string]int64

	// Quality distribution
	excellentCalls int // MOS >= 4.0
	goodCalls      int // MOS >= 3.5
	fairCalls      int // MOS >= 3.0
	poorCalls      int // MOS < 3.0
}

// NewVoIPStatsProvider creates a new VoIP stats provider.
func NewVoIPStatsProvider() *VoIPStatsProvider {
	return &VoIPStatsProvider{
		theme:       themes.Solarized(),
		codecCounts: make(map[string]int64),
	}
}

// ProtocolName returns the protocol name.
func (v *VoIPStatsProvider) ProtocolName() string {
	return "VoIP (SIP/RTP)"
}

// IsActive returns true if there are any VoIP calls tracked.
func (v *VoIPStatsProvider) IsActive() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.totalCalls > 0
}

// SetTheme updates the theme.
func (v *VoIPStatsProvider) SetTheme(theme themes.Theme) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.theme = theme
}

// UpdateCalls updates the provider with the current list of calls.
// This should be called whenever the call list changes.
func (v *VoIPStatsProvider) UpdateCalls(calls []Call) {
	v.mu.Lock()
	defer v.mu.Unlock()

	v.calls = calls
	v.recalculateMetrics()
}

// recalculateMetrics recalculates all metrics from the current call list.
// Must be called with lock held.
func (v *VoIPStatsProvider) recalculateMetrics() {
	// Reset counters
	v.totalCalls = len(v.calls)
	v.activeCalls = 0
	v.completedCalls = 0
	v.failedCalls = 0
	v.ringingCalls = 0
	v.rtpOnlyCalls = 0
	v.excellentCalls = 0
	v.goodCalls = 0
	v.fairCalls = 0
	v.poorCalls = 0

	v.codecCounts = make(map[string]int64)

	var totalMOS, totalJitter, totalPacketLoss, totalDuration float64
	var mosCount, jitterCount, lossCount, durationCount int

	for _, call := range v.calls {
		// Count by state
		switch call.State {
		case CallStateRinging:
			v.ringingCalls++
		case CallStateActive:
			v.activeCalls++
		case CallStateEnded:
			v.completedCalls++
		case CallStateFailed:
			v.failedCalls++
		case CallStateRTPOnly:
			v.rtpOnlyCalls++
		}

		// Track codec distribution
		if call.Codec != "" {
			codec := normalizeCodecName(call.Codec)
			v.codecCounts[codec]++
		}

		// Aggregate quality metrics from completed/active calls with valid data
		if call.MOS > 0 {
			totalMOS += call.MOS
			mosCount++

			// Categorize by MOS quality
			if call.MOS >= 4.0 {
				v.excellentCalls++
			} else if call.MOS >= 3.5 {
				v.goodCalls++
			} else if call.MOS >= 3.0 {
				v.fairCalls++
			} else {
				v.poorCalls++
			}
		}

		if call.Jitter > 0 {
			totalJitter += call.Jitter
			jitterCount++
		}

		if call.PacketLoss > 0 {
			totalPacketLoss += call.PacketLoss
			lossCount++
		}

		if call.Duration.Seconds() > 0 {
			totalDuration += call.Duration.Seconds()
			durationCount++
		}
	}

	// Calculate averages
	if mosCount > 0 {
		v.avgMOS = totalMOS / float64(mosCount)
	} else {
		v.avgMOS = 0
	}

	if jitterCount > 0 {
		v.avgJitter = totalJitter / float64(jitterCount)
	} else {
		v.avgJitter = 0
	}

	if lossCount > 0 {
		v.avgPacketLoss = totalPacketLoss / float64(lossCount)
	} else {
		v.avgPacketLoss = 0
	}

	if durationCount > 0 {
		v.avgDuration = totalDuration / float64(durationCount)
	} else {
		v.avgDuration = 0
	}
}

// normalizeCodecName normalizes codec names for consistent display.
func normalizeCodecName(codec string) string {
	// Normalize common codec names
	normalized := strings.ToUpper(codec)
	switch {
	case strings.Contains(normalized, "PCMU") || strings.Contains(normalized, "G711U"):
		return "G.711u"
	case strings.Contains(normalized, "PCMA") || strings.Contains(normalized, "G711A"):
		return "G.711a"
	case strings.Contains(normalized, "G729"):
		return "G.729"
	case strings.Contains(normalized, "G722"):
		return "G.722"
	case strings.Contains(normalized, "OPUS"):
		return "Opus"
	case strings.Contains(normalized, "AMR-WB"):
		return "AMR-WB"
	case strings.Contains(normalized, "AMR"):
		return "AMR"
	case strings.Contains(normalized, "SILK"):
		return "SILK"
	case strings.Contains(normalized, "SPEEX"):
		return "Speex"
	case strings.Contains(normalized, "ILBC"):
		return "iLBC"
	default:
		return codec
	}
}

// GetMetrics returns the current metrics.
func (v *VoIPStatsProvider) GetMetrics() ProtocolMetrics {
	v.mu.RLock()
	defer v.mu.RUnlock()

	// Calculate success rate
	var successRate float64
	totalCompleted := v.completedCalls + v.failedCalls
	if totalCompleted > 0 {
		successRate = float64(v.completedCalls) / float64(totalCompleted) * 100
	}

	return ProtocolMetrics{
		TotalItems:     int64(v.totalCalls),
		ActiveItems:    int64(v.activeCalls),
		CompletedItems: int64(v.completedCalls),
		FailedItems:    int64(v.failedCalls),
		SuccessRate:    successRate,
		AvgLatency:     v.avgDuration,
		AvgQuality:     v.avgMOS,
		QualityMetric:  "MOS",
		Distribution:   v.codecCounts,
	}
}

// Render renders the VoIP statistics section.
func (v *VoIPStatsProvider) Render(width int, theme themes.Theme) string {
	v.mu.RLock()
	defer v.mu.RUnlock()

	var result strings.Builder

	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(theme.InfoColor).
		MarginBottom(1)

	labelStyle := lipgloss.NewStyle().
		Foreground(theme.StatusBarFg).
		Bold(true)

	valueStyle := lipgloss.NewStyle().
		Foreground(theme.StatusBarFg)

	dimStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("240"))

	if v.totalCalls == 0 {
		result.WriteString(valueStyle.Render("  No VoIP calls detected.\n"))
		return result.String()
	}

	// Call Overview Section
	result.WriteString(titleStyle.Render("📞 Call Overview"))
	result.WriteString("\n\n")

	// Total and status breakdown
	result.WriteString(labelStyle.Render("Total Calls:    "))
	result.WriteString(valueStyle.Render(fmt.Sprintf("%d", v.totalCalls)))
	result.WriteString("\n")

	// Active calls with status breakdown
	result.WriteString(labelStyle.Render("Active:         "))
	activeStyle := lipgloss.NewStyle().Foreground(theme.SuccessColor).Bold(true)
	result.WriteString(activeStyle.Render(fmt.Sprintf("%d", v.activeCalls)))
	if v.ringingCalls > 0 {
		result.WriteString(dimStyle.Render(fmt.Sprintf(" (+ %d ringing)", v.ringingCalls)))
	}
	result.WriteString("\n")

	// Completed calls
	result.WriteString(labelStyle.Render("Completed:      "))
	result.WriteString(valueStyle.Render(fmt.Sprintf("%d", v.completedCalls)))
	result.WriteString("\n")

	// Failed calls
	result.WriteString(labelStyle.Render("Failed:         "))
	if v.failedCalls > 0 {
		failStyle := lipgloss.NewStyle().Foreground(theme.ErrorColor).Bold(true)
		result.WriteString(failStyle.Render(fmt.Sprintf("%d", v.failedCalls)))
	} else {
		result.WriteString(valueStyle.Render("0"))
	}
	result.WriteString("\n")

	// RTP-only calls (if any)
	if v.rtpOnlyCalls > 0 {
		result.WriteString(labelStyle.Render("RTP Only:       "))
		result.WriteString(dimStyle.Render(fmt.Sprintf("%d", v.rtpOnlyCalls)))
		result.WriteString("\n")
	}

	// Success rate
	totalCompleted := v.completedCalls + v.failedCalls
	if totalCompleted > 0 {
		successRate := float64(v.completedCalls) / float64(totalCompleted) * 100
		result.WriteString(labelStyle.Render("Success Rate:   "))
		result.WriteString(RenderSuccessRate(successRate, theme))
		result.WriteString("\n")
	}

	result.WriteString("\n")

	// Quality Metrics Section (only if we have data)
	if v.avgMOS > 0 || v.avgJitter > 0 || v.avgPacketLoss > 0 {
		result.WriteString(titleStyle.Render("📊 Quality Metrics"))
		result.WriteString("\n\n")

		// MOS (Mean Opinion Score)
		if v.avgMOS > 0 {
			result.WriteString(labelStyle.Render("Avg MOS:        "))
			// MOS scale: 4.0+ excellent, 3.5+ good, 3.0+ fair, <3.0 poor
			result.WriteString(RenderQualityMetric(v.avgMOS, 4.0, 3.0, true, theme))
			result.WriteString(dimStyle.Render(" / 5.0"))
			result.WriteString("\n")

			// Quality distribution
			result.WriteString(labelStyle.Render("Quality Dist:   "))
			if v.excellentCalls > 0 {
				result.WriteString(lipgloss.NewStyle().Foreground(theme.SuccessColor).Render(fmt.Sprintf("★%d ", v.excellentCalls)))
			}
			if v.goodCalls > 0 {
				result.WriteString(lipgloss.NewStyle().Foreground(theme.InfoColor).Render(fmt.Sprintf("●%d ", v.goodCalls)))
			}
			if v.fairCalls > 0 {
				result.WriteString(lipgloss.NewStyle().Foreground(theme.WarningColor).Render(fmt.Sprintf("◐%d ", v.fairCalls)))
			}
			if v.poorCalls > 0 {
				result.WriteString(lipgloss.NewStyle().Foreground(theme.ErrorColor).Render(fmt.Sprintf("○%d", v.poorCalls)))
			}
			result.WriteString("\n")
		}

		// Jitter
		if v.avgJitter > 0 {
			result.WriteString(labelStyle.Render("Avg Jitter:     "))
			// Jitter: <20ms good, <50ms acceptable, >50ms poor
			result.WriteString(RenderQualityMetric(v.avgJitter, 20, 50, false, theme))
			result.WriteString(dimStyle.Render(" ms"))
			result.WriteString("\n")
		}

		// Packet Loss
		if v.avgPacketLoss > 0 {
			result.WriteString(labelStyle.Render("Avg Packet Loss:"))
			// Packet loss: <1% good, <3% acceptable, >3% poor
			result.WriteString(RenderQualityMetric(v.avgPacketLoss, 1.0, 3.0, false, theme))
			result.WriteString(dimStyle.Render("%"))
			result.WriteString("\n")
		}

		// Average duration
		if v.avgDuration > 0 {
			result.WriteString(labelStyle.Render("Avg Duration:   "))
			result.WriteString(valueStyle.Render(formatCallDuration(v.avgDuration)))
			result.WriteString("\n")
		}

		result.WriteString("\n")
	}

	// Codec Distribution Section (only if we have data)
	if len(v.codecCounts) > 0 {
		result.WriteString(titleStyle.Render("🎵 Codec Distribution"))
		result.WriteString("\n\n")

		// Sort codecs by count for display
		type codecCount struct {
			name  string
			count int64
		}
		codecs := make([]codecCount, 0, len(v.codecCounts))
		var maxCount int64
		for name, count := range v.codecCounts {
			codecs = append(codecs, codecCount{name, count})
			if count > maxCount {
				maxCount = count
			}
		}
		sort.Slice(codecs, func(i, j int) bool {
			return codecs[i].count > codecs[j].count
		})

		// Render bar chart (top 5 codecs)
		maxCodecs := 5
		if len(codecs) < maxCodecs {
			maxCodecs = len(codecs)
		}

		barWidth := 25
		for i := 0; i < maxCodecs; i++ {
			codec := codecs[i]
			result.WriteString("  ")
			result.WriteString(RenderDistributionBar(
				fmt.Sprintf("%-8s", codec.name),
				codec.count,
				maxCount,
				barWidth,
				theme,
			))
			result.WriteString("\n")
		}

		if len(codecs) > maxCodecs {
			result.WriteString(dimStyle.Render(fmt.Sprintf("  ... and %d more codecs\n", len(codecs)-maxCodecs)))
		}
	}

	return result.String()
}

// formatCallDuration formats a duration in seconds to a human-readable string.
func formatCallDuration(seconds float64) string {
	if seconds < 60 {
		return fmt.Sprintf("%.0fs", seconds)
	}
	minutes := int(seconds / 60)
	secs := int(seconds) % 60
	if minutes < 60 {
		return fmt.Sprintf("%dm %ds", minutes, secs)
	}
	hours := minutes / 60
	mins := minutes % 60
	return fmt.Sprintf("%dh %dm", hours, mins)
}
