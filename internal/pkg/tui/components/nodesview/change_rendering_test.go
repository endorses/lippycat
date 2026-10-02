//go:build tui || all

package nodesview

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/muesli/termenv"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Inspect effective terminal colors, including surrounding row/box styles and
// resets, rather than only checking that an escape sequence occurs somewhere.
func colorsAtText(t *testing.T, output, token string) (foreground, background string) {
	t.Helper()
	index := strings.Index(output, token)
	require.NotEqual(t, -1, index, "missing token %q", token)
	for _, match := range regexp.MustCompile(`\x1b\[([0-9;]*)m`).FindAllStringSubmatch(output[:index], -1) {
		params := strings.Split(match[1], ";")
		for i := 0; i < len(params); i++ {
			switch params[i] {
			case "", "0":
				foreground, background = "", ""
			case "39":
				foreground = ""
			case "49":
				background = ""
			case "38", "48":
				require.GreaterOrEqual(t, len(params)-i, 3)
				if params[i+1] == "5" {
					if params[i] == "38" {
						foreground = "indexed:" + params[i+2]
					} else {
						background = "indexed:" + params[i+2]
					}
					i += 2
					continue
				}
				require.GreaterOrEqual(t, len(params)-i, 5)
				require.Equal(t, "2", params[i+1], "expected truecolor output")
				var rgb [3]int
				for j := range rgb {
					value, err := strconv.Atoi(params[i+j+2])
					require.NoError(t, err)
					rgb[j] = value
				}
				color := fmt.Sprintf("#%02x%02x%02x", rgb[0], rgb[1], rgb[2])
				if params[i] == "38" {
					foreground = color
				} else {
					background = color
				}
				i += 4
			case "30":
				foreground = "#000000"
			case "40":
				background = "#000000"
			}
		}
	}
	return foreground, background
}

func TestNodeHighlightPaletteInRenderedViews(t *testing.T) {
	original := lipgloss.ColorProfile()
	t.Cleanup(func() { lipgloss.SetColorProfile(original) })
	lipgloss.SetColorProfile(termenv.TrueColor)
	for _, view := range []string{"tree", "flat", "graph"} {
		for _, selected := range []bool{false, true} {
			for _, reverse := range []bool{false, true} {
				for _, quiet := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/selected=%v/reverse=%v/quiet=%v", view, selected, reverse, quiet), func(t *testing.T) {
						processor, changes := changeRenderingFixture()
						key := NodeKey{ProcessorAddr: processor.Address, HunterID: "edge"}
						change := changes[key]
						change.CapturedChanged, change.ForwardedChanged = !reverse, reverse
						cpuColor, ramColor, activeCounter, idleCounter, delta := "#dc322f", "#cb4b16", "12.4M", "12.3M", "+2"
						if reverse {
							change.CPU, change.Memory, change.FilterDelta = ResourceElevated, ResourceHigh, -2
							cpuColor, ramColor, activeCounter, idleCounter, delta = ramColor, cpuColor, idleCounter, activeCounter, "-2"
						}
						changes[key] = change
						index := -1
						if selected {
							index = 0
						}
						params := TableViewParams{Processors: []ProcessorInfo{processor}, Hunters: processor.Hunters, SelectedIndex: index, Width: 160, Theme: themes.Solarized(), Changes: changes, Quiet: quiet, HunterLines: map[int]int{}, ProcessorLines: map[int]int{}}
						var output string
						switch view {
						case "tree":
							output, _ = RenderTreeView(params)
						case "flat":
							output, _ = RenderFlatView(params)
						case "graph":
							output = RenderGraphView(GraphViewParams{Processors: params.Processors, Hunters: params.Hunters, SelectedIndex: index, Width: 160, Theme: params.Theme, Changes: changes, Quiet: quiet}).Content
						}
						for token, want := range map[string]string{"24%": cpuColor, "182.0M": ramColor} {
							fg, bg := colorsAtText(t, output, token)
							assert.Equal(t, want, fg, token)
							assert.NotEqual(t, want, bg, token)
							if selected && view != "graph" {
								assert.Equal(t, "#000000", bg, "resource value stays legible against selection")
							}
						}
						for token, want := range map[string]string{delta: "#268bd2", activeCounter: "#859900"} {
							fg, bg := colorsAtText(t, output, token)
							if quiet {
								assert.NotEqual(t, want, bg, token)
								continue
							}
							assert.Equal(t, "#fdf6e3", fg, token)
							assert.Equal(t, want, bg, token)
						}
						_, bg := colorsAtText(t, output, idleCounter)
						assert.NotEqual(t, "#859900", bg, "unchanged counter must not inherit activity highlight")
						if selected && view != "graph" {
							_, bg = colorsAtText(t, output, "192.0.2.1")
							assert.Equal(t, "#2aa198", bg, "row selection remains visible between highlights")
						}
					})
				}
			}
		}
	}
}

func changeRenderingFixture() (ProcessorInfo, map[NodeKey]NodeChanges) {
	hunter := types.HunterInfo{ID: "edge", ProcessorAddr: "central:55555", Hostname: "192.0.2.1", CPUPercent: 24, MemoryRSSBytes: 182000000, PacketsCaptured: 12400000, PacketsForwarded: 12300000, ActiveFilters: 10, Status: management.HunterStatus_STATUS_HEALTHY}
	processor := ProcessorInfo{Address: hunter.ProcessorAddr, ProcessorID: "central", Hunters: []types.HunterInfo{hunter}, TotalHunters: 1, ConnectionState: ProcessorConnectionStateConnected}
	changes := map[NodeKey]NodeChanges{
		{ProcessorAddr: processor.Address}:                      {Label: "NEW", StatusChanged: true},
		{ProcessorAddr: processor.Address, HunterID: hunter.ID}: {CPU: ResourceHigh, Memory: ResourceElevated, FiltersChanged: true, FilterDelta: 2, Activity: true, CapturedChanged: true, ForwardedChanged: true, Label: "RECOVERED", StatusChanged: true},
	}
	return processor, changes
}

func TestNodeTableChangesKeepColumnWidthsAndSelection(t *testing.T) {
	processor, changes := changeRenderingFixture()
	for _, flat := range []bool{false, true} {
		for _, width := range []int{40, 65, 120, 160} {
			params := TableViewParams{Processors: []ProcessorInfo{processor}, Hunters: processor.Hunters, SelectedIndex: 0, Width: width, Theme: themes.Solarized(), HunterLines: map[int]int{}, ProcessorLines: map[int]int{}}
			render := RenderTreeView
			if flat {
				render = RenderFlatView
			}
			baseline, baselineLine := render(params)
			params.Changes = changes
			changed, changedLine := render(params)
			require.Equal(t, baselineLine, changedLine)
			baselineRow := strings.Split(ansi.Strip(baseline), "\n")[baselineLine]
			changedRow := strings.Split(ansi.Strip(changed), "\n")[changedLine]
			assert.Equal(t, lipgloss.Width(baselineRow), lipgloss.Width(changedRow), "width=%d flat=%v", width, flat)
			assert.LessOrEqual(t, lipgloss.Width(changedRow), width)
			assert.Contains(t, changedRow, "24%")
			assert.Contains(t, changedRow, "182.0M")
			if width >= 65 {
				assert.NotContains(t, changedRow, "↑")
				assert.NotContains(t, changedRow, "↓")
				assert.Contains(t, changedRow, "+2")
				assert.Contains(t, changedRow, "·")
			}
			if width >= 120 {
				assert.Contains(t, changedRow, "RECOVERED")
				assert.Equal(t, lipgloss.Width(baselineRow[:strings.Index(baselineRow, "24%")]), lipgloss.Width(changedRow[:strings.Index(changedRow, "24%")]))
			}
			params.Quiet = true
			quiet, quietLine := render(params)
			assert.Equal(t, changedLine, quietLine)
			assert.Equal(t, ansi.Strip(changed), ansi.Strip(quiet))
		}
	}
}

func TestNodeGraphChangesPreserveRegionsAndBoxWidths(t *testing.T) {
	processor, changes := changeRenderingFixture()
	for _, width := range []int{40, 80, 140} {
		params := GraphViewParams{Processors: []ProcessorInfo{processor}, Hunters: processor.Hunters, SelectedIndex: 0, Width: width, Theme: themes.Solarized()}
		baseline := RenderGraphView(params)
		params.Changes = changes
		changed := RenderGraphView(params)
		assert.Equal(t, baseline.SelectedNodeLine, changed.SelectedNodeLine)
		assert.Equal(t, baseline.HunterBoxRegions, changed.HunterBoxRegions)
		assert.Equal(t, baseline.ProcessorBoxRegions, changed.ProcessorBoxRegions)
		assert.Contains(t, ansi.Strip(changed.Content), "24%")
		assert.Contains(t, ansi.Strip(changed.Content), "182.0M")
		assert.Contains(t, ansi.Strip(changed.Content), "10 +2")
		assert.Contains(t, changed.Content, "┏") // Selection survives an accent.
		baselineLines := strings.Split(baseline.Content, "\n")
		changedLines := strings.Split(changed.Content, "\n")
		require.Len(t, changedLines, len(baselineLines))
		for i := range changedLines {
			assert.Equal(t, lipgloss.Width(baselineLines[i]), lipgloss.Width(changedLines[i]), "line=%d width=%d", i, width)
		}
		params.Quiet = true
		quiet := RenderGraphView(params)
		assert.Equal(t, ansi.Strip(changed.Content), ansi.Strip(quiet.Content))
	}
}

func TestNodeChangeColorsAndQuietAcrossThemeAndColorProfiles(t *testing.T) {
	original := lipgloss.ColorProfile()
	t.Cleanup(func() { lipgloss.SetColorProfile(original) })
	dark := themes.Solarized()
	light := dark
	light.Foreground = lipgloss.Color("#002b36")
	light.Background = lipgloss.Color("#fdf6e3")
	light.StatusBarBg = lipgloss.Color("#eee8d5")
	for _, theme := range []themes.Theme{dark, light} {
		for _, profile := range []termenv.Profile{termenv.TrueColor, termenv.ANSI, termenv.Ascii} {
			lipgloss.SetColorProfile(profile)
			processor, changes := changeRenderingFixture()
			params := GraphViewParams{Processors: []ProcessorInfo{processor}, Width: 140, SelectedIndex: 0, Theme: theme, Changes: changes}
			normal := RenderGraphView(params)
			params.Quiet = true
			quiet := RenderGraphView(params)
			assert.Equal(t, ansi.Strip(normal.Content), ansi.Strip(quiet.Content))
			assert.Contains(t, ansi.Strip(quiet.Content), "RECOVERED")
			assert.NotContains(t, ansi.Strip(quiet.Content), "↑")
			if profile != termenv.Ascii {
				assert.NotEqual(t, normal.Content, quiet.Content)
			}
			for _, line := range strings.Split(normal.Content, "\n") {
				assert.True(t, utf8.ValidString(line))
			}
		}
	}
}

func TestNodeCellsPrioritizeValuesAndUseTerminalWidths(t *testing.T) {
	assert.Equal(t, "-    ", fitCell("-", 5))
	assert.Equal(t, "100%", fitCell("100%", 4))
	assert.Equal(t, "10     ", filterText(10, NodeChanges{FiltersChanged: true, FilterDelta: 1234567}, 7))
	assert.Equal(t, "edge", withChangeLabel("edge", "RECOVERED", 4))
	for _, input := range []string{"界界界", "ééééé", "\x1b[31m界界界\x1b[0m"} {
		cell := fitCell(input, 5)
		assert.Equal(t, 5, lipgloss.Width(cell))
		assert.True(t, utf8.ValidString(cell))
	}
}

func TestUnavailableHunterMetricsRemainMissing(t *testing.T) {
	processor, changes := changeRenderingFixture()
	processor.Hunters[0].StatsUnavailable = true
	params := TableViewParams{Processors: []ProcessorInfo{processor}, Hunters: processor.Hunters, SelectedIndex: 0, Width: 160, Theme: themes.Solarized(), Changes: changes, HunterLines: map[int]int{}, ProcessorLines: map[int]int{}}
	table, selected := RenderTreeView(params)
	row := strings.Split(ansi.Strip(table), "\n")[selected]
	for _, oldValue := range []string{"24%", "182.0M", "12.4M", "12.3M", "+2", "↑", "↓", "·"} {
		assert.NotContains(t, row, oldValue)
	}
	assert.GreaterOrEqual(t, strings.Count(row, "-"), 5)
	graph := RenderGraphView(GraphViewParams{Processors: []ProcessorInfo{processor}, Width: 140, SelectedIndex: 0, Theme: themes.Solarized(), Changes: changes})
	for _, oldValue := range []string{"24%", "182.0M", "12.4M", "12.3M", "+2", "·"} {
		assert.NotContains(t, ansi.Strip(graph.Content), oldValue)
	}
}

func TestNodeRenderingLongIdentitiesAndShortWidths(t *testing.T) {
	processor, changes := changeRenderingFixture()
	processor.Hunters[0].ID = "東京-edge-with-a-long-identity"
	processor.Hunters[0].Hostname = "2001:db8:1234:5678::abcdef"
	changes[NodeKey{ProcessorAddr: processor.Address, HunterID: processor.Hunters[0].ID}] = changes[NodeKey{ProcessorAddr: processor.Address, HunterID: "edge"}]
	for _, width := range []int{20, 40, 160} {
		params := TableViewParams{Processors: []ProcessorInfo{processor}, Hunters: processor.Hunters, SelectedIndex: 0, Width: width, Theme: themes.Solarized(), Changes: changes, HunterLines: map[int]int{}, ProcessorLines: map[int]int{}}
		table, _ := RenderTreeView(params)
		for _, line := range strings.Split(table, "\n") {
			assert.True(t, utf8.ValidString(line))
			assert.LessOrEqual(t, lipgloss.Width(line), width)
		}
	}
	graph := RenderGraphView(GraphViewParams{Processors: []ProcessorInfo{processor}, Width: 80, SelectedIndex: 0, Theme: themes.Solarized(), Changes: changes})
	region := graph.HunterBoxRegions[0]
	for _, line := range strings.Split(graph.Content, "\n")[region.StartLine : region.EndLine+1] {
		assert.True(t, utf8.ValidString(line))
		assert.Equal(t, region.EndCol, lipgloss.Width(line))
	}
}

func TestSelectedTableStatusAccentsPreserveANSIText(t *testing.T) {
	original := lipgloss.ColorProfile()
	t.Cleanup(func() { lipgloss.SetColorProfile(original) })
	dark := themes.Solarized()
	light := dark
	light.Foreground, light.Background, light.StatusBarBg = lipgloss.Color("#002b36"), lipgloss.Color("#fdf6e3"), lipgloss.Color("#eee8d5")
	for _, theme := range []themes.Theme{dark, light} {
		for _, profile := range []termenv.Profile{termenv.TrueColor, termenv.ANSI, termenv.Ascii} {
			lipgloss.SetColorProfile(profile)
			for _, flat := range []bool{false, true} {
				for _, selectProcessor := range []bool{false, true} {
					processor, changes := changeRenderingFixture()
					processor.Hunters[0].Status = management.HunterStatus_STATUS_ERROR
					params := TableViewParams{Processors: []ProcessorInfo{processor}, Hunters: processor.Hunters, SelectedIndex: 0, Width: 160, Theme: theme, Changes: changes, HunterLines: map[int]int{}, ProcessorLines: map[int]int{}}
					if selectProcessor {
						params.SelectedProcessorAddr, params.SelectedIndex = processor.Address, -1
					}
					render := RenderTreeView
					if flat {
						render = RenderFlatView
					}
					normal, normalLine := render(params)
					params.Quiet = true
					quiet, quietLine := render(params)
					assert.Equal(t, quietLine, normalLine)
					assert.Equal(t, ansi.Strip(quiet), ansi.Strip(normal), "profile=%v flat=%v processor=%v", profile, flat, selectProcessor)
					assert.NotContains(t, ansi.Strip(normal), "\x1b")
					status := "✗·"
					if flat {
						status = "ERROR·"
					}
					assert.Contains(t, ansi.Strip(normal), status)
				}
			}
		}
	}
}
