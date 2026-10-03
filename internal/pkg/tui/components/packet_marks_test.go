//go:build tui || all

package components

import (
	"fmt"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/stretchr/testify/require"
)

func TestPacketMarksUsePaddingWithoutMovingContent(t *testing.T) {
	for _, virtual := range []bool{false, true} {
		for _, details := range []bool{false, true} {
			t.Run(fmt.Sprintf("virtual=%t/details=%t", virtual, details), func(t *testing.T) {
				p := NewPacketList()
				p.SetSize(120, 12)
				packets := []PacketDisplay{{CaptureID: 1, Info: "first", Protocol: "TCP"}, {CaptureID: 2, Info: "second", Protocol: "UDP"}, {CaptureID: 0, Info: "missing", Protocol: "TCP"}}
				if virtual {
					p.SetVirtualPackets(3, 0, packets)
				} else {
					p.SetPackets(packets)
				}
				before := ansi.Strip(p.View(true, details))
				p.SetMarkedPackets(map[uint64]bool{0: true, 2: true})
				after := ansi.Strip(p.View(true, details))
				require.Equal(t, lipgloss.Width(before), lipgloss.Width(after))
				require.Equal(t, lipgloss.Height(before), lipgloss.Height(after))
				require.Equal(t, before, strings.ReplaceAll(after, "*", " "))
				require.Equal(t, 1, strings.Count(after, "*"))
				lines := strings.Split(after, "\n")
				require.Equal(t, "*", ansi.Cut(lines[4], 1, 2))
				require.Contains(t, lines[4], "second")
				p.SetMarkedPackets(nil)
				require.Equal(t, before, ansi.Strip(p.View(true, details)))
			})
		}
	}
}

func TestPacketMarksSkipUnloadedVirtualRows(t *testing.T) {
	p := NewPacketList()
	p.SetSize(120, 12)
	p.SetVirtualPackets(100, 20, []PacketDisplay{{CaptureID: 1, Info: "other page"}})
	p.SetMarkedPackets(map[uint64]bool{1: true})
	view := ansi.Strip(p.View(true, false))
	require.Contains(t, view, "Loading packet")
	require.NotContains(t, view, "*")
}

func TestSaveDialogClearMarksKeepsDialogOpen(t *testing.T) {
	fd := fileDialogFixture(t, true)
	originalTitle := fd.ModalOptions().Title
	fd.SetPacketMarks(12)
	require.Equal(t, "Save 12 marked packets", fd.ModalOptions().Title)
	require.Contains(t, ansi.Strip(fd.View()), "Clear marks")
	cmd := clickFileControl(t, &fd, "clear-marks")
	require.NotNil(t, cmd)
	require.IsType(t, ClearPacketMarksMsg{}, cmd())
	require.True(t, fd.IsActive())
	require.Equal(t, originalTitle, fd.ModalOptions().Title)
	require.NotContains(t, ansi.Strip(fd.View()), "Clear marks")
	require.Nil(t, fd.HandleModalAction("clear-marks"))
}

func TestOpenDialogDoesNotOfferPacketMarkActions(t *testing.T) {
	fd := fileDialogFixture(t, false)
	originalTitle := fd.ModalOptions().Title
	fd.SetPacketMarks(12)
	require.Equal(t, originalTitle, fd.ModalOptions().Title)
	require.NotContains(t, ansi.Strip(fd.View()), "Clear marks")
	require.Nil(t, fd.HandleModalAction("clear-marks"))
}

func TestFooterMarkedSaveHint(t *testing.T) {
	f := NewFooter()
	f.SetWidth(240)
	f.SetMarkedPacketCount(12)
	require.Contains(t, ansi.Strip(f.View()), "w: save marked (12)")
	require.Contains(t, ansi.Strip(f.View()), "m: mark")
	f.SetWidth(100)
	require.Contains(t, ansi.Strip(f.View()), "w:sav 12*")
	f.SetWidth(60)
	require.Contains(t, ansi.Strip(f.View()), "w:12*")
	f.SetWidth(100)
	f.SetStreamingSave(true)
	require.Contains(t, ansi.Strip(f.View()), "w:stp")
	f.SetStreamingSave(false)
	f.SetMarkedPacketCount(0)
	require.Contains(t, ansi.Strip(f.View()), "w:sav")
	require.NotContains(t, ansi.Strip(f.View()), "12*")
	f.SetDetailsFocused(true)
	require.NotContains(t, ansi.Strip(f.View()), "m:mark")
}
