//go:build tui || all

package components

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/sms"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestSMSDetailsEscapesControlsAndPreservesUnicode(t *testing.T) {
	call := &Call{State: CallStateMessage, SMS: []types.SMSRecord{{Message: &sms.Message{Status: sms.StatusDecoded, Encoding: sms.EncodingUCS2, Text: "Hello 界\nline\x1b[31m\x00\u009b31m\u202e", From: "+123", To: "+456"}}}}
	content := renderSMSDetails(call, lipgloss.NewStyle())
	require.Contains(t, content, "Hello 界\nline\\x1b[31m\\x00\\x9b31m\\u202e")
	require.NotContains(t, content, "\x1b")
	require.Contains(t, content, "SMS sender: +123")
	for _, width := range []int{2, 8, 20, 80} {
		wrapped := wrapDetailContent(content, width, false)
		for _, line := range strings.Split(wrapped, "\n") {
			require.LessOrEqual(t, lipgloss.Width(line), width)
		}
	}
	view := NewCallsView()
	view.SetCalls([]Call{*call})
	view.PrepareDetails(1, 20)
	for _, line := range strings.Split(view.RenderDetails(1, 20, true), "\n") {
		require.LessOrEqual(t, lipgloss.Width(line), 1)
	}
}

func TestSMSDetailsReportsAssemblyAndUnavailableContent(t *testing.T) {
	message := &sms.Message{Status: sms.StatusDecoded, Encoding: sms.EncodingGSM7, Text: "world", Concat: &sms.Concatenation{Reference: 8, ReferenceBits: 16, Total: 2, Part: 2}, Assembly: sms.AssemblyInfo{ID: "group", Status: sms.AssemblyPending, Received: []uint8{2}, Missing: []uint8{1}}}
	call := &Call{State: CallStateMessage, SMS: []types.SMSRecord{{Message: message}}}
	content := renderSMSDetails(call, lipgloss.NewStyle())
	require.Contains(t, content, "Part 2 of 2 (reference 8, 16-bit)")
	require.Contains(t, content, "missing [1]")
	require.Contains(t, content, "Incomplete text (this segment):\nworld")
	message.Assembly.Status = sms.AssemblyComplete
	message.Assembly.Text = "hello world"
	message.Assembly.Missing = nil
	content = renderSMSDetails(call, lipgloss.NewStyle())
	require.Contains(t, content, "Complete text:\nhello world")
	require.NotContains(t, content, "Incomplete text")
	require.Contains(t, renderSMSDetails(&Call{State: CallStateMessage}, lipgloss.NewStyle()), "content unavailable")
	require.Empty(t, renderSMSDetails(&Call{State: CallStateActive}, lipgloss.NewStyle()))
}
