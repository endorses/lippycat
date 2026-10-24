//go:build tui || all

package components

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/sms"
)

// safeSMSDisplay prevents content from executing terminal controls while keeping
// ordinary Unicode and message line breaks intact. Wrapping is owned by the
// details viewport and uses terminal-cell widths.
func safeSMSDisplay(text string) string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	var result strings.Builder
	for _, r := range text {
		switch {
		case r == '\n':
			result.WriteRune(r)
		case r == '\t':
			result.WriteString("    ")
		case unicode.IsControl(r) || r == '\u2028' || r == '\u2029' || (r >= '\u202a' && r <= '\u202e') || (r >= '\u2066' && r <= '\u2069'):
			if r < 256 {
				fmt.Fprintf(&result, "\\x%02x", r)
			} else {
				fmt.Fprintf(&result, "\\u%04x", r)
			}
		default:
			result.WriteRune(r)
		}
	}
	return result.String()
}

func renderSMSDetails(call *Call, heading lipgloss.Style) string {
	if len(call.SMS) == 0 {
		if call.State == CallStateMessage {
			return "\n" + heading.Render("Message:") + "\nSMS content unavailable (no decoded metadata)\n"
		}
		return ""
	}
	var result strings.Builder
	result.WriteString("\n" + heading.Render("Message:") + "\n")
	shownAssemblies := make(map[string]bool)
	for index, record := range call.SMS {
		message := record.Message
		if message == nil {
			continue
		}
		if len(call.SMS) > 1 {
			fmt.Fprintf(&result, "Message %d\n", index+1)
		}
		fmt.Fprintf(&result, "Encoding: %s\n", safeSMSDisplay(string(message.Encoding)))
		if message.From != "" {
			fmt.Fprintf(&result, "SMS sender: %s\n", safeSMSDisplay(message.From))
		}
		if message.To != "" {
			fmt.Fprintf(&result, "SMS recipient: %s\n", safeSMSDisplay(message.To))
		}
		if message.Status != sms.StatusDecoded {
			fmt.Fprintf(&result, "Decode status: %s\n", safeSMSDisplay(string(message.Status)))
		}
		if message.Concat != nil {
			fmt.Fprintf(&result, "Part %d of %d (reference %d, %d-bit)\n", message.Concat.Part, message.Concat.Total, message.Concat.Reference, message.Concat.ReferenceBits)
			fmt.Fprintf(&result, "Assembly: %s; received %v; missing %v\n", safeSMSDisplay(string(message.Assembly.Status)), message.Assembly.Received, message.Assembly.Missing)
			if message.Assembly.Status == sms.AssemblyComplete {
				if !shownAssemblies[message.Assembly.ID] {
					result.WriteString("Complete text:\n" + safeSMSDisplay(message.Assembly.Text) + "\n")
					shownAssemblies[message.Assembly.ID] = true
				}
			} else if message.Status == sms.StatusDecoded {
				result.WriteString("Incomplete text (this segment):\n" + safeSMSDisplay(message.Text) + "\n")
			}
		} else if message.Status == sms.StatusDecoded {
			if message.Assembly.Status == sms.AssemblyConflict {
				result.WriteString("Conflicting transaction content observed; original text:\n")
			}
			if message.Text == "" {
				result.WriteString("Text: (empty)\n")
			} else {
				result.WriteString(safeSMSDisplay(message.Text) + "\n")
			}
		}
		if message.Status != sms.StatusDecoded {
			result.WriteString("Decoded text unavailable; inspect the raw SIP packet for details.\n")
		}
	}
	return result.String()
}
