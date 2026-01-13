//go:build tui || all

package settings

import (
	"strconv"

	"github.com/charmbracelet/bubbles/textinput"
)

// CreateCommonInputs creates the buffer size and filter text inputs used by multiple modes.
// These inputs share common styling and validation logic.
func CreateCommonInputs(bufferSize int, filter string) (textinput.Model, textinput.Model) {
	// Buffer size input
	bufferInput := textinput.New()
	bufferInput.Placeholder = "10000"
	bufferInput.CharLimit = 10
	bufferInput.Width = 20
	bufferInput.SetValue(strconv.Itoa(bufferSize))

	// Filter input
	filterInput := textinput.New()
	filterInput.Placeholder = "e.g., port 5060 or tcp"
	filterInput.CharLimit = 256
	filterInput.Width = 60
	filterInput.SetValue(filter)

	return bufferInput, filterInput
}
