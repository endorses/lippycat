// Package output provides utilities for consistent CLI output formatting.
package output

import (
	"encoding/json"
	"os"

	"golang.org/x/term"
)

// IsTTY returns true if stdout is connected to a terminal.
func IsTTY() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// MarshalJSON marshals v to JSON with formatting based on TTY detection.
// When stdout is a TTY, output is pretty-printed with 2-space indentation.
// When piped or redirected, output is compact single-line JSON.
func MarshalJSON(v any) ([]byte, error) {
	return MarshalJSONPretty(v, IsTTY())
}

// MarshalJSONPretty marshals v to JSON with explicit formatting control.
// When pretty is true, output is indented with 2 spaces.
// When pretty is false, output is compact single-line JSON.
func MarshalJSONPretty(v any, pretty bool) ([]byte, error) {
	if pretty {
		return json.MarshalIndent(v, "", "  ")
	}
	return json.Marshal(v)
}
