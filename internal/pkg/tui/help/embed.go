//go:build tui || all

// Package help provides embedded help documentation for the TUI.
package help

import "embed"

//go:embed *.md
var Files embed.FS
