//go:build tui || all
// +build tui all

package themes

import "github.com/charmbracelet/lipgloss"

// Theme represents a color theme for the TUI
type Theme struct {
	Name string

	// General UI colors
	Background         lipgloss.Color
	Foreground         lipgloss.Color
	TerminalBg         lipgloss.Color // Actual terminal background (transparent)
	HeaderBg           lipgloss.Color
	HeaderFg           lipgloss.Color
	StatusBarBg        lipgloss.Color
	StatusBarFg        lipgloss.Color
	SelectionBg        lipgloss.Color
	SelectionFg        lipgloss.Color
	CursorBg           lipgloss.Color // Cursor background color
	CursorFg           lipgloss.Color // Cursor foreground color
	BorderColor        lipgloss.Color
	FocusedBorderColor lipgloss.Color

	// Protocol colors
	TCPColor     lipgloss.Color
	UDPColor     lipgloss.Color
	SIPColor     lipgloss.Color
	RTPColor     lipgloss.Color
	DNSColor     lipgloss.Color
	HTTPColor    lipgloss.Color
	TLSColor     lipgloss.Color
	SSHColor     lipgloss.Color
	ICMPColor    lipgloss.Color
	ICMPv6Color  lipgloss.Color
	ARPColor     lipgloss.Color
	VPNColor     lipgloss.Color
	UnknownColor lipgloss.Color
	ErrorColor   lipgloss.Color

	// Emphasis colors
	WarningColor lipgloss.Color
	SuccessColor lipgloss.Color
	InfoColor    lipgloss.Color
	FilterColor  lipgloss.Color
}

// Solarized color palette
var (
	// Solarized Dark base colors
	solarizedBase03 = lipgloss.Color("#002b36") // background
	solarizedBase02 = lipgloss.Color("#073642") // background highlights
	solarizedBase01 = lipgloss.Color("#586e75") // comments / secondary content
	solarizedBase00 = lipgloss.Color("#657b83") // body text / default code
	solarizedBase0  = lipgloss.Color("#839496") // body text / default code
	solarizedBase1  = lipgloss.Color("#93a1a1") // optional emphasized content
	solarizedBase2  = lipgloss.Color("#eee8d5") // background highlights (light)
	solarizedBase3  = lipgloss.Color("#fdf6e3") // background (light)

	// Solarized accent colors
	solarizedYellow  = lipgloss.Color("#b58900")
	solarizedOrange  = lipgloss.Color("#cb4b16")
	solarizedRed     = lipgloss.Color("#dc322f")
	solarizedMagenta = lipgloss.Color("#d33682")
	solarizedViolet  = lipgloss.Color("#6c71c4")
	solarizedBlue    = lipgloss.Color("#268bd2")
	solarizedCyan    = lipgloss.Color("#2aa198")
	solarizedGreen   = lipgloss.Color("#859900")
)

// Solarized returns the Solarized theme (htop-like with transparent background)
func Solarized() Theme {
	return Theme{
		Name: "Solarized",

		// General UI
		Background:         lipgloss.Color("0"),
		Foreground:         solarizedBase0,
		TerminalBg:         lipgloss.Color("0"),
		HeaderBg:           solarizedGreen,
		HeaderFg:           lipgloss.Color("0"),
		StatusBarBg:        solarizedBase02,
		StatusBarFg:        solarizedBase0,
		SelectionBg:        solarizedCyan,
		SelectionFg:        lipgloss.Color("0"),
		CursorBg:           solarizedBlue,
		CursorFg:           solarizedBase3, // Light foreground for cursor in dark mode
		BorderColor:        solarizedBase1,
		FocusedBorderColor: solarizedRed,

		// Protocol colors
		TCPColor:     solarizedCyan,
		UDPColor:     solarizedGreen,
		SIPColor:     solarizedBlue,
		RTPColor:     solarizedGreen,
		DNSColor:     solarizedYellow,
		HTTPColor:    solarizedViolet,
		TLSColor:     solarizedMagenta,
		SSHColor:     solarizedMagenta,
		ICMPColor:    solarizedOrange,
		ICMPv6Color:  solarizedOrange,
		ARPColor:     solarizedYellow,
		VPNColor:     solarizedMagenta,
		UnknownColor: solarizedBase0,
		ErrorColor:   solarizedRed,

		// Emphasis
		WarningColor: solarizedOrange,
		SuccessColor: solarizedGreen,
		InfoColor:    solarizedBlue,
		FilterColor:  solarizedViolet,
	}
}

// GetTheme returns a theme by name
func GetTheme(name string) Theme {
	switch name {
	case "solarized":
		return Solarized()
	default:
		return Solarized() // Default to solarized
	}
}
