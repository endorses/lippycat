//go:build tui || all
// +build tui all

package components

import (
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// EmailSession represents aggregated email session statistics
type EmailSession struct {
	SessionID     string
	MailFrom      string
	RcptTo        []string
	Subject       string
	MessageCount  int64
	CommandCount  int64
	ResponseCount int64
	Encrypted     bool
	AuthMethod    string
	ServerBanner  string
	ClientHelo    string
	LastSeen      time.Time
	MessageSize   int
}

// EmailView displays aggregated email sessions
type EmailView struct {
	sessions    []EmailSession
	sessionMap  map[string]*EmailSession // Map from session ID to session for updates
	selected    int
	offset      int
	width       int
	height      int
	theme       themes.Theme
	showDetails bool
}

// NewEmailView creates a new Email view
func NewEmailView() *EmailView {
	return &EmailView{
		sessions:    make([]EmailSession, 0),
		sessionMap:  make(map[string]*EmailSession),
		selected:    0,
		offset:      0,
		showDetails: false,
		theme:       themes.Solarized(),
	}
}

// SetTheme sets the color theme
func (ev *EmailView) SetTheme(theme themes.Theme) {
	ev.theme = theme
}

// SetSize sets the dimensions
func (ev *EmailView) SetSize(width, height int) {
	ev.width = width
	ev.height = height
}

// UpdateFromPacket updates email session stats from a packet with Email metadata
func (ev *EmailView) UpdateFromPacket(pkt *types.PacketDisplay) {
	if pkt.EmailData == nil {
		return
	}

	// Use SessionID if available, otherwise create one from addresses
	sessionID := pkt.EmailData.SessionID
	if sessionID == "" {
		sessionID = fmt.Sprintf("%s-%s", pkt.SrcIP, pkt.DstIP)
	}

	session, exists := ev.sessionMap[sessionID]
	if !exists {
		session = &EmailSession{
			SessionID: sessionID,
			RcptTo:    make([]string, 0),
		}
		ev.sessionMap[sessionID] = session
	}

	// Update session from packet metadata
	if pkt.EmailData.MailFrom != "" {
		session.MailFrom = pkt.EmailData.MailFrom
	}
	if len(pkt.EmailData.RcptTo) > 0 {
		// Merge recipients
		rcptSet := make(map[string]bool)
		for _, r := range session.RcptTo {
			rcptSet[r] = true
		}
		for _, r := range pkt.EmailData.RcptTo {
			if !rcptSet[r] {
				session.RcptTo = append(session.RcptTo, r)
				rcptSet[r] = true
			}
		}
	}
	if pkt.EmailData.Subject != "" {
		session.Subject = pkt.EmailData.Subject
	}
	if pkt.EmailData.ServerBanner != "" {
		session.ServerBanner = pkt.EmailData.ServerBanner
	}
	if pkt.EmailData.ClientHelo != "" {
		session.ClientHelo = pkt.EmailData.ClientHelo
	}
	if pkt.EmailData.AuthMethod != "" {
		session.AuthMethod = pkt.EmailData.AuthMethod
	}
	if pkt.EmailData.Encrypted {
		session.Encrypted = true
	}
	if pkt.EmailData.MessageSize > session.MessageSize {
		session.MessageSize = pkt.EmailData.MessageSize
	}

	// Count commands and responses
	if pkt.EmailData.IsServer {
		session.ResponseCount++
	} else {
		session.CommandCount++
		if pkt.EmailData.Command == "DATA" {
			session.MessageCount++
		}
	}

	session.LastSeen = pkt.Timestamp

	// Rebuild sorted list
	ev.rebuildSessionList()
}

// rebuildSessionList rebuilds the sorted session list from the map
func (ev *EmailView) rebuildSessionList() {
	ev.sessions = make([]EmailSession, 0, len(ev.sessionMap))
	for _, s := range ev.sessionMap {
		ev.sessions = append(ev.sessions, *s)
	}

	// Sort by last seen (most recent first)
	sort.Slice(ev.sessions, func(i, j int) bool {
		return ev.sessions[i].LastSeen.After(ev.sessions[j].LastSeen)
	})

	// Adjust selection if needed
	if ev.selected >= len(ev.sessions) && len(ev.sessions) > 0 {
		ev.selected = len(ev.sessions) - 1
	}
}

// GetSelected returns the currently selected session
func (ev *EmailView) GetSelected() *EmailSession {
	if ev.selected >= 0 && ev.selected < len(ev.sessions) {
		return &ev.sessions[ev.selected]
	}
	return nil
}

// SelectNext moves selection down
func (ev *EmailView) SelectNext() {
	if ev.selected < len(ev.sessions)-1 {
		ev.selected++
		ev.adjustOffset()
	}
}

// SelectPrevious moves selection up
func (ev *EmailView) SelectPrevious() {
	if ev.selected > 0 {
		ev.selected--
		ev.adjustOffset()
	}
}

// ToggleDetails toggles the details panel
func (ev *EmailView) ToggleDetails() {
	ev.showDetails = !ev.showDetails
}

// IsShowingDetails returns whether the details panel is visible
func (ev *EmailView) IsShowingDetails() bool {
	return ev.showDetails
}

// Update handles messages
func (ev *EmailView) Update(msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			ev.SelectPrevious()
		case "down", "j":
			ev.SelectNext()
		case "d":
			ev.ToggleDetails()
		case "home", "g":
			if len(ev.sessions) > 0 {
				ev.selected = 0
				ev.offset = 0
			}
		case "end", "G":
			if len(ev.sessions) > 0 {
				ev.selected = len(ev.sessions) - 1
				ev.adjustOffset()
			}
		case "pgup":
			ev.PageUp()
		case "pgdown":
			ev.PageDown()
		}
	case tea.MouseMsg:
		if msg.Type == tea.MouseLeft {
			ev.HandleMouseClick(msg.Y)
		}
	}
	return nil
}

// HandleMouseClick handles mouse clicks on session rows
func (ev *EmailView) HandleMouseClick(mouseY int) {
	headerOffset := 4
	if mouseY < headerOffset {
		return
	}

	clickedRow := mouseY - headerOffset + ev.offset
	if clickedRow >= 0 && clickedRow < len(ev.sessions) {
		ev.selected = clickedRow
		ev.adjustOffset()
	}
}

// adjustOffset ensures the selected session is visible
func (ev *EmailView) adjustOffset() {
	contentHeight := ev.height - 3
	visibleLines := contentHeight - 2
	if visibleLines < 1 {
		visibleLines = 1
	}

	if ev.selected < ev.offset {
		ev.offset = ev.selected
	}

	if ev.selected >= ev.offset+visibleLines {
		ev.offset = ev.selected - visibleLines + 1
	}

	if ev.offset < 0 {
		ev.offset = 0
	}
}

// PageUp moves up one page
func (ev *EmailView) PageUp() {
	contentHeight := ev.height - 3
	pageSize := contentHeight - 2
	if pageSize < 1 {
		pageSize = 1
	}

	ev.selected -= pageSize
	if ev.selected < 0 {
		ev.selected = 0
	}
	ev.adjustOffset()
}

// PageDown moves down one page
func (ev *EmailView) PageDown() {
	contentHeight := ev.height - 3
	pageSize := contentHeight - 2
	if pageSize < 1 {
		pageSize = 1
	}

	ev.selected += pageSize
	if ev.selected >= len(ev.sessions) {
		ev.selected = len(ev.sessions) - 1
	}
	if ev.selected < 0 {
		ev.selected = 0
	}
	ev.adjustOffset()
}

// View renders the sessions view
func (ev *EmailView) View() string {
	if len(ev.sessions) == 0 {
		return ev.renderEmpty()
	}

	return ev.RenderTable(ev.width, ev.height)
}

// RenderTable renders just the sessions table with specified width and height
func (ev *EmailView) RenderTable(width, height int) string {
	if len(ev.sessions) == 0 {
		style := lipgloss.NewStyle().
			Foreground(ev.theme.StatusBarFg).
			Italic(true).
			Width(width).
			Height(height).
			Align(lipgloss.Center, lipgloss.Center)

		return style.Render("No email sessions recorded")
	}

	return ev.renderTableWithSize(width, height)
}

// RenderDetails renders the session details panel
func (ev *EmailView) RenderDetails(width, height int) string {
	selectedSession := ev.GetSelected()
	if selectedSession == nil {
		style := lipgloss.NewStyle().
			Foreground(ev.theme.StatusBarFg).
			Italic(true).
			Width(width).
			Height(height).
			Align(lipgloss.Center, lipgloss.Center)

		return style.Render("Select a session to view details")
	}

	return ev.renderSessionDetails(selectedSession, width, height)
}

// renderEmpty shows a message when no sessions are present
func (ev *EmailView) renderEmpty() string {
	style := lipgloss.NewStyle().
		Foreground(ev.theme.StatusBarFg).
		Italic(true).
		Width(ev.width).
		Height(ev.height).
		Align(lipgloss.Center, lipgloss.Center)

	return style.Render("No email sessions recorded")
}

// renderTableWithSize shows the sessions table with specified dimensions
func (ev *EmailView) renderTableWithSize(width, height int) string {
	availableWidth := width - 6

	// Column widths
	const (
		fromMin      = 25
		toMin        = 25
		subjectMin   = 20
		msgsMin      = 5
		encryptedMin = 5
		lastSeenMin  = 12
	)

	// Calculate column widths
	fromWidth := fromMin
	toWidth := toMin
	subjectWidth := subjectMin
	msgsWidth := msgsMin
	encryptedWidth := encryptedMin
	lastSeenWidth := lastSeenMin

	fixedTotal := msgsWidth + encryptedWidth + lastSeenWidth + 6
	remaining := availableWidth - fixedTotal - fromMin - toMin - subjectMin
	if remaining > 0 {
		// Give extra space to subject column
		subjectWidth = subjectMin + remaining
	}

	// Header style
	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(ev.theme.HeaderBg).
		Reverse(true).
		Inline(true)

	rowStyle := lipgloss.NewStyle().
		Foreground(ev.theme.Foreground).
		Inline(true)

	selectedStyle := lipgloss.NewStyle().
		Foreground(ev.theme.SelectionBg).
		Reverse(true).
		Bold(true).
		Inline(true)

	// Build header
	header := fmt.Sprintf("%-*s %-*s %-*s %*s %*s %*s",
		fromWidth, truncateEmail("From", fromWidth),
		toWidth, truncateEmail("To", toWidth),
		subjectWidth, truncateEmail("Subject", subjectWidth),
		msgsWidth, "Msgs",
		encryptedWidth, "TLS",
		lastSeenWidth, "Last Seen")

	borderWidth := width - 2
	borderStyle := lipgloss.NewStyle().
		Foreground(ev.theme.BorderColor).
		Border(lipgloss.RoundedBorder()).
		Padding(1, 2).
		Width(borderWidth)

	var content strings.Builder
	content.WriteString(headerStyle.Render(header))
	content.WriteString("\n")

	// Build rows
	contentHeight := height - 3
	visibleLines := contentHeight - 2
	if visibleLines < 1 {
		visibleLines = 1
	}

	visibleStart := ev.offset
	visibleEnd := ev.offset + visibleLines
	if visibleEnd > len(ev.sessions) {
		visibleEnd = len(ev.sessions)
	}

	for i := visibleStart; i < visibleEnd; i++ {
		session := ev.sessions[i]

		// Format To (first recipient + count)
		to := "-"
		if len(session.RcptTo) > 0 {
			to = session.RcptTo[0]
			if len(session.RcptTo) > 1 {
				to = fmt.Sprintf("%s (+%d)", to, len(session.RcptTo)-1)
			}
		}

		// Format encrypted
		encrypted := " "
		if session.Encrypted {
			encrypted = "🔒"
		}

		// Format last seen
		lastSeen := session.LastSeen.Format("15:04:05")

		row := fmt.Sprintf("%-*s %-*s %-*s %*d %*s %*s",
			fromWidth, truncateEmail(session.MailFrom, fromWidth),
			toWidth, truncateEmail(to, toWidth),
			subjectWidth, truncateEmail(session.Subject, subjectWidth),
			msgsWidth, session.MessageCount,
			encryptedWidth, encrypted,
			lastSeenWidth, lastSeen)

		if i == ev.selected {
			content.WriteString(selectedStyle.Render(row))
		} else {
			// Color by encryption status
			style := rowStyle
			if !session.Encrypted && session.MessageCount > 0 {
				style = style.Foreground(ev.theme.WarningColor)
			}
			content.WriteString(style.Render(row))
		}

		if i < visibleEnd-1 {
			content.WriteString("\n")
		}
	}

	// Pad remaining space
	linesRendered := visibleEnd - visibleStart
	for i := linesRendered; i < visibleLines; i++ {
		if i > 0 || linesRendered > 0 {
			content.WriteString("\n")
		}
	}

	return borderStyle.Height(contentHeight).Render(content.String())
}

// truncateEmail truncates a string to fit width with ellipsis
func truncateEmail(s string, width int) string {
	if s == "" {
		return "-"
	}
	if len(s) <= width {
		return s
	}
	if width <= 3 {
		return s[:width]
	}
	return s[:width-3] + "..."
}

// renderSessionDetails shows session details panel
func (ev *EmailView) renderSessionDetails(session *EmailSession, width, height int) string {
	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(ev.theme.InfoColor).
		MarginBottom(1)

	sectionHeaderStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(ev.theme.SuccessColor)

	var content strings.Builder

	content.WriteString(titleStyle.Render("📧 Email Session Details"))
	content.WriteString("\n")
	content.WriteString(fmt.Sprintf("Session: %s\n", session.SessionID))
	content.WriteString(fmt.Sprintf("Last Seen: %s\n", session.LastSeen.Format("2006-01-02 15:04:05")))
	content.WriteString("\n")

	content.WriteString(sectionHeaderStyle.Render("Envelope:"))
	content.WriteString("\n")
	content.WriteString(fmt.Sprintf("  From: %s\n", session.MailFrom))
	if len(session.RcptTo) > 0 {
		content.WriteString("  To:\n")
		for _, rcpt := range session.RcptTo {
			content.WriteString(fmt.Sprintf("    - %s\n", rcpt))
		}
	}
	if session.Subject != "" {
		content.WriteString(fmt.Sprintf("  Subject: %s\n", session.Subject))
	}
	content.WriteString("\n")

	content.WriteString(sectionHeaderStyle.Render("Statistics:"))
	content.WriteString("\n")
	content.WriteString(fmt.Sprintf("  Messages: %d\n", session.MessageCount))
	content.WriteString(fmt.Sprintf("  Commands: %d\n", session.CommandCount))
	content.WriteString(fmt.Sprintf("  Responses: %d\n", session.ResponseCount))
	if session.MessageSize > 0 {
		content.WriteString(fmt.Sprintf("  Message Size: %d bytes\n", session.MessageSize))
	}
	content.WriteString("\n")

	content.WriteString(sectionHeaderStyle.Render("Security:"))
	content.WriteString("\n")
	if session.Encrypted {
		content.WriteString("  TLS: Enabled 🔒\n")
	} else {
		warningStyle := lipgloss.NewStyle().
			Foreground(ev.theme.WarningColor)
		content.WriteString(warningStyle.Render("  TLS: Not encrypted ⚠\n"))
	}
	if session.AuthMethod != "" {
		content.WriteString(fmt.Sprintf("  Auth: %s\n", session.AuthMethod))
	}
	content.WriteString("\n")

	if session.ServerBanner != "" || session.ClientHelo != "" {
		content.WriteString(sectionHeaderStyle.Render("Connection:"))
		content.WriteString("\n")
		if session.ServerBanner != "" {
			banner := session.ServerBanner
			if len(banner) > 50 {
				banner = banner[:50] + "..."
			}
			content.WriteString(fmt.Sprintf("  Server: %s\n", banner))
		}
		if session.ClientHelo != "" {
			content.WriteString(fmt.Sprintf("  Client: %s\n", session.ClientHelo))
		}
	}

	borderStyle := lipgloss.NewStyle().
		Foreground(ev.theme.BorderColor).
		Border(lipgloss.RoundedBorder()).
		Padding(1, 2).
		Width(width - 2).
		Height(height - 2)

	return borderStyle.Render(content.String())
}

// Count returns the number of tracked sessions
func (ev *EmailView) Count() int {
	return len(ev.sessions)
}

// Clear resets the email view
func (ev *EmailView) Clear() {
	ev.sessions = make([]EmailSession, 0)
	ev.sessionMap = make(map[string]*EmailSession)
	ev.selected = 0
	ev.offset = 0
}
