//go:build tui || all

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

// DNSQuery represents aggregated DNS query statistics for a domain
type DNSQuery struct {
	Domain            string
	QueryCount        int64
	ResponseCount     int64
	NXDomainCount     int64
	ServerFailCount   int64
	AvgResponseTimeMs int64
	UniqueClients     int
	RecordTypes       map[string]int64
	TunnelingScore    float64
	LastSeen          time.Time
}

// pendingDNSQuery tracks a DNS query awaiting response for RTT correlation
type pendingDNSQuery struct {
	domain    string
	timestamp time.Time
}

// orphanDNSResponse tracks a DNS response that arrived before its query
type orphanDNSResponse struct {
	domain    string
	timestamp time.Time
}

// DNSQueriesView displays aggregated DNS queries
type DNSQueriesView struct {
	queries     []DNSQuery
	queryMap    map[string]*DNSQuery // Map from domain to query for updates
	selected    int
	offset      int
	width       int
	height      int
	theme       themes.Theme
	showDetails bool

	// DNS query correlation for RTT calculation
	// Key: transaction ID (uint16), Value: pending query info
	pendingQueries map[uint16]pendingDNSQuery

	// Orphan responses (arrived before their queries) for bidirectional correlation
	// Key: transaction ID (uint16), Value: orphan response info
	orphanResponses map[uint16]orphanDNSResponse
}

// NewDNSQueriesView creates a new DNS queries view
func NewDNSQueriesView() *DNSQueriesView {
	return &DNSQueriesView{
		queries:         make([]DNSQuery, 0),
		queryMap:        make(map[string]*DNSQuery),
		pendingQueries:  make(map[uint16]pendingDNSQuery),
		orphanResponses: make(map[uint16]orphanDNSResponse),
		selected:        0,
		offset:          0,
		showDetails:     false,
		theme:           themes.Solarized(),
	}
}

// SetTheme sets the color theme
func (dv *DNSQueriesView) SetTheme(theme themes.Theme) {
	dv.theme = theme
}

// SetSize sets the dimensions
func (dv *DNSQueriesView) SetSize(width, height int) {
	dv.width = width
	dv.height = height
}

// UpdateFromPacket updates DNS query stats from a packet with DNS metadata
func (dv *DNSQueriesView) UpdateFromPacket(pkt *types.PacketDisplay) {
	if pkt.DNSData == nil || pkt.DNSData.QueryName == "" {
		return
	}

	// Normalize domain name for consistent lookups:
	// - Convert to lowercase (DNS is case-insensitive)
	// - Remove trailing dot (FQDN vs relative name)
	domain := normalizeDomain(pkt.DNSData.QueryName)
	if domain == "" {
		return
	}

	query, exists := dv.queryMap[domain]
	if !exists {
		query = &DNSQuery{
			Domain:      domain,
			RecordTypes: make(map[string]int64),
		}
		dv.queryMap[domain] = query
	}

	txID := pkt.DNSData.TransactionID

	if pkt.DNSData.IsResponse {
		query.ResponseCount++

		// Try to get RTT from multiple sources:
		// 1. Pre-calculated by processor (CorrelatedQuery + QueryResponseTimeMs)
		// 2. Our own correlation from pendingQueries
		// 3. Store as orphan for later correlation if query arrives after response
		var rttMs int64

		if pkt.DNSData.CorrelatedQuery && pkt.DNSData.QueryResponseTimeMs > 0 {
			// Use pre-calculated RTT from processor/CLI
			rttMs = pkt.DNSData.QueryResponseTimeMs
		} else if pending, ok := dv.pendingQueries[txID]; ok {
			// Calculate RTT from stored query timestamp
			rttMs = pkt.Timestamp.Sub(pending.timestamp).Milliseconds()
			// Remove from pending (response received)
			delete(dv.pendingQueries, txID)
		} else {
			// Response arrived before query - store as orphan for later correlation
			dv.orphanResponses[txID] = orphanDNSResponse{
				domain:    domain,
				timestamp: pkt.Timestamp,
			}
		}

		// Update average RTT if we have a valid value
		if rttMs > 0 && rttMs < 30000 { // Sanity check: RTT should be < 30s
			dv.updateAverageRTT(query, rttMs)
		}

		switch pkt.DNSData.ResponseCode {
		case "NXDOMAIN":
			query.NXDomainCount++
		case "SERVFAIL":
			query.ServerFailCount++
		}
	} else {
		query.QueryCount++

		// Check for orphan response (response arrived before this query)
		if orphan, ok := dv.orphanResponses[txID]; ok {
			// Calculate RTT: response_time - query_time
			// The capture timestamps should be correct, so RTT = response_ts - query_ts
			rttMs := orphan.timestamp.Sub(pkt.Timestamp).Milliseconds()
			if rttMs > 0 && rttMs < 30000 {
				dv.updateAverageRTT(query, rttMs)
			}
			delete(dv.orphanResponses, txID)
		} else {
			// Store query for RTT correlation when response arrives
			dv.pendingQueries[txID] = pendingDNSQuery{
				domain:    domain,
				timestamp: pkt.Timestamp,
			}
		}

		// Cleanup stale entries (older than 10 seconds)
		// Do this occasionally to prevent memory growth
		if len(dv.pendingQueries) > 100 || len(dv.orphanResponses) > 100 {
			dv.cleanupStalePendingQueries(pkt.Timestamp)
			dv.cleanupStaleOrphanResponses(pkt.Timestamp)
		}
	}

	// Normalize query type - gopacket returns "Unknown" for unrecognized types
	queryType := pkt.DNSData.QueryType
	if queryType != "" && queryType != "Unknown" {
		query.RecordTypes[queryType]++
	}

	if pkt.DNSData.TunnelingScore > query.TunnelingScore {
		query.TunnelingScore = pkt.DNSData.TunnelingScore
	}

	query.LastSeen = pkt.Timestamp

	// Rebuild sorted list
	dv.rebuildQueryList()
}

// rebuildQueryList rebuilds the sorted query list from the map
func (dv *DNSQueriesView) rebuildQueryList() {
	dv.queries = make([]DNSQuery, 0, len(dv.queryMap))
	for _, q := range dv.queryMap {
		dv.queries = append(dv.queries, *q)
	}

	// Sort by query count (descending)
	sort.Slice(dv.queries, func(i, j int) bool {
		return dv.queries[i].QueryCount > dv.queries[j].QueryCount
	})

	// Adjust selection if needed
	if dv.selected >= len(dv.queries) && len(dv.queries) > 0 {
		dv.selected = len(dv.queries) - 1
	}
}

// updateAverageRTT updates the average RTT for a domain query
func (dv *DNSQueriesView) updateAverageRTT(query *DNSQuery, rttMs int64) {
	totalResponses := query.ResponseCount
	if totalResponses <= 1 {
		query.AvgResponseTimeMs = rttMs
	} else {
		// Incremental average: new_avg = old_avg + (new_value - old_avg) / n
		query.AvgResponseTimeMs = query.AvgResponseTimeMs + (rttMs-query.AvgResponseTimeMs)/totalResponses
	}
}

// cleanupStalePendingQueries removes DNS queries older than 10 seconds
// to prevent memory growth from unanswered queries
func (dv *DNSQueriesView) cleanupStalePendingQueries(now time.Time) {
	const maxAge = 10 * time.Second
	for txID, pending := range dv.pendingQueries {
		if now.Sub(pending.timestamp) > maxAge {
			delete(dv.pendingQueries, txID)
		}
	}
}

// cleanupStaleOrphanResponses removes orphan responses older than 10 seconds
func (dv *DNSQueriesView) cleanupStaleOrphanResponses(now time.Time) {
	const maxAge = 10 * time.Second
	for txID, orphan := range dv.orphanResponses {
		if now.Sub(orphan.timestamp) > maxAge {
			delete(dv.orphanResponses, txID)
		}
	}
}

// GetSelected returns the currently selected query
func (dv *DNSQueriesView) GetSelected() *DNSQuery {
	if dv.selected >= 0 && dv.selected < len(dv.queries) {
		return &dv.queries[dv.selected]
	}
	return nil
}

// SelectNext moves selection down
func (dv *DNSQueriesView) SelectNext() {
	if dv.selected < len(dv.queries)-1 {
		dv.selected++
		dv.adjustOffset()
	}
}

// SelectPrevious moves selection up
func (dv *DNSQueriesView) SelectPrevious() {
	if dv.selected > 0 {
		dv.selected--
		dv.adjustOffset()
	}
}

// ToggleDetails toggles the details panel
func (dv *DNSQueriesView) ToggleDetails() {
	dv.showDetails = !dv.showDetails
}

// IsShowingDetails returns whether the details panel is visible
func (dv *DNSQueriesView) IsShowingDetails() bool {
	return dv.showDetails
}

// Update handles messages
func (dv *DNSQueriesView) Update(msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			dv.SelectPrevious()
		case "down", "j":
			dv.SelectNext()
		case "d":
			dv.ToggleDetails()
		case "home", "g":
			if len(dv.queries) > 0 {
				dv.selected = 0
				dv.offset = 0
			}
		case "end", "G":
			if len(dv.queries) > 0 {
				dv.selected = len(dv.queries) - 1
				dv.adjustOffset()
			}
		case "pgup":
			dv.PageUp()
		case "pgdown":
			dv.PageDown()
		}
	case tea.MouseMsg:
		if msg.Type == tea.MouseLeft {
			dv.HandleMouseClick(msg.Y)
		}
	}
	return nil
}

// HandleMouseClick handles mouse clicks on query rows
func (dv *DNSQueriesView) HandleMouseClick(mouseY int) {
	headerOffset := 4
	if mouseY < headerOffset {
		return
	}

	clickedRow := mouseY - headerOffset + dv.offset
	if clickedRow >= 0 && clickedRow < len(dv.queries) {
		dv.selected = clickedRow
		dv.adjustOffset()
	}
}

// adjustOffset ensures the selected query is visible
func (dv *DNSQueriesView) adjustOffset() {
	contentHeight := dv.height - 3
	visibleLines := contentHeight - 2
	if visibleLines < 1 {
		visibleLines = 1
	}

	if dv.selected < dv.offset {
		dv.offset = dv.selected
	}

	if dv.selected >= dv.offset+visibleLines {
		dv.offset = dv.selected - visibleLines + 1
	}

	if dv.offset < 0 {
		dv.offset = 0
	}
}

// PageUp moves up one page
func (dv *DNSQueriesView) PageUp() {
	contentHeight := dv.height - 3
	pageSize := contentHeight - 2
	if pageSize < 1 {
		pageSize = 1
	}

	dv.selected -= pageSize
	if dv.selected < 0 {
		dv.selected = 0
	}
	dv.adjustOffset()
}

// PageDown moves down one page
func (dv *DNSQueriesView) PageDown() {
	contentHeight := dv.height - 3
	pageSize := contentHeight - 2
	if pageSize < 1 {
		pageSize = 1
	}

	dv.selected += pageSize
	if dv.selected >= len(dv.queries) {
		dv.selected = len(dv.queries) - 1
	}
	if dv.selected < 0 {
		dv.selected = 0
	}
	dv.adjustOffset()
}

// View renders the queries view
func (dv *DNSQueriesView) View() string {
	if len(dv.queries) == 0 {
		return dv.renderEmpty()
	}

	return dv.RenderTable(dv.width, dv.height)
}

// RenderTable renders just the queries table with specified width and height
func (dv *DNSQueriesView) RenderTable(width, height int) string {
	if len(dv.queries) == 0 {
		style := lipgloss.NewStyle().
			Foreground(dv.theme.StatusBarFg).
			Italic(true).
			Width(width).
			Height(height).
			Align(lipgloss.Center, lipgloss.Center)

		return style.Render("No DNS queries recorded")
	}

	return dv.renderTableWithSize(width, height)
}

// RenderDetails renders the query details panel
func (dv *DNSQueriesView) RenderDetails(width, height int) string {
	selectedQuery := dv.GetSelected()
	if selectedQuery == nil {
		style := lipgloss.NewStyle().
			Foreground(dv.theme.StatusBarFg).
			Italic(true).
			Width(width).
			Height(height).
			Align(lipgloss.Center, lipgloss.Center)

		return style.Render("Select a query to view details")
	}

	return dv.renderQueryDetails(selectedQuery, width, height)
}

// renderEmpty shows a message when no queries are present
func (dv *DNSQueriesView) renderEmpty() string {
	style := lipgloss.NewStyle().
		Foreground(dv.theme.StatusBarFg).
		Italic(true).
		Width(dv.width).
		Height(dv.height).
		Align(lipgloss.Center, lipgloss.Center)

	return style.Render("No DNS queries recorded")
}

// renderTableWithSize shows the queries table with specified dimensions
func (dv *DNSQueriesView) renderTableWithSize(width, height int) string {
	availableWidth := width - 6

	// Column widths
	const (
		domainMin    = 30
		queriesMin   = 8
		responsesMin = 10
		nxdomainMin  = 9
		rttMin       = 8
		typesMin     = 15
		scoreMin     = 8
	)

	// Calculate column widths
	domainWidth := domainMin
	queriesWidth := queriesMin
	responsesWidth := responsesMin
	nxdomainWidth := nxdomainMin
	rttWidth := rttMin
	typesWidth := typesMin
	scoreWidth := scoreMin

	fixedTotal := queriesWidth + responsesWidth + nxdomainWidth + rttWidth + typesWidth + scoreWidth + 6
	remaining := availableWidth - fixedTotal - domainMin
	if remaining > 0 {
		// Give extra space to domain column
		domainWidth = domainMin + remaining
	}

	// Header style
	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(dv.theme.HeaderBg).
		Reverse(true).
		Inline(true)

	rowStyle := lipgloss.NewStyle().
		Foreground(dv.theme.Foreground).
		Inline(true)

	selectedStyle := lipgloss.NewStyle().
		Foreground(dv.theme.SelectionBg).
		Reverse(true).
		Bold(true).
		Inline(true)

	// Build header
	header := fmt.Sprintf("%-*s %*s %*s %*s %*s %-*s %*s",
		domainWidth, truncateDNS("Domain", domainWidth),
		queriesWidth, "Queries",
		responsesWidth, "Responses",
		nxdomainWidth, "NXDOMAIN",
		rttWidth, "Avg RTT",
		typesWidth, truncateDNS("Types", typesWidth),
		scoreWidth, "Tunnel")

	borderWidth := width - 2
	borderStyle := lipgloss.NewStyle().
		Foreground(dv.theme.BorderColor).
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

	visibleStart := dv.offset
	if visibleStart > len(dv.queries) {
		visibleStart = len(dv.queries)
	}
	visibleEnd := visibleStart + visibleLines
	if visibleEnd > len(dv.queries) {
		visibleEnd = len(dv.queries)
	}

	for i := visibleStart; i < visibleEnd; i++ {
		query := dv.queries[i]

		// Format RTT
		rtt := "N/A"
		if query.AvgResponseTimeMs > 0 {
			rtt = fmt.Sprintf("%dms", query.AvgResponseTimeMs)
		}

		// Format record types (top 3)
		types := formatRecordTypes(query.RecordTypes)

		// Format tunneling score
		tunnelScore := ""
		if query.TunnelingScore > 0.3 {
			tunnelScore = fmt.Sprintf("%.0f%%", query.TunnelingScore*100)
		}

		row := fmt.Sprintf("%-*s %*d %*d %*d %*s %-*s %*s",
			domainWidth, truncateDNS(query.Domain, domainWidth),
			queriesWidth, query.QueryCount,
			responsesWidth, query.ResponseCount,
			nxdomainWidth, query.NXDomainCount,
			rttWidth, rtt,
			typesWidth, truncateDNS(types, typesWidth),
			scoreWidth, tunnelScore)

		if i == dv.selected {
			content.WriteString(selectedStyle.Render(row))
		} else {
			// Color by tunneling score
			style := rowStyle
			if query.TunnelingScore > 0.7 {
				style = style.Foreground(dv.theme.ErrorColor)
			} else if query.TunnelingScore > 0.5 {
				style = style.Foreground(dv.theme.WarningColor)
			} else if query.NXDomainCount > query.QueryCount/2 && query.QueryCount > 0 {
				style = style.Foreground(dv.theme.WarningColor)
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

// formatRecordTypes formats record types as comma-separated list
func formatRecordTypes(types map[string]int64) string {
	if len(types) == 0 {
		return "-"
	}

	// Sort by count
	type typeCount struct {
		name  string
		count int64
	}
	var sorted []typeCount
	for name, count := range types {
		// Skip empty or unknown types
		if name == "" || name == "Unknown" {
			continue
		}
		sorted = append(sorted, typeCount{name, count})
	}

	if len(sorted) == 0 {
		return "-"
	}

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].count > sorted[j].count
	})

	// Take top 3
	var result []string
	for i, tc := range sorted {
		if i >= 3 {
			break
		}
		result = append(result, tc.name)
	}

	return strings.Join(result, ",")
}

// truncateDNS truncates a string to fit width with ellipsis
func truncateDNS(s string, width int) string {
	if len(s) <= width {
		return s
	}
	if width <= 3 {
		return s[:width]
	}
	return s[:width-3] + "..."
}

// normalizeDomain normalizes a DNS domain name for consistent lookups
// - Converts to lowercase (DNS is case-insensitive per RFC 1035)
// - Removes trailing dot (FQDN indicator)
// - Trims whitespace
func normalizeDomain(domain string) string {
	// Trim whitespace
	domain = strings.TrimSpace(domain)

	// Remove trailing dot (FQDN indicator)
	domain = strings.TrimSuffix(domain, ".")

	// Convert to lowercase (DNS is case-insensitive)
	domain = strings.ToLower(domain)

	return domain
}

// renderQueryDetails shows query details panel
func (dv *DNSQueriesView) renderQueryDetails(query *DNSQuery, width, height int) string {
	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(dv.theme.InfoColor).
		MarginBottom(1)

	sectionHeaderStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(dv.theme.SuccessColor)

	var content strings.Builder

	content.WriteString(titleStyle.Render("🔍 DNS Query Details"))
	content.WriteString("\n")
	content.WriteString(fmt.Sprintf("Domain: %s\n", query.Domain))
	content.WriteString(fmt.Sprintf("Last Seen: %s\n", query.LastSeen.Format("2006-01-02 15:04:05")))
	content.WriteString("\n")

	content.WriteString(sectionHeaderStyle.Render("Statistics:"))
	content.WriteString("\n")
	content.WriteString(fmt.Sprintf("  Total Queries: %d\n", query.QueryCount))
	content.WriteString(fmt.Sprintf("  Total Responses: %d\n", query.ResponseCount))
	if query.AvgResponseTimeMs > 0 {
		content.WriteString(fmt.Sprintf("  Avg Response Time: %dms\n", query.AvgResponseTimeMs))
	}
	content.WriteString("\n")

	content.WriteString(sectionHeaderStyle.Render("Response Codes:"))
	content.WriteString("\n")
	successCount := query.ResponseCount - query.NXDomainCount - query.ServerFailCount
	content.WriteString(fmt.Sprintf("  NOERROR: %d\n", successCount))
	content.WriteString(fmt.Sprintf("  NXDOMAIN: %d\n", query.NXDomainCount))
	content.WriteString(fmt.Sprintf("  SERVFAIL: %d\n", query.ServerFailCount))
	content.WriteString("\n")

	content.WriteString(sectionHeaderStyle.Render("Record Types:"))
	content.WriteString("\n")
	for rtype, count := range query.RecordTypes {
		content.WriteString(fmt.Sprintf("  %s: %d\n", rtype, count))
	}

	if query.TunnelingScore > 0.3 {
		content.WriteString("\n")
		warningStyle := lipgloss.NewStyle().
			Foreground(dv.theme.WarningColor).
			Bold(true)
		content.WriteString(warningStyle.Render(fmt.Sprintf("⚠️  Tunneling Score: %.0f%%", query.TunnelingScore*100)))
		content.WriteString("\n")
		if query.TunnelingScore > 0.7 {
			content.WriteString("High probability of DNS tunneling detected.\n")
		} else if query.TunnelingScore > 0.5 {
			content.WriteString("Moderate tunneling indicators detected.\n")
		} else {
			content.WriteString("Low tunneling indicators detected.\n")
		}
	}

	borderStyle := lipgloss.NewStyle().
		Foreground(dv.theme.BorderColor).
		Border(lipgloss.RoundedBorder()).
		Padding(1, 2).
		Width(width - 2).
		Height(height - 2)

	return borderStyle.Render(content.String())
}

// Count returns the number of tracked domains
func (dv *DNSQueriesView) Count() int {
	return len(dv.queries)
}

// Clear resets the queries view
func (dv *DNSQueriesView) Clear() {
	dv.queries = make([]DNSQuery, 0)
	dv.queryMap = make(map[string]*DNSQuery)
	dv.pendingQueries = make(map[uint16]pendingDNSQuery)
	dv.orphanResponses = make(map[uint16]orphanDNSResponse)
	dv.selected = 0
	dv.offset = 0
}
