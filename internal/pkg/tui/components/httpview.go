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

// HTTPRequest represents an aggregated HTTP request/response pair
type HTTPRequest struct {
	RequestID    string
	Method       string
	Path         string
	Host         string
	StatusCode   int
	StatusReason string
	ContentType  string
	UserAgent    string
	Server       string
	RequestSize  int64
	ResponseSize int64
	ResponseTime int64 // RTT in milliseconds
	Timestamp    time.Time
	SrcIP        string
	DstIP        string
	SrcPort      string
	DstPort      string
	HasResponse  bool
	Headers      map[string]string
	QueryString  string
	BodyPreview  string
}

// HTTPView displays aggregated HTTP requests
type HTTPView struct {
	requests    []HTTPRequest
	requestMap  map[string]*HTTPRequest // Map from request ID to request for updates
	selected    int
	offset      int
	width       int
	height      int
	theme       themes.Theme
	showDetails bool
	autoScroll  bool // Whether to auto-scroll to top when new requests arrive
}

// NewHTTPView creates a new HTTP view
func NewHTTPView() *HTTPView {
	return &HTTPView{
		requests:    make([]HTTPRequest, 0),
		requestMap:  make(map[string]*HTTPRequest),
		selected:    0,
		offset:      0,
		showDetails: false,
		autoScroll:  true, // Auto-scroll to top by default
		theme:       themes.Solarized(),
	}
}

// SetTheme sets the color theme
func (hv *HTTPView) SetTheme(theme themes.Theme) {
	hv.theme = theme
}

// SetSize sets the dimensions
func (hv *HTTPView) SetSize(width, height int) {
	hv.width = width
	hv.height = height
}

// UpdateFromPacket updates HTTP request stats from a packet with HTTP metadata
func (hv *HTTPView) UpdateFromPacket(pkt *types.PacketDisplay) {
	if pkt.HTTPData == nil {
		return
	}

	// Create a request ID from the flow key for correlation
	// Use src:port -> dst:port for requests, reverse for responses
	var requestID string
	if pkt.HTTPData.Type == "request" {
		requestID = fmt.Sprintf("%s:%s->%s:%s", pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort)
	} else {
		// Response: reverse the flow
		requestID = fmt.Sprintf("%s:%s->%s:%s", pkt.DstIP, pkt.DstPort, pkt.SrcIP, pkt.SrcPort)
	}

	request, exists := hv.requestMap[requestID]
	if !exists && pkt.HTTPData.Type == "request" {
		// New request
		request = &HTTPRequest{
			RequestID:   requestID,
			Method:      pkt.HTTPData.Method,
			Path:        pkt.HTTPData.Path,
			Host:        pkt.HTTPData.Host,
			UserAgent:   pkt.HTTPData.UserAgent,
			ContentType: pkt.HTTPData.ContentType,
			Timestamp:   pkt.Timestamp,
			SrcIP:       pkt.SrcIP,
			DstIP:       pkt.DstIP,
			SrcPort:     pkt.SrcPort,
			DstPort:     pkt.DstPort,
			RequestSize: pkt.HTTPData.ContentLength,
			QueryString: pkt.HTTPData.QueryString,
			Headers:     pkt.HTTPData.Headers,
		}
		hv.requestMap[requestID] = request
	} else if exists && pkt.HTTPData.Type == "response" {
		// Update with response data
		request.StatusCode = pkt.HTTPData.StatusCode
		request.StatusReason = pkt.HTTPData.StatusReason
		request.ResponseSize = pkt.HTTPData.ContentLength
		request.Server = pkt.HTTPData.Server
		request.HasResponse = true
		if pkt.HTTPData.ContentType != "" {
			request.ContentType = pkt.HTTPData.ContentType
		}
		request.ResponseTime = pkt.HTTPData.RequestResponseTimeMs
		if pkt.HTTPData.BodyPreview != "" {
			request.BodyPreview = pkt.HTTPData.BodyPreview
		}
	} else if !exists && pkt.HTTPData.Type == "response" {
		// Response without request (late join or missed request)
		request = &HTTPRequest{
			RequestID:    requestID,
			StatusCode:   pkt.HTTPData.StatusCode,
			StatusReason: pkt.HTTPData.StatusReason,
			ContentType:  pkt.HTTPData.ContentType,
			Server:       pkt.HTTPData.Server,
			ResponseSize: pkt.HTTPData.ContentLength,
			Timestamp:    pkt.Timestamp,
			SrcIP:        pkt.DstIP,   // Reversed for response
			DstIP:        pkt.SrcIP,   // Reversed for response
			SrcPort:      pkt.DstPort, // Reversed for response
			DstPort:      pkt.SrcPort, // Reversed for response
			HasResponse:  true,
			BodyPreview:  pkt.HTTPData.BodyPreview,
		}
		hv.requestMap[requestID] = request
	}

	// Rebuild sorted list
	hv.rebuildRequestList()
}

// rebuildRequestList rebuilds the sorted request list from the map
func (hv *HTTPView) rebuildRequestList() {
	hv.requests = make([]HTTPRequest, 0, len(hv.requestMap))
	for _, r := range hv.requestMap {
		hv.requests = append(hv.requests, *r)
	}

	// Sort by timestamp (chronological - oldest first, newest last)
	sort.Slice(hv.requests, func(i, j int) bool {
		return hv.requests[i].Timestamp.Before(hv.requests[j].Timestamp)
	})

	// Limit to max 1000 requests to prevent memory growth
	const maxRequests = 1000
	if len(hv.requests) > maxRequests {
		// Remove oldest requests (at the beginning of the list)
		oldRequests := hv.requests[:len(hv.requests)-maxRequests]
		for _, r := range oldRequests {
			delete(hv.requestMap, r.RequestID)
		}
		hv.requests = hv.requests[len(hv.requests)-maxRequests:]
	}

	// Auto-scroll to bottom when new requests arrive (newest at bottom)
	if hv.autoScroll && len(hv.requests) > 0 {
		hv.selected = len(hv.requests) - 1
		hv.adjustOffset()
	} else if hv.selected >= len(hv.requests) && len(hv.requests) > 0 {
		// Adjust selection if needed when not auto-scrolling
		hv.selected = len(hv.requests) - 1
	}
}

// GetSelected returns the currently selected request
func (hv *HTTPView) GetSelected() *HTTPRequest {
	if hv.selected >= 0 && hv.selected < len(hv.requests) {
		return &hv.requests[hv.selected]
	}
	return nil
}

// SelectNext moves selection down
func (hv *HTTPView) SelectNext() {
	if hv.selected < len(hv.requests)-1 {
		hv.selected++
		hv.autoScroll = false // Disable auto-scroll when user navigates
		hv.adjustOffset()
	}
}

// SelectPrevious moves selection up
func (hv *HTTPView) SelectPrevious() {
	if hv.selected > 0 {
		hv.selected--
		hv.autoScroll = false // Disable auto-scroll when user navigates
		hv.adjustOffset()
	}
}

// ToggleDetails toggles the details panel
func (hv *HTTPView) ToggleDetails() {
	hv.showDetails = !hv.showDetails
}

// IsShowingDetails returns whether the details panel is visible
func (hv *HTTPView) IsShowingDetails() bool {
	return hv.showDetails
}

// Update handles messages
func (hv *HTTPView) Update(msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			hv.SelectPrevious()
		case "down", "j":
			hv.SelectNext()
		case "d":
			hv.ToggleDetails()
		case "home", "g":
			if len(hv.requests) > 0 {
				hv.selected = 0
				hv.offset = 0
				hv.autoScroll = false // Disable auto-scroll when jumping to top
			}
		case "end", "G":
			if len(hv.requests) > 0 {
				hv.selected = len(hv.requests) - 1
				hv.autoScroll = true // Re-enable auto-scroll when jumping to end (bottom)
				hv.adjustOffset()
			}
		case "pgup":
			hv.PageUp()
		case "pgdown":
			hv.PageDown()
		}
	case tea.MouseMsg:
		if msg.Type == tea.MouseLeft {
			hv.HandleMouseClick(msg.Y)
			hv.autoScroll = false // Disable auto-scroll on mouse click
		}
	}
	return nil
}

// HandleMouseClick handles mouse clicks on request rows
func (hv *HTTPView) HandleMouseClick(mouseY int) {
	headerOffset := 4
	if mouseY < headerOffset {
		return
	}

	clickedRow := mouseY - headerOffset + hv.offset
	if clickedRow >= 0 && clickedRow < len(hv.requests) {
		hv.selected = clickedRow
		hv.adjustOffset()
	}
}

// adjustOffset ensures the selected request is visible
func (hv *HTTPView) adjustOffset() {
	contentHeight := hv.height - 3
	visibleLines := contentHeight - 2
	if visibleLines < 1 {
		visibleLines = 1
	}

	if hv.selected < hv.offset {
		hv.offset = hv.selected
	}

	if hv.selected >= hv.offset+visibleLines {
		hv.offset = hv.selected - visibleLines + 1
	}

	if hv.offset < 0 {
		hv.offset = 0
	}
}

// PageUp moves up one page
func (hv *HTTPView) PageUp() {
	contentHeight := hv.height - 3
	pageSize := contentHeight - 2
	if pageSize < 1 {
		pageSize = 1
	}

	hv.selected -= pageSize
	if hv.selected < 0 {
		hv.selected = 0
	}
	hv.autoScroll = false // Disable auto-scroll when navigating up
	hv.adjustOffset()
}

// PageDown moves down one page
func (hv *HTTPView) PageDown() {
	contentHeight := hv.height - 3
	pageSize := contentHeight - 2
	if pageSize < 1 {
		pageSize = 1
	}

	hv.selected += pageSize
	if hv.selected >= len(hv.requests) {
		hv.selected = len(hv.requests) - 1
		hv.autoScroll = true // Re-enable auto-scroll when reaching bottom
	} else {
		hv.autoScroll = false // Disable auto-scroll when navigating
	}
	if hv.selected < 0 {
		hv.selected = 0
	}
	hv.adjustOffset()
}

// View renders the HTTP requests view
func (hv *HTTPView) View() string {
	if len(hv.requests) == 0 {
		return hv.renderEmpty()
	}

	return hv.RenderTable(hv.width, hv.height)
}

// RenderTable renders just the requests table with specified width and height
func (hv *HTTPView) RenderTable(width, height int) string {
	if len(hv.requests) == 0 {
		style := lipgloss.NewStyle().
			Foreground(hv.theme.StatusBarFg).
			Italic(true).
			Width(width).
			Height(height).
			Align(lipgloss.Center, lipgloss.Center)

		return style.Render("No HTTP requests recorded")
	}

	return hv.renderTableWithSize(width, height)
}

// RenderDetails renders the request details panel
func (hv *HTTPView) RenderDetails(width, height int) string {
	selectedRequest := hv.GetSelected()
	if selectedRequest == nil {
		style := lipgloss.NewStyle().
			Foreground(hv.theme.StatusBarFg).
			Italic(true).
			Width(width).
			Height(height).
			Align(lipgloss.Center, lipgloss.Center)

		return style.Render("Select a request to view details")
	}

	return hv.renderRequestDetails(selectedRequest, width, height)
}

// renderEmpty shows a message when no requests are present
func (hv *HTTPView) renderEmpty() string {
	style := lipgloss.NewStyle().
		Foreground(hv.theme.StatusBarFg).
		Italic(true).
		Width(hv.width).
		Height(hv.height).
		Align(lipgloss.Center, lipgloss.Center)

	return style.Render("No HTTP requests recorded")
}

// renderTableWithSize shows the requests table with specified dimensions
func (hv *HTTPView) renderTableWithSize(width, height int) string {
	availableWidth := width - 6

	// Column widths
	const (
		methodMin    = 7
		statusMin    = 4
		hostMin      = 25
		pathMin      = 25
		contentMin   = 15
		respTimeMin  = 6
		timestampMin = 10
	)

	// Calculate column widths
	methodWidth := methodMin
	statusWidth := statusMin
	hostWidth := hostMin
	pathWidth := pathMin
	contentWidth := contentMin
	respTimeWidth := respTimeMin
	timestampWidth := timestampMin

	fixedTotal := methodWidth + statusWidth + respTimeWidth + timestampWidth + 8
	remaining := availableWidth - fixedTotal - hostMin - pathMin - contentMin
	if remaining > 0 {
		// Split extra space between host and path columns
		hostWidth = hostMin + remaining/2
		pathWidth = pathMin + remaining - remaining/2
	}

	// Header style
	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(hv.theme.HeaderBg).
		Reverse(true).
		Inline(true)

	rowStyle := lipgloss.NewStyle().
		Foreground(hv.theme.Foreground).
		Inline(true)

	selectedStyle := lipgloss.NewStyle().
		Foreground(hv.theme.SelectionBg).
		Reverse(true).
		Bold(true).
		Inline(true)

	// Build header
	header := fmt.Sprintf("%-*s %*s %-*s %-*s %-*s %*s %*s",
		methodWidth, truncateHTTP("Method", methodWidth),
		statusWidth, "Code",
		hostWidth, truncateHTTP("Host", hostWidth),
		pathWidth, truncateHTTP("Path", pathWidth),
		contentWidth, truncateHTTP("Content-Type", contentWidth),
		respTimeWidth, "RTT",
		timestampWidth, "Time")

	borderWidth := width - 2
	borderStyle := lipgloss.NewStyle().
		Foreground(hv.theme.BorderColor).
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

	visibleStart := hv.offset
	visibleEnd := hv.offset + visibleLines
	if visibleEnd > len(hv.requests) {
		visibleEnd = len(hv.requests)
	}

	for i := visibleStart; i < visibleEnd; i++ {
		req := hv.requests[i]

		// Format method
		method := req.Method
		if method == "" {
			method = "???"
		}

		// Format status code
		statusStr := "-"
		if req.HasResponse {
			statusStr = fmt.Sprintf("%d", req.StatusCode)
		}

		// Format response time
		respTime := "-"
		if req.ResponseTime > 0 {
			respTime = fmt.Sprintf("%dms", req.ResponseTime)
		}

		// Format timestamp
		timestamp := req.Timestamp.Format("15:04:05")

		// Format content type (simplified)
		contentType := req.ContentType
		if idx := strings.Index(contentType, ";"); idx > 0 {
			contentType = contentType[:idx]
		}

		row := fmt.Sprintf("%-*s %*s %-*s %-*s %-*s %*s %*s",
			methodWidth, truncateHTTP(method, methodWidth),
			statusWidth, statusStr,
			hostWidth, truncateHTTP(req.Host, hostWidth),
			pathWidth, truncateHTTP(req.Path, pathWidth),
			contentWidth, truncateHTTP(contentType, contentWidth),
			respTimeWidth, respTime,
			timestampWidth, timestamp)

		if i == hv.selected {
			content.WriteString(selectedStyle.Render(row))
		} else {
			// Color by status code
			style := rowStyle
			if req.HasResponse {
				if req.StatusCode >= 500 {
					style = style.Foreground(hv.theme.ErrorColor)
				} else if req.StatusCode >= 400 {
					style = style.Foreground(hv.theme.WarningColor)
				} else if req.StatusCode >= 200 && req.StatusCode < 300 {
					style = style.Foreground(hv.theme.SuccessColor)
				}
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

// truncateHTTP truncates a string to fit width with ellipsis
func truncateHTTP(s string, width int) string {
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

// renderRequestDetails shows request details panel
func (hv *HTTPView) renderRequestDetails(req *HTTPRequest, width, height int) string {
	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(hv.theme.InfoColor).
		MarginBottom(1)

	sectionHeaderStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(hv.theme.SuccessColor)

	var content strings.Builder

	content.WriteString(titleStyle.Render("HTTP Request Details"))
	content.WriteString("\n")
	content.WriteString(fmt.Sprintf("Time: %s\n", req.Timestamp.Format("2006-01-02 15:04:05.000")))
	content.WriteString("\n")

	content.WriteString(sectionHeaderStyle.Render("Request:"))
	content.WriteString("\n")
	if req.Method != "" {
		content.WriteString(fmt.Sprintf("  %s %s\n", req.Method, req.Path))
	}
	if req.Host != "" {
		content.WriteString(fmt.Sprintf("  Host: %s\n", req.Host))
	}
	if req.UserAgent != "" {
		ua := req.UserAgent
		if len(ua) > 60 {
			ua = ua[:60] + "..."
		}
		content.WriteString(fmt.Sprintf("  User-Agent: %s\n", ua))
	}
	if req.QueryString != "" {
		qs := req.QueryString
		if len(qs) > 60 {
			qs = qs[:60] + "..."
		}
		content.WriteString(fmt.Sprintf("  Query: %s\n", qs))
	}
	content.WriteString("\n")

	content.WriteString(sectionHeaderStyle.Render("Response:"))
	content.WriteString("\n")
	if req.HasResponse {
		// Color status code
		statusStyle := lipgloss.NewStyle()
		if req.StatusCode >= 500 {
			statusStyle = statusStyle.Foreground(hv.theme.ErrorColor)
		} else if req.StatusCode >= 400 {
			statusStyle = statusStyle.Foreground(hv.theme.WarningColor)
		} else if req.StatusCode >= 200 && req.StatusCode < 300 {
			statusStyle = statusStyle.Foreground(hv.theme.SuccessColor)
		}
		statusText := fmt.Sprintf("  Status: %d %s\n", req.StatusCode, req.StatusReason)
		content.WriteString(statusStyle.Render(statusText))
		if req.ContentType != "" {
			content.WriteString(fmt.Sprintf("  Content-Type: %s\n", req.ContentType))
		}
		if req.Server != "" {
			content.WriteString(fmt.Sprintf("  Server: %s\n", req.Server))
		}
		if req.ResponseTime > 0 {
			content.WriteString(fmt.Sprintf("  Response Time: %dms\n", req.ResponseTime))
		}
	} else {
		content.WriteString("  (awaiting response)\n")
	}
	content.WriteString("\n")

	content.WriteString(sectionHeaderStyle.Render("Connection:"))
	content.WriteString("\n")
	content.WriteString(fmt.Sprintf("  %s:%s -> %s:%s\n", req.SrcIP, req.SrcPort, req.DstIP, req.DstPort))
	if req.RequestSize > 0 || req.ResponseSize > 0 {
		content.WriteString(fmt.Sprintf("  Request Size: %d bytes\n", req.RequestSize))
		content.WriteString(fmt.Sprintf("  Response Size: %d bytes\n", req.ResponseSize))
	}

	// Show body preview if available
	if req.BodyPreview != "" {
		content.WriteString("\n")
		content.WriteString(sectionHeaderStyle.Render("Body Preview:"))
		content.WriteString("\n")
		preview := req.BodyPreview
		if len(preview) > 200 {
			preview = preview[:200] + "..."
		}
		// Limit to single lines for display
		lines := strings.Split(preview, "\n")
		for i, line := range lines {
			if i >= 5 {
				content.WriteString("  ...\n")
				break
			}
			if len(line) > 60 {
				line = line[:60] + "..."
			}
			content.WriteString(fmt.Sprintf("  %s\n", line))
		}
	}

	borderStyle := lipgloss.NewStyle().
		Foreground(hv.theme.BorderColor).
		Border(lipgloss.RoundedBorder()).
		Padding(1, 2).
		Width(width - 2).
		Height(height - 2)

	return borderStyle.Render(content.String())
}

// Count returns the number of tracked requests
func (hv *HTTPView) Count() int {
	return len(hv.requests)
}

// Clear resets the HTTP view
func (hv *HTTPView) Clear() {
	hv.requests = make([]HTTPRequest, 0)
	hv.requestMap = make(map[string]*HTTPRequest)
	hv.selected = 0
	hv.offset = 0
	hv.autoScroll = true // Re-enable auto-scroll on clear
}
