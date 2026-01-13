//go:build tui || all

package tui

import (
	"fmt"
	"regexp"
	"strings"
)

// ChainErrorInfo represents parsed information from a chain error
type ChainErrorInfo struct {
	IsChainError      bool
	FailedProcessorID string
	ProcessorPath     []string
	ChainDepth        int
	UnderlyingError   string
}

// parseChainError attempts to parse a chain error from an error string
// Chain error format: "chain error at <processor-id> (depth=<depth>, path=<path>): <underlying-error>"
func parseChainError(errorStr string) ChainErrorInfo {
	info := ChainErrorInfo{IsChainError: false}

	// Check if this is a chain error
	if !strings.Contains(errorStr, "chain error at") {
		return info
	}

	info.IsChainError = true

	// Extract failed processor ID
	re := regexp.MustCompile(`chain error at ([^\s]+)`)
	if matches := re.FindStringSubmatch(errorStr); len(matches) > 1 {
		info.FailedProcessorID = matches[1]
	}

	// Extract chain depth
	depthRe := regexp.MustCompile(`depth=(\d+)`)
	if matches := depthRe.FindStringSubmatch(errorStr); len(matches) > 1 {
		fmt.Sscanf(matches[1], "%d", &info.ChainDepth)
	}

	// Extract processor path
	pathRe := regexp.MustCompile(`path=([^)]+)`)
	if matches := pathRe.FindStringSubmatch(errorStr); len(matches) > 1 {
		pathStr := matches[1]
		// Split by " -> " to get processor list
		processors := strings.Split(pathStr, " -> ")
		info.ProcessorPath = processors
	}

	// Extract underlying error (after the colon following the closing paren)
	colonIdx := strings.Index(errorStr, "):")
	if colonIdx != -1 && colonIdx+2 < len(errorStr) {
		info.UnderlyingError = strings.TrimSpace(errorStr[colonIdx+2:])
	}

	return info
}

// formatChainError formats a chain error for display in the TUI
func (m Model) formatChainError(operation, filterPattern, errorStr string) string {
	info := parseChainError(errorStr)

	if !info.IsChainError {
		// Not a chain error - display simple error
		if filterPattern != "" {
			return fmt.Sprintf("%s failed for '%s': %s", operation, filterPattern, errorStr)
		}
		return fmt.Sprintf("%s failed: %s", operation, errorStr)
	}

	// Format chain error with detailed context
	var sb strings.Builder

	// Operation context
	if filterPattern != "" {
		sb.WriteString(fmt.Sprintf("%s failed for '%s'\n", operation, filterPattern))
	} else {
		sb.WriteString(fmt.Sprintf("%s failed\n", operation))
	}

	// Show which processor failed
	sb.WriteString(fmt.Sprintf("Failed at: %s", info.FailedProcessorID))
	if info.ChainDepth > 0 {
		sb.WriteString(fmt.Sprintf(" (depth %d)", info.ChainDepth))
	}
	sb.WriteString("\n")

	// Show processor path if available
	if len(info.ProcessorPath) > 0 {
		sb.WriteString(fmt.Sprintf("Path: %s\n", strings.Join(info.ProcessorPath, " → ")))
	}

	// Show underlying error
	if info.UnderlyingError != "" {
		sb.WriteString(fmt.Sprintf("Error: %s", info.UnderlyingError))
	}

	return sb.String()
}
