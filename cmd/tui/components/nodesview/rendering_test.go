//go:build tui || all
// +build tui all

package nodesview

import (
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
)

func TestTruncateString_ShorterThanMax(t *testing.T) {
	result := TruncateString("hello", 10)
	if result != "hello" {
		t.Errorf("Expected 'hello', got '%s'", result)
	}
}

func TestTruncateString_ExactlyMax(t *testing.T) {
	result := TruncateString("hello", 5)
	if result != "hello" {
		t.Errorf("Expected 'hello', got '%s'", result)
	}
}

func TestTruncateString_LongerThanMax(t *testing.T) {
	result := TruncateString("hello world", 8)
	if result != "hello..." {
		t.Errorf("Expected 'hello...', got '%s'", result)
	}
}

func TestTruncateString_VeryShortMax(t *testing.T) {
	result := TruncateString("hello", 3)
	if result != "hel" {
		t.Errorf("Expected 'hel', got '%s'", result)
	}
}

func TestTruncateString_MaxTooSmallForEllipsis(t *testing.T) {
	result := TruncateString("hello", 2)
	if result != "he" {
		t.Errorf("Expected 'he', got '%s'", result)
	}
}

func TestFormatPacketNumber_Zero(t *testing.T) {
	result := FormatPacketNumber(0)
	if result != "0" {
		t.Errorf("Expected '0', got '%s'", result)
	}
}

func TestFormatPacketNumber_Hundreds(t *testing.T) {
	result := FormatPacketNumber(500)
	if result != "500" {
		t.Errorf("Expected '500', got '%s'", result)
	}
}

func TestFormatPacketNumber_Thousands(t *testing.T) {
	result := FormatPacketNumber(1500)
	if result != "1.5K" {
		t.Errorf("Expected '1.5K', got '%s'", result)
	}
}

func TestFormatPacketNumber_Millions(t *testing.T) {
	result := FormatPacketNumber(2500000)
	if result != "2.5M" {
		t.Errorf("Expected '2.5M', got '%s'", result)
	}
}

func TestFormatPacketNumber_Billions(t *testing.T) {
	result := FormatPacketNumber(3500000000)
	if result != "3.5G" {
		t.Errorf("Expected '3.5G', got '%s'", result)
	}
}

func TestFormatPacketNumber_ExactThousand(t *testing.T) {
	result := FormatPacketNumber(1000)
	if result != "1.0K" {
		t.Errorf("Expected '1.0K', got '%s'", result)
	}
}

func TestFormatDuration_Seconds(t *testing.T) {
	// 45 seconds in nanoseconds
	result := FormatDuration(45 * 1000000000)
	if result != "45s" {
		t.Errorf("Expected '45s', got '%s'", result)
	}
}

func TestFormatDuration_Minutes(t *testing.T) {
	// 5 minutes 30 seconds in nanoseconds
	result := FormatDuration(330 * 1000000000)
	if result != "5m30s" {
		t.Errorf("Expected '5m30s', got '%s'", result)
	}
}

func TestFormatDuration_Hours(t *testing.T) {
	// 2 hours 15 minutes in nanoseconds
	result := FormatDuration(8100 * 1000000000)
	if result != "2h15m" {
		t.Errorf("Expected '2h15m', got '%s'", result)
	}
}

func TestFormatDuration_ZeroSeconds(t *testing.T) {
	result := FormatDuration(0)
	if result != "0s" {
		t.Errorf("Expected '0s', got '%s'", result)
	}
}

func TestFormatDuration_ExactMinute(t *testing.T) {
	// Exactly 1 minute in nanoseconds
	result := FormatDuration(60 * 1000000000)
	if result != "1m0s" {
		t.Errorf("Expected '1m0s', got '%s'", result)
	}
}

func TestFormatDuration_ExactHour(t *testing.T) {
	// Exactly 1 hour in nanoseconds
	result := FormatDuration(3600 * 1000000000)
	if result != "1h0m" {
		t.Errorf("Expected '1h0m', got '%s'", result)
	}
}

func TestRenderBox_BasicContent(t *testing.T) {
	lines := []string{"Hello", "World"}
	style := lipgloss.NewStyle()
	result := RenderBox(lines, 20, style)

	// Check that it contains box drawing characters
	if !strings.Contains(result, "╭") {
		t.Error("Expected top-left corner '╭'")
	}
	if !strings.Contains(result, "╮") {
		t.Error("Expected top-right corner '╮'")
	}
	if !strings.Contains(result, "╰") {
		t.Error("Expected bottom-left corner '╰'")
	}
	if !strings.Contains(result, "╯") {
		t.Error("Expected bottom-right corner '╯'")
	}
	if !strings.Contains(result, "Hello") {
		t.Error("Expected content 'Hello'")
	}
	if !strings.Contains(result, "World") {
		t.Error("Expected content 'World'")
	}
}

func TestRenderBox_EmptyLines(t *testing.T) {
	lines := []string{}
	style := lipgloss.NewStyle()
	result := RenderBox(lines, 20, style)

	// Should still render a box (just empty)
	if !strings.Contains(result, "╭") || !strings.Contains(result, "╯") {
		t.Error("Expected box to render even with empty content")
	}
}

func TestColumnWidthCalculator_SufficientSpace(t *testing.T) {
	calc := ColumnWidthCalculator{Width: 100}
	id, host, status, _, _, _, _ := calc.GetColumnWidths()

	// With sufficient space, should use preferred widths
	if id != 15 {
		t.Errorf("Expected id column 15, got %d", id)
	}
	if host != 20 {
		t.Errorf("Expected host column 20, got %d", host)
	}
	if status != 8 {
		t.Errorf("Expected status column 8, got %d", status)
	}
}

func TestColumnWidthCalculator_InsufficientSpace(t *testing.T) {
	calc := ColumnWidthCalculator{Width: 50}
	id, host, status, uptime, captured, forwarded, filters := calc.GetColumnWidths()

	// With insufficient space, should use minimum widths
	if id < 8 {
		t.Errorf("Expected id column >= 8, got %d", id)
	}
	if host < 8 {
		t.Errorf("Expected host column >= 8, got %d", host)
	}
	if status < 7 {
		t.Errorf("Expected status column >= 7, got %d", status)
	}

	// Verify all values are returned
	if uptime < 0 || captured < 0 || forwarded < 0 || filters < 0 {
		t.Error("Expected all column widths to be non-negative")
	}
}

func TestColumnWidthCalculator_VeryNarrow(t *testing.T) {
	calc := ColumnWidthCalculator{Width: 20}
	id, host, status, uptime, captured, forwarded, filters := calc.GetColumnWidths()

	// Even with very narrow width, should return minimum widths
	totalWidth := id + host + status + uptime + captured + forwarded + filters
	if totalWidth <= 0 {
		t.Error("Expected positive total width even in narrow space")
	}
}
