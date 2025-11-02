//go:build tui || all
// +build tui all

package tui

import (
	"fmt"
	"path/filepath"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/cmd/tui/components"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/pcap"
	"github.com/google/gopacket/layers"
)

// determineSaveMode returns the save mode (oneshot or streaming)
func (m *Model) determineSaveMode() string {
	if m.captureMode == components.CaptureModeOffline {
		return "oneshot"
	}
	if m.uiState.IsPaused() {
		return "oneshot"
	}
	return "streaming"
}

// proceedWithSave starts the save operation for the given file path
func (m *Model) proceedWithSave(filePath string) tea.Cmd {
	// Determine save mode and start save
	mode := m.determineSaveMode()

	if mode == "oneshot" {
		// One-shot save (offline or paused)
		m.uiState.SaveInProgress = true
		// Show info toast
		toastCmd := m.uiState.Toast.Show(
			"Saving packets...",
			components.ToastInfo,
			0, // Will be replaced when complete
		)
		// Start save
		saveCmd := m.startOneShotSave(filePath)
		return tea.Batch(toastCmd, saveCmd)
	} else {
		// Streaming save (live/remote)
		return m.startStreamingSave(filePath)
	}
}

// getPacketsToSave returns packets to save based on filter state
func (m *Model) getPacketsToSave() []components.PacketDisplay {
	if m.packetStore.HasFilter() {
		return m.packetStore.GetFilteredPackets()
	}
	return m.packetStore.GetPacketsInOrder()
}

// getFilterFunction returns a filter function for the streaming writer
func (m *Model) getFilterFunction() func(components.PacketDisplay) bool {
	if !m.packetStore.HasFilter() {
		return nil // No filter, save everything
	}

	// Return filter function that checks if packet matches
	filterChain := m.packetStore.FilterChain
	return func(pkt components.PacketDisplay) bool {
		if filterChain == nil {
			return true
		}
		return filterChain.Match(pkt)
	}
}

// startOneShotSave starts a one-shot save operation (offline/paused mode)
func (m *Model) startOneShotSave(filePath string) tea.Cmd {
	return func() tea.Msg {
		// Get packets to save
		packets := m.getPacketsToSave()

		if len(packets) == 0 {
			return SaveCompleteMsg{
				Success: false,
				Path:    filePath,
				Error:   fmt.Errorf("no packets to save"),
			}
		}

		// Get link type from first packet (default to Ethernet if not set)
		linkType := layers.LinkTypeEthernet
		if packets[0].LinkType != 0 {
			linkType = packets[0].LinkType
		}

		// Create one-shot writer
		writer, err := pcap.NewOneShotWriter(pcap.Config{
			FilePath: filePath,
			LinkType: linkType,
			Snaplen:  65536,
		})
		if err != nil {
			return SaveCompleteMsg{
				Success: false,
				Path:    filePath,
				Error:   fmt.Errorf("failed to create writer: %w", err),
			}
		}

		// Write all packets
		for _, pkt := range packets {
			if err := writer.WritePacket(pkt); err != nil {
				if closeErr := writer.Close(); closeErr != nil {
					logger.Error("Failed to close writer during error cleanup", "error", closeErr, "file", filePath)
				}
				return SaveCompleteMsg{
					Success: false,
					Path:    filePath,
					Error:   fmt.Errorf("failed to write packet: %w", err),
				}
			}
		}

		// Close and get final count
		if err := writer.Close(); err != nil {
			return SaveCompleteMsg{
				Success: false,
				Path:    filePath,
				Error:   fmt.Errorf("failed to close file: %w", err),
			}
		}

		return SaveCompleteMsg{
			Success:      true,
			Path:         filePath,
			PacketsSaved: writer.PacketCount(),
			Streaming:    false,
		}
	}
}

// startStreamingSave starts a streaming save operation (live/remote mode)
func (m *Model) startStreamingSave(filePath string) tea.Cmd {
	// Get filter function
	filterFunc := m.getFilterFunction()

	// Get link type from existing packets (default to Ethernet if not set)
	linkType := layers.LinkTypeEthernet
	packets := m.getPacketsToSave()
	if len(packets) > 0 && packets[0].LinkType != 0 {
		linkType = packets[0].LinkType
	}

	// Create streaming writer
	writer, err := pcap.NewStreamingWriter(pcap.Config{
		FilePath:     filePath,
		LinkType:     linkType,
		Snaplen:      65536,
		SyncInterval: 5 * time.Second,
	}, filterFunc)

	if err != nil {
		// Return error immediately
		return func() tea.Msg {
			return SaveCompleteMsg{
				Success: false,
				Path:    filePath,
				Error:   fmt.Errorf("failed to create streaming writer: %w", err),
			}
		}
	}

	// Store writer in model
	m.activeWriter = writer
	m.savePath = filePath
	m.uiState.StreamingSave = true
	m.uiState.Footer.SetStreamingSave(true) // Update footer hint

	// Write existing packets in background to avoid blocking/dropping
	// Channel buffer is 1000, so writing >1000 packets synchronously would drop packets
	go func() {
		for _, pkt := range packets {
			// Block until packet can be written (don't drop buffered packets)
			// This is OK because we're in a background goroutine
			for {
				err := writer.WritePacket(pkt)
				if err == nil {
					break // Success
				}
				// If writer is closed or context cancelled, stop trying
				if err.Error() == "writer is closed" || err.Error() == "writer context cancelled" {
					return
				}
				// If error is "buffer full", retry after short delay
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()

	// Show toast notification
	return m.uiState.Toast.Show(
		fmt.Sprintf("Recording to %s...", filepath.Base(filePath)),
		components.ToastInfo,
		components.ToastDurationNormal, // Show for 3 seconds to notify user streaming has started
	)
}

// stopStreamingSave stops the active streaming save
func (m *Model) stopStreamingSave() tea.Cmd {
	if m.activeWriter == nil {
		return nil
	}

	writer := m.activeWriter
	path := m.savePath

	// Close writer in goroutine
	return func() tea.Msg {
		count := writer.PacketCount()
		err := writer.Close()

		if err != nil {
			return SaveCompleteMsg{
				Success:   false,
				Path:      path,
				Error:     fmt.Errorf("failed to close file: %w", err),
				Streaming: true,
			}
		}

		return SaveCompleteMsg{
			Success:      true,
			Path:         path,
			PacketsSaved: count,
			Streaming:    true,
		}
	}
}
