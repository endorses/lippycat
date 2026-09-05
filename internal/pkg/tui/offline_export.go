//go:build tui || all

package tui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// The worker starts immediately; a Bubble Tea command only delivers its result.
// Session cleanup can therefore cancel and join even an abandoned command.
type offlineExportState struct {
	cancel context.CancelFunc
	done   chan struct{}
	result SaveCompleteMsg // published by closing done
}

func (m *Model) exportRunning() bool {
	if m.offlineExport == nil {
		return false
	}
	select {
	case <-m.offlineExport.done:
		return false
	default:
		return true
	}
}

func (m *Model) cancelOfflineExport() bool {
	if !m.exportRunning() {
		return false
	}
	m.offlineExport.cancel()
	return true
}

func (m *Model) startOfflineExport(path string) tea.Cmd {
	if m.exportRunning() || m.uiState.SaveInProgress {
		return m.uiState.Toast.Show("A packet export is already in progress.", components.ToastInfo, components.ToastDurationNormal)
	}
	if m.offlineBrowse == nil {
		b := &offlineBrowser{dataset: m.offlineSession.Dataset, results: make(map[*offlineBrowseResult]struct{})}
		m.offlineSession.browser = b
		m.offlineBrowse = &offlineBrowserState{owner: b}
	}
	b := m.offlineBrowse.owner
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return func() tea.Msg {
			return SaveCompleteMsg{Path: path, Error: fmt.Errorf("offline packet dataset is closing")}
		}
	}
	if b.query == nil && !b.closed {
		q, err := offline.AllPackets(context.Background(), b.dataset, offline.Token{Dataset: b.dataset.Generation(), Query: 1})
		if err != nil {
			b.mu.Unlock()
			return func() tea.Msg { return SaveCompleteMsg{Path: path, Error: err} }
		}
		b.query = q
	}
	// Acquire ownership before returning to the event loop: a subsequent filter
	// replacement may close this query as soon as its result is published.
	pin, err := offline.PinQuery(b.query)
	b.mu.Unlock()
	if err != nil {
		return func() tea.Msg { return SaveCompleteMsg{Path: path, Error: err} }
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &offlineExportState{cancel: cancel, done: make(chan struct{})}
	m.offlineExport = s
	m.offlineSession.export = s
	m.uiState.SaveInProgress = true
	go func() {
		defer close(s.done)
		defer cancel()
		count, err := exportOfflinePCAP(ctx, path, pin.Iterate)
		err = errors.Join(err, pin.Close())
		s.result = SaveCompleteMsg{Success: err == nil, Path: path, PacketsSaved: count, Error: err}
	}()
	return tea.Batch(m.uiState.Toast.ShowWithKey("Saving packets… Esc cancels export", components.ToastInfo, 0, components.ToastKeyFileSave), func() tea.Msg { <-s.done; return s.result })
}

type offlineDetailIterator func(context.Context, func(offline.Detail) error) error

// Write beside the destination and publish only after every record and close
// succeeds. Cancellation, mixed links, corruption and disk errors never leave a
// successful-looking partial capture or replace an existing destination.
func exportOfflinePCAP(ctx context.Context, path string, iterate offlineDetailIterator) (count uint64, err error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".lippycat-export-*.pcap")
	if err != nil {
		return 0, fmt.Errorf("create offline export: %w", err)
	}
	temp := f.Name()
	closed, published := false, false
	defer func() {
		if !closed {
			err = errors.Join(err, f.Close())
		}
		if !published {
			if removeErr := os.Remove(temp); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				err = errors.Join(err, fmt.Errorf("remove incomplete export: %w", removeErr))
			}
		}
	}()
	count, err = writeOfflinePCAP(ctx, f, iterate)
	if err != nil {
		return count, err
	}
	if err = f.Sync(); err != nil {
		return count, fmt.Errorf("flush offline export: %w", err)
	}
	err = f.Close()
	closed = true
	if err != nil {
		return count, fmt.Errorf("close offline export: %w", err)
	}
	if err = ctx.Err(); err != nil {
		return count, err
	}
	if err = os.Rename(temp, path); err != nil {
		return count, fmt.Errorf("publish offline export: %w", err)
	}
	published = true
	return count, nil
}

func writeOfflinePCAP(ctx context.Context, output io.Writer, iterate offlineDetailIterator) (uint64, error) {
	w := pcapgo.NewWriterNanos(output)
	var count uint64
	var link layers.LinkType
	err := iterate(ctx, func(d offline.Detail) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if count == 0 {
			link = d.Packet.LinkType
			if err := w.WriteFileHeader(math.MaxUint32, link); err != nil {
				return fmt.Errorf("write offline export header: %w", err)
			}
		} else if d.Packet.LinkType != link {
			return fmt.Errorf("cannot export mixed link types to PCAP (packet %d has %s; expected %s); export inputs separately", d.ID, d.Packet.LinkType, link)
		}
		if uint64(len(d.Packet.RawData)) != uint64(d.CapturedLength) || d.CapturedLength > d.OriginalLength {
			return fmt.Errorf("invalid capture lengths for offline packet %d", d.ID)
		}
		info := gopacket.CaptureInfo{Timestamp: d.Packet.Timestamp, CaptureLength: int(d.CapturedLength), Length: int(d.OriginalLength)}
		if err := w.WritePacket(info, d.Packet.RawData); err != nil {
			return fmt.Errorf("write offline packet %d: %w", d.ID, err)
		}
		count++
		return nil
	})
	if err == nil && count == 0 {
		err = fmt.Errorf("no packets to save")
	}
	return count, err
}
