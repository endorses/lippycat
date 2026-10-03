//go:build tui || all

package tui

import (
	"context"
	"errors"
	"fmt"
	"sort"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
)

// The worker starts immediately and is owned by its session, even when Bubble
// Tea never executes the returned delivery command.
type offlineMarkRangeState struct {
	cancel context.CancelFunc
	done   chan struct{}
	ids    []offline.PacketID
	err    error
}

type offlineMarkRangeMsg struct {
	session  *offlineIndexedSession
	state    *offlineMarkRangeState
	token    offline.Token
	revision uint64
	replace  bool
}

func (m *Model) pinOfflineMarkQuery() (*offline.QueryPin, offline.Token, error) {
	if m.offlineSession == nil || m.offlineLeaving {
		return nil, offline.Token{}, fmt.Errorf("offline capture is unavailable")
	}
	if m.offlineBrowse == nil {
		b := &offlineBrowser{dataset: m.offlineSession.Dataset, results: make(map[*offlineBrowseResult]struct{})}
		m.offlineSession.browser = b
		m.offlineBrowse = &offlineBrowserState{owner: b}
	}
	b := m.offlineBrowse.owner
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, offline.Token{}, fmt.Errorf("offline capture is closing")
	}
	if b.query == nil {
		q, err := offline.AllPackets(context.Background(), b.dataset, offline.Token{Dataset: b.dataset.Generation(), Query: 1})
		if err != nil {
			return nil, offline.Token{}, err
		}
		b.query = q
	}
	pin, err := offline.PinQuery(b.query)
	return pin, b.query.Token(), err
}

func (m *Model) startOfflineMarkRange(anchorID uint64, cursor uint64, replace bool) tea.Cmd {
	m.ensurePacketMarks()
	if anchorID == 0 {
		return m.markError(fmt.Errorf("mark a packet first to choose a range anchor"))
	}
	pin, token, err := m.pinOfflineMarkQuery()
	if err != nil {
		return m.markError(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	state := &offlineMarkRangeState{cancel: cancel, done: make(chan struct{})}
	prior := m.offlineSession.markRange
	if prior != nil {
		prior.cancel()
	}
	m.offlineSession.markRange = state
	msg := offlineMarkRangeMsg{session: m.offlineSession, state: state, token: token, revision: m.packetMarks.revision, replace: replace}
	limit := uint64(m.packetMarks.maxPackets)
	go func() {
		defer close(state.done)
		defer cancel()
		if prior != nil {
			<-prior.done
		}
		state.ids, state.err = pin.RangeIDs(ctx, offline.PacketID(anchorID-1), cursor, limit)
		state.err = errors.Join(state.err, pin.Close())
	}()
	return func() tea.Msg { <-state.done; return msg }
}

func (m Model) handleOfflineMarkRange(msg offlineMarkRangeMsg) (Model, tea.Cmd) {
	if m.offlineSession != msg.session || m.offlineLeaving || msg.session.markRange != msg.state ||
		msg.token.Dataset != m.offlineSession.Dataset.Generation() || msg.token.Query != m.offlineQueryGeneration() ||
		msg.revision != m.packetMarks.revision {
		return m, nil
	}
	if msg.state.err != nil {
		if errors.Is(msg.state.err, context.Canceled) {
			return m, nil
		}
		return m, m.markError(msg.state.err)
	}
	records := make(map[uint64]offline.RawRecord)
	if !msg.replace {
		for id, record := range m.packetMarks.records {
			records[id] = record
		}
	}
	for _, id := range msg.state.ids {
		records[uint64(id)+1] = offline.RawRecord{}
		if len(records) > m.packetMarks.maxPackets {
			return m, m.markError(fmt.Errorf("packet marking limit reached; clear marks or select a smaller range"))
		}
	}
	m.packetMarks.records = records
	m.packetMarks.bytes = 0
	m.publishPacketMarks()
	return m, nil
}

// Selected identities are copied before launching the worker. The query pin
// keeps the backing dataset alive while filters or the capture session change.
func (m *Model) startMarkedOfflineExport(path string, ids []uint64) tea.Cmd {
	pin, _, err := m.pinOfflineMarkQuery()
	if err != nil {
		return m.markError(err)
	}
	selected := make([]offline.PacketID, 0, len(ids))
	for _, id := range ids {
		if id == 0 {
			err = errors.Join(fmt.Errorf("invalid marked packet identity"), pin.Close())
			return m.markError(err)
		}
		selected = append(selected, offline.PacketID(id-1))
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i] < selected[j] })
	ctx, cancel := context.WithCancel(context.Background())
	state := &offlineExportState{cancel: cancel, done: make(chan struct{})}
	m.offlineExport = state
	m.offlineSession.export = state
	m.uiState.SaveInProgress = true
	go func() {
		defer close(state.done)
		defer cancel()
		count, err := exportOfflinePCAP(ctx, path, func(ctx context.Context, visit func(offline.RawRecord) error) error {
			return pin.IterateSelectedRaw(ctx, selected, visit)
		})
		err = errors.Join(err, pin.Close())
		state.result = SaveCompleteMsg{Success: err == nil, Path: path, PacketsSaved: count, Error: err}
	}()
	return tea.Batch(m.uiState.Toast.ShowWithKey("Saving marked packets… Esc cancels export", components.ToastInfo, 0, components.ToastKeyFileSave), func() tea.Msg { <-state.done; return state.result })
}
