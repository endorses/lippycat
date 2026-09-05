//go:build tui || all

package tui

import (
	"context"
	"errors"
	"sync"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
)

// offlineBrowser owns every page/detail lease, including results whose messages
// are abandoned when the program exits. Reads are serialized and cancellable.
type offlineBrowser struct {
	mu      sync.Mutex
	dataset offline.Dataset
	query   offline.Query
	cancel  context.CancelFunc
	done    chan struct{}
	closed  bool
	results map[*offlineBrowseResult]struct{}
	current *offlineBrowseResult
}
type offlineBrowseResult struct {
	token       offline.Token
	row, cursor uint64
	page        offline.Page
	detail      *offline.DetailPin
	err         error
	reuse       bool
}
type offlineBrowseMsg struct {
	owner  *offlineBrowser
	result *offlineBrowseResult
}
type offlineBrowserState struct {
	owner          *offlineBrowser
	request        offline.RequestID
	cursor, offset uint64
	rows           int
	current        *offlineBrowseResult
	requested      bool
}

func (b *offlineBrowser) releaseLocked(r *offlineBrowseResult) error {
	if r == nil {
		return nil
	}
	if _, ok := b.results[r]; !ok {
		return nil
	}
	delete(b.results, r)
	var err error
	if r.detail != nil {
		err = r.detail.Close()
	}
	err = errors.Join(err, r.page.Close())
	r.detail = nil
	r.page = offline.Page{}
	return err
}
func (b *offlineBrowser) release(r *offlineBrowseResult) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.releaseLocked(r)
}

// Cancel requests without closing the installed page while replacement indexes.
func (m *Model) cancelOfflineBrowserReads() {

	if m.offlineBrowse == nil {
		return
	}
	s := m.offlineBrowse
	s.request++
	s.requested = false
	s.owner.mu.Lock()
	if s.owner.cancel != nil {
		s.owner.cancel()
	}
	s.owner.mu.Unlock()
}

func (b *offlineBrowser) close() error {
	b.mu.Lock()
	b.closed = true
	if b.cancel != nil {
		b.cancel()
	}
	done := b.done
	b.mu.Unlock()
	if done != nil {
		<-done
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	var err error
	for r := range b.results {
		err = errors.Join(err, b.releaseLocked(r))
	}
	b.current = nil
	if b.query != nil {
		err = errors.Join(err, b.query.Close())
		b.query = nil
	}
	return err
}
func (b *offlineBrowser) load(token offline.Token, offset, cursor uint64, rows int, maxBytes uint64, reuse bool) tea.Cmd {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	if b.cancel != nil {
		b.cancel()
	}
	prior := b.done
	ctx, cancel := context.WithCancel(context.Background())
	b.cancel = cancel
	done := make(chan struct{})
	b.done = done
	b.mu.Unlock()
	ch := make(chan tea.Msg, 1)
	go func() {
		defer close(done)
		if prior != nil {
			<-prior
		}
		b.mu.Lock()
		for pending := range b.results {
			if pending != b.current {
				if err := b.releaseLocked(pending); err != nil {
					b.mu.Unlock()
					ch <- offlineBrowseMsg{b, &offlineBrowseResult{token: token, err: err}}
					return
				}
			}
		}
		b.mu.Unlock()
		r := &offlineBrowseResult{token: token, row: offset, cursor: cursor, reuse: reuse}
		if err := ctx.Err(); err != nil {
			r.err = err
		} else {
			if b.query == nil {
				b.query, r.err = offline.AllPackets(ctx, b.dataset, offline.Token{Dataset: token.Dataset, Query: token.Query})
			}
			if r.err == nil && !reuse {
				// Fetch the viewport and one following viewport. Byte caps include retained
				// summaries; details remain independently pinned under the shared budget.
				r.page, r.err = b.query.Page(ctx, offline.PageRequest{Token: token, Row: offset, Limit: uint32(max(1, min(rows*2, 512))), MaxBytes: maxBytes})
			}
			if r.err == nil && b.dataset.Count() > 0 {
				r.detail, r.err = b.dataset.PinDetail(ctx, token, offline.PacketID(cursor))
			}
		}
		b.mu.Lock()
		b.results[r] = struct{}{}
		b.mu.Unlock()
		ch <- offlineBrowseMsg{b, r}
	}()
	return func() tea.Msg { return <-ch }
}

// drainBefore joins a cancelled request outside Update and releases obsolete
// output even if Bubble Tea never consumes its completion message.
func (b *offlineBrowser) drainBefore(done <-chan struct{}, cutoff offline.RequestID) error {
	if done != nil {
		<-done
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	var err error
	for r := range b.results {
		if r != b.current && r.token.Request < cutoff {
			err = errors.Join(err, b.releaseLocked(r))
		}
	}
	return err
}

func (m *Model) syncOfflineBrowser() tea.Cmd {
	if m.offlineSession == nil || m.offlineOpening || m.offlineLeaving || !m.uiState.PacketList.IsVirtual() {
		return nil
	}
	if m.uiState.ViewMode != "packets" || m.uiState.Tabs.GetActive() != 0 {
		s := m.offlineBrowse
		if s == nil || !s.requested {
			return nil
		}
		m.cancelOfflineBrowserReads()
		m.uiState.DetailsPanel.SetPacket(nil)
		m.uiState.PacketList.SetVirtualPackets(m.offlineSession.Dataset.Count(), m.uiState.PacketList.LogicalOffset(), nil)
		err := s.owner.release(s.current)
		s.current = nil
		s.owner.mu.Lock()
		s.owner.current = nil
		done := s.owner.done
		s.owner.mu.Unlock()
		cutoff := s.request
		return func() tea.Msg { return offlineCleanupMsg{err: errors.Join(err, s.owner.drainBefore(done, cutoff))} }
	}
	if m.offlineBrowse == nil {
		b := &offlineBrowser{dataset: m.offlineSession.Dataset, results: make(map[*offlineBrowseResult]struct{})}
		m.offlineSession.browser = b
		m.offlineBrowse = &offlineBrowserState{owner: b}
	}
	s := m.offlineBrowse
	cursor, offset, rows := m.uiState.PacketList.LogicalCursor(), m.uiState.PacketList.LogicalOffset(), m.uiState.PacketList.VisibleRows()
	selectedMissing := s.current != nil && m.offlineSession.Dataset.Count() > 0 && (cursor < s.current.page.Row || cursor >= s.current.page.Row+uint64(len(s.current.page.Rows)))
	if s.requested && s.cursor == cursor && s.offset == offset && s.rows == rows && !selectedMissing {
		return nil
	}
	s.request++
	s.cursor = cursor
	s.offset = offset
	s.rows = rows
	s.requested = true
	reuse := s.current != nil && offset >= s.current.page.Row && offset+uint64(max(1, rows)) <= s.current.page.Row+uint64(len(s.current.page.Rows))
	if s.current != nil && s.current.detail != nil {
		m.uiState.DetailsPanel.SetPacket(nil)
		if err := s.current.detail.Close(); err != nil {
			return m.uiState.Toast.Show(err.Error(), components.ToastError, components.ToastDurationLong)
		}
		s.current.detail = nil
	}
	if !reuse && s.current != nil {
		m.uiState.PacketList.SetVirtualPackets(m.offlineSession.Dataset.Count(), offset, nil)
		if err := s.owner.release(s.current); err != nil {
			return m.uiState.Toast.Show(err.Error(), components.ToastError, components.ToastDurationLong)
		}
		s.current = nil
	}
	loadOffset := offset
	if selectedMissing {
		loadOffset = cursor
	}
	if m.offlineSession.Dataset.Count() > 0 {
		m.uiState.DetailsPanel.SetLoading()
	}
	return s.owner.load(offline.Token{Dataset: m.offlineSession.Dataset.Generation(), Query: 1, Request: s.request}, loadOffset, cursor, rows, offlinePageBudget(m.offlineInstalled.Limits), reuse)
}
func (m Model) handleOfflineBrowse(msg offlineBrowseMsg) (Model, tea.Cmd) {
	s, r := m.offlineBrowse, msg.result
	if s != nil && s.current == r {
		return m, nil
	}
	if s == nil || s.owner != msg.owner || s.request != r.token.Request || m.offlineSession == nil || r.token.Dataset != m.offlineSession.Dataset.Generation() || r.token.Query != 1 || m.offlineLeaving {
		if err := msg.owner.release(r); err != nil {
			return m, m.uiState.Toast.Show(err.Error(), components.ToastError, components.ToastDurationLong)
		}
		return m, nil
	}
	if r.err != nil {
		m.uiState.DetailsPanel.SetPacket(nil)
		err := errors.Join(r.err, msg.owner.release(r))
		if errors.Is(err, context.Canceled) {
			return m, nil
		}
		return m, m.uiState.Toast.Show("Could not load offline packets: "+err.Error(), components.ToastError, components.ToastDurationLong)
	}
	if r.reuse && s.current != nil {
		r.page = s.current.page
		s.current.page = offline.Page{}
	}
	// Page accounting conservatively charges each Summary struct both in its
	// decoded reservation and in the page backing slice. The scalar display
	// projection fits within that duplicate struct charge and borrows strings
	// from the page lease; it allocates no metadata or payload copies.
	packets := make([]components.PacketDisplay, len(r.page.Rows))
	for i, row := range r.page.Rows {
		packets[i] = row.DisplayFields()
	}
	m.uiState.PacketList.SetVirtualPackets(m.offlineSession.Dataset.Count(), r.page.Row, packets)
	m.uiState.DetailsPanel.SetPacket(nil)
	if r.detail != nil {
		m.uiState.DetailsPanel.SetPacket(&r.detail.Value.Packet)
	}
	old := s.current
	s.current = r
	s.owner.mu.Lock()
	s.owner.current = r
	s.owner.mu.Unlock()
	if err := msg.owner.release(old); err != nil {
		return m, m.uiState.Toast.Show(err.Error(), components.ToastError, components.ToastDurationLong)
	}
	return m, nil
}

// Give a single large summary room beyond the usual quarter-cache viewport,
// while leaving two record allocations and framing space for a following read.
func offlinePageBudget(limits offline.ResourceLimits) uint64 {
	if limits.CacheBytes == 0 {
		return 64 << 10
	}
	budget := limits.CacheBytes / 4
	if limits.MaxRecordBytes <= limits.CacheBytes/2 && limits.CacheBytes-2*limits.MaxRecordBytes > 64 {
		headroom := limits.CacheBytes - 2*limits.MaxRecordBytes - 64
		recordBudget := limits.MaxRecordBytes
		if recordBudget <= headroom && headroom-recordBudget >= 4096 {
			recordBudget += 4096
		} else {
			recordBudget = headroom
		}
		budget = min(headroom, max(budget, recordBudget))
	}
	return max(uint64(1), budget)
}
