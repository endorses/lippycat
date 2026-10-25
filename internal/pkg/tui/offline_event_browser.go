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

// One session-owned reader owns installed and abandoned queries and page leases.
// Its workers serialize reads and cleanup; Close is called outside Tea Update.
type offlineEventBrowser struct {
	mu       sync.Mutex
	releases sync.WaitGroup
	dataset  offline.EventDataset
	query    offline.EventQuery
	cancel   context.CancelFunc
	done     chan struct{}
	closed   bool
	results  map[*offlineEventBrowseResult]struct{}
	queries  map[offline.EventQuery]struct{}
	current  *offlineEventBrowseResult
	progress offline.QueryProgress
}

type offlineEventBrowseResult struct {
	token    offline.Token
	cursor   uint64
	page     offline.EventPage
	detail   *offline.EventDetail
	items    []components.EventItem
	selected *components.EventItem
	err      error
}

type offlineEventBrowserState struct {
	owner               *offlineEventBrowser
	request             offline.RequestID
	queryGeneration     offline.QueryGeneration
	cursor, offset      uint64
	rows                int
	requested           bool
	current             *offlineEventBrowseResult
	descriptions        []string
	protocol, attempted string
	detailScroll        int
	detailScrollArrival uint64
	detailScrollValid   bool
}

type offlineEventBrowseMsg struct {
	owner  *offlineEventBrowser
	result *offlineEventBrowseResult
}

func (b *offlineEventBrowser) releaseResultLocked(r *offlineEventBrowseResult) error {
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
	r.page, r.detail, r.items, r.selected = offline.EventPage{}, nil, nil, nil
	return err
}

func (b *offlineEventBrowser) releaseResult(r *offlineEventBrowseResult) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.releaseResultLocked(r)
}

func (b *offlineEventBrowser) releaseQuery(q offline.EventQuery) error {
	if q == nil {
		return nil
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil // Close retains ownership, including commands Tea abandons.
	}
	if _, owned := b.queries[q]; !owned {
		b.mu.Unlock()
		return nil
	}
	delete(b.queries, q)
	b.releases.Add(1)
	b.mu.Unlock()
	defer b.releases.Done()
	err := q.Close()
	if err != nil {
		b.mu.Lock()
		b.queries[q] = struct{}{}
		b.mu.Unlock()
	}
	return err
}

func (b *offlineEventBrowser) Close() error {
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
	b.releases.Wait()
	b.mu.Lock()
	var err error
	for r := range b.results {
		err = errors.Join(err, b.releaseResultLocked(r))
	}
	b.current, b.query = nil, nil
	queries := b.queries
	b.queries = make(map[offline.EventQuery]struct{})
	b.mu.Unlock()
	for q := range queries {
		if closeErr := q.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
			b.mu.Lock()
			b.queries[q] = struct{}{}
			b.mu.Unlock()
		}
	}
	return err
}

func (b *offlineEventBrowser) begin() (context.Context, <-chan struct{}, chan struct{}, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, nil, nil, false
	}
	if b.cancel != nil {
		b.cancel()
	}
	prior := b.done
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	b.cancel, b.done = cancel, done
	return ctx, prior, done, true
}

// cleanupPending runs after the preceding worker joins, including when its
// result message was never delivered. Only the installed query/page survives.
func (b *offlineEventBrowser) cleanupPending() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return context.Canceled
	}
	var err error
	for r := range b.results {
		if r != b.current {
			err = errors.Join(err, b.releaseResultLocked(r))
		}
	}
	var obsolete offline.EventQuery
	for q := range b.queries {
		if q != b.query {
			obsolete = q
			break
		}
	}
	b.mu.Unlock()
	for obsolete != nil {
		err = errors.Join(err, b.releaseQuery(obsolete))
		b.mu.Lock()
		obsolete = nil
		if !b.closed {
			for q := range b.queries {
				if q != b.query {
					obsolete = q
					break
				}
			}
		}
		b.mu.Unlock()
		if err != nil {
			return err
		}
	}
	return err
}

func (b *offlineEventBrowser) load(token offline.Token, offset, cursor uint64, rows int, maxBytes uint64) tea.Cmd {
	ctx, prior, done, ok := b.begin()
	if !ok {
		return nil
	}
	ch := make(chan offlineEventBrowseMsg, 1)
	go func() {
		defer close(done)
		if prior != nil {
			<-prior
		}
		r := &offlineEventBrowseResult{token: token, cursor: cursor}
		r.err = b.cleanupPending()
		if r.err == nil {
			r.err = ctx.Err()
		}
		b.mu.Lock()
		q := b.query
		b.mu.Unlock()
		if r.err == nil && q == nil {
			q, r.err = offline.AllEvents(ctx, b.dataset, offline.Token{Dataset: token.Dataset, Query: token.Query})
			if q != nil {
				b.mu.Lock()
				b.query, b.queries[q] = q, struct{}{}
				b.mu.Unlock()
			}
		}
		if r.err == nil {
			r.page, r.err = q.Page(ctx, offline.PageRequest{Token: token, Row: offset, Limit: uint32(max(1, min(rows*2, 512))), MaxBytes: maxBytes})
		}
		if r.err == nil {
			// EventPage reserves EventPresentationBytesPerRow for these scalar
			// records. Event values and strings borrow the live page lease.
			r.items = make([]components.EventItem, len(r.page.Rows))
			for i, row := range r.page.Rows {
				r.items[i] = components.EventItem{Event: row.Event, ArrivalSequence: uint64(row.ID)}
			}
			if cursor >= r.page.Row && cursor-r.page.Row < uint64(len(r.items)) {
				r.selected = &r.items[cursor-r.page.Row]
			} else if q.Count() > 0 {
				// A byte-capped viewport can end before the cursor. Resolve just
				// that row, retaining one separately charged detail lease.
				selected, err := q.Page(ctx, offline.PageRequest{Token: token, Row: cursor, Limit: 1, MaxBytes: maxBytes})
				r.err = err
				if err == nil {
					var id offline.EventRowID
					if len(selected.Rows) == 1 {
						id = selected.Rows[0].ID
					} else {
						r.err = errors.New("selected offline event row unavailable")
					}
					r.err = errors.Join(r.err, selected.Close())
					if r.err == nil {
						r.detail, r.err = b.dataset.Detail(ctx, token, id)
						if r.err == nil {
							r.selected = &components.EventItem{Event: r.detail.Record.Event, ArrivalSequence: uint64(id)}
						}
					}
				}
			}
		}
		if r.err == nil {
			r.err = ctx.Err()
		}
		b.mu.Lock()
		b.results[r] = struct{}{}
		b.mu.Unlock()
		ch <- offlineEventBrowseMsg{b, r}
	}()
	return func() tea.Msg { return <-ch }
}

func (m *Model) ensureOfflineEventBrowser() error {
	if m.offlineEventBrowse != nil || m.offlineSession == nil || m.offlineSession.EventDataset == nil {
		return nil
	}
	b := &offlineEventBrowser{dataset: m.offlineSession.EventDataset, results: make(map[*offlineEventBrowseResult]struct{}), queries: make(map[offline.EventQuery]struct{})}
	if err := m.offlineSession.registerEventCloser(b); err != nil {
		// No worker has started: ownership was rejected and immediate cleanup
		// cannot wait on I/O or on another goroutine.
		return errors.Join(err, b.Close())
	}
	m.offlineEventBrowse = &offlineEventBrowserState{owner: b, queryGeneration: 1, protocol: "All", attempted: "All"}
	return nil
}

func (m *Model) cancelOfflineEventReads() {
	if s := m.offlineEventBrowse; s != nil {
		s.request++
		s.requested = false
		s.owner.mu.Lock()
		if s.owner.cancel != nil {
			s.owner.cancel()
		}
		s.owner.mu.Unlock()
	}
}

func (m *Model) detachOfflineEvents() {
	m.cancelOfflineEventReads()
	m.offlineEventFilter = nil
	if m.uiState.EventsView.IsVirtual() {
		m.uiState.EventsView.SetVirtualDetail(nil)
		m.uiState.EventsView.SetVirtualWindow(0, 0, nil)
	}
	m.offlineEventBrowse = nil
}

func (m *Model) syncOfflineEventBrowser() tea.Cmd {
	if m.offlineSession == nil || m.offlineSession.EventDataset == nil || m.offlineOpening || m.offlineLeaving || m.offlineEventFilter != nil {
		return nil
	}
	if m.uiState.ViewMode != "events" || m.uiState.Tabs.GetActive() != 0 {
		if s := m.offlineEventBrowse; s != nil && s.requested {
			if s.current != nil && s.current.selected != nil {
				_, _, s.detailScroll = m.uiState.EventsView.DetailsScrollState()
				s.detailScrollArrival, s.detailScrollValid = s.current.selected.ArrivalSequence, true
			}
			m.cancelOfflineEventReads()
			m.uiState.EventsView.SetVirtualDetail(nil)
			m.uiState.EventsView.SetVirtualWindow(m.offlineEventCount(), m.uiState.EventsView.LogicalOffset(), nil)
			old := s.current
			s.current = nil
			s.owner.mu.Lock()
			s.owner.current = nil
			s.owner.mu.Unlock()
			return func() tea.Msg { return offlineCleanupMsg{err: s.owner.releaseResult(old)} }
		}
		return nil
	}
	if err := m.ensureOfflineEventBrowser(); err != nil {
		return m.uiState.Toast.Show(err.Error(), components.ToastError, components.ToastDurationLong)
	}
	s := m.offlineEventBrowse
	if protocol := m.uiState.SelectedProtocol.Name; protocol != s.attempted {
		return m.startOfflineEventFilter(s.descriptions, protocol)
	}
	v := m.uiState.EventsView
	if !v.IsVirtual() {
		v.EnableVirtualEvents(m.offlineEventCount())
	}
	cursor, offset, rows := v.LogicalCursor(), v.LogicalOffset(), v.VisibleRows()
	if s.requested && s.cursor == cursor && s.offset == offset && s.rows == rows {
		return nil
	}
	if s.current != nil && s.current.selected != nil {
		_, _, s.detailScroll = v.DetailsScrollState()
		s.detailScrollArrival, s.detailScrollValid = s.current.selected.ArrivalSequence, true
	}
	// A complete prefetched viewport and its cursor already have a lease.
	if r := s.current; r != nil && offset >= r.page.Row && offset-r.page.Row+uint64(max(1, rows)) <= uint64(len(r.items)) && cursor >= r.page.Row && cursor-r.page.Row < uint64(len(r.items)) {
		s.cursor, s.offset, s.rows, s.requested = cursor, offset, rows, true
		r.selected = &r.items[cursor-r.page.Row]
		v.SetVirtualDetail(r.selected)
		m.presentOfflineRelated(r.selected.Event)
		m.prepareEventsViewLayout()
		return nil
	}
	m.cancelOfflineEventReads()
	s.cursor, s.offset, s.rows, s.requested = cursor, offset, rows, true
	v.SetVirtualDetail(nil)
	v.SetVirtualWindow(m.offlineEventCount(), offset, nil)
	if s.current != nil {
		if err := s.owner.releaseResult(s.current); err != nil {
			return m.uiState.Toast.Show(err.Error(), components.ToastError, components.ToastDurationLong)
		}
		s.current = nil
		s.owner.mu.Lock()
		s.owner.current = nil
		s.owner.mu.Unlock()
	}
	return s.owner.load(offline.Token{Dataset: s.owner.dataset.Generation(), Query: s.queryGeneration, Request: s.request}, offset, cursor, rows, offlinePageBudget(m.offlineInstalled.Limits))
}

func (m *Model) offlineEventCount() uint64 {
	if s := m.offlineEventBrowse; s != nil {
		s.owner.mu.Lock()
		defer s.owner.mu.Unlock()
		if s.owner.query != nil {
			return s.owner.query.Count()
		}
	}
	if m.offlineSession != nil && m.offlineSession.EventDataset != nil {
		return m.offlineSession.EventDataset.Count()
	}
	return 0
}

func (m Model) handleOfflineEventBrowse(msg offlineEventBrowseMsg) (Model, tea.Cmd) {
	s, r := m.offlineEventBrowse, msg.result
	if s != nil && s.current == r {
		return m, nil
	}
	if s == nil || s.owner != msg.owner || s.request != r.token.Request || s.queryGeneration != r.token.Query || m.offlineSession == nil || m.offlineSession.EventDataset == nil || r.token.Dataset != m.offlineSession.EventDataset.Generation() || m.offlineOpening || m.offlineLeaving {
		return m, func() tea.Msg { return offlineCleanupMsg{err: msg.owner.releaseResult(r)} }
	}
	if r.err != nil {
		err := errors.Join(r.err, msg.owner.releaseResult(r))
		if errors.Is(err, context.Canceled) {
			return m, nil
		}
		return m, m.uiState.Toast.Show("Could not load offline events: "+err.Error(), components.ToastError, components.ToastDurationLong)
	}
	old := s.current
	s.current = r
	s.owner.mu.Lock()
	s.owner.current = r
	s.owner.mu.Unlock()
	m.uiState.EventsView.SetVirtualWindow(m.offlineEventCount(), r.page.Row, r.items)
	m.uiState.EventsView.SetVirtualDetail(r.selected)
	m.prepareEventsViewLayout()
	if r.selected != nil {
		if s.detailScrollValid && s.detailScrollArrival == r.selected.ArrivalSequence {
			m.uiState.EventsView.SetDetailsScrollOffset(s.detailScroll)
		}
		m.presentOfflineRelated(r.selected.Event)
	}
	return m, func() tea.Msg { return offlineCleanupMsg{err: msg.owner.releaseResult(old)} }
}
