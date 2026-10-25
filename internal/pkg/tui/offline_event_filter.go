//go:build tui || all

package tui

import (
	"context"
	"errors"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/eventquery"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
)

type offlineEventFilterState struct {
	modalState   components.ModalState
	owner        *offlineEventBrowser
	token        offline.Token
	descriptions []string
	protocol     string
	cancelled    bool
}

type offlineEventFilterMsg struct {
	state *offlineEventFilterState
	query offline.EventQuery
	err   error
}

type offlineEventFilterProgressMsg struct{ state *offlineEventFilterState }

func offlineEventFilterTick(s *offlineEventFilterState) tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(time.Time) tea.Msg { return offlineEventFilterProgressMsg{s} })
}

func (m *Model) eventFilterDescriptions() []string {
	if m.offlineSession != nil && m.offlineEvents() != nil {
		if s := m.offlineEventBrowse; s != nil {
			return append([]string(nil), s.descriptions...)
		}
		return nil
	}
	return m.eventStore.UserFilterDescriptions()
}

func compileOfflineEventFilter(descriptions []string, protocol string) (eventquery.Predicate, error) {
	predicates := make([]eventquery.Predicate, len(descriptions))
	for i, description := range descriptions {
		predicate, err := eventquery.Compile(description)
		if err != nil {
			return nil, err
		}
		predicates[i] = predicate
	}
	if protocol == "All" && len(predicates) == 0 {
		return nil, nil
	}
	return func(event events.Event) bool {
		if !eventMatchesProtocol(event, protocol) {
			return false
		}
		for _, predicate := range predicates {
			if !predicate(event) {
				return false
			}
		}
		return true
	}, nil
}

func (m *Model) startOfflineEventFilter(descriptions []string, protocol string) tea.Cmd {
	if m.offlineSession != nil && m.offlineAnalysisPending() {
		return m.uiState.Toast.Show("Event filters pending ordered analysis", components.ToastInfo, components.ToastDurationLong)
	}
	if m.offlineSession == nil || m.offlineEvents() == nil || m.offlineOpening || m.offlineLeaving {
		return nil
	}
	descriptions = append([]string(nil), descriptions...)
	match, err := compileOfflineEventFilter(descriptions, protocol)
	if err != nil {
		return m.uiState.Toast.Show("Invalid event filter: "+err.Error(), components.ToastError, components.ToastDurationLong)
	}
	if err := m.ensureOfflineEventBrowser(); err != nil {
		return m.uiState.Toast.Show(err.Error(), components.ToastError, components.ToastDurationLong)
	}
	browser := m.offlineEventBrowse
	m.cancelOfflineEventReads()
	m.offlineEventFilterGeneration = max(m.offlineEventFilterGeneration, browser.queryGeneration) + 1
	s := &offlineEventFilterState{owner: browser.owner, token: offline.Token{Dataset: browser.owner.dataset.Generation(), Revision: browser.owner.dataset.Revision(), Query: m.offlineEventFilterGeneration}, descriptions: descriptions, protocol: protocol}
	browser.attempted = protocol
	m.offlineEventFilter = s
	ctx, prior, done, ok := s.owner.begin()
	if !ok {
		m.offlineEventFilter = nil
		return nil
	}
	s.owner.mu.Lock()
	s.owner.progress = offline.QueryProgress{Token: s.token, Total: s.owner.dataset.Count()}
	s.owner.mu.Unlock()
	ch := make(chan offlineEventFilterMsg, 1)
	go func() {
		defer close(done)
		if prior != nil {
			<-prior
		}
		var q offline.EventQuery
		err := s.owner.cleanupPending()
		if err == nil {
			err = ctx.Err()
		}
		if err == nil {
			// The scope is a separate constraint; user expressions retain the
			// same canonical eventquery language and stacked AND semantics.
			spec := offline.EventQuerySpec{Token: s.token, Description: descriptions, Match: match, Progress: func(p offline.QueryProgress) {
				s.owner.mu.Lock()
				if !s.owner.closed && p.Token == s.token && ctx.Err() == nil {
					s.owner.progress = p
				}
				s.owner.mu.Unlock()
			}}
			q, err = s.owner.dataset.Query(ctx, spec)
		}
		if err == nil {
			err = ctx.Err()
		}
		s.owner.mu.Lock()
		if q != nil {
			s.owner.queries[q] = struct{}{}
		}
		s.owner.mu.Unlock()
		ch <- offlineEventFilterMsg{s, q, err}
	}()
	return tea.Batch(func() tea.Msg { return <-ch }, offlineEventFilterTick(s))
}

func (m Model) handleOfflineEventFilter(msg offlineEventFilterMsg) (Model, tea.Cmd) {
	s := msg.state
	dispose := func() tea.Msg { return offlineCleanupMsg{err: s.owner.releaseQuery(msg.query)} }
	if m.offlineEventFilter != s || m.offlineSession == nil || m.offlineEvents() == nil || m.offlineEvents().Generation() != s.token.Dataset || m.offlineEvents().Revision() != s.token.Revision || m.offlineOpening || m.offlineLeaving {
		return m, dispose
	}
	m.offlineEventFilter = nil
	if msg.err != nil || s.cancelled {
		if s.cancelled || errors.Is(msg.err, context.Canceled) {
			return m, dispose
		}
		return m, tea.Batch(dispose, m.uiState.Toast.Show("Offline event filter failed: "+msg.err.Error(), components.ToastError, components.ToastDurationLong))
	}
	s.owner.mu.Lock()
	_, owned := s.owner.queries[msg.query]
	if !owned || s.owner.closed {
		s.owner.mu.Unlock()
		return m, dispose
	}
	old := s.owner.query
	s.owner.query = msg.query
	s.owner.mu.Unlock()
	b := m.offlineEventBrowse
	b.queryGeneration, b.descriptions, b.protocol = s.token.Query, s.descriptions, s.protocol
	b.requested = false
	m.resetCaptureInspection()
	m.cancelOfflineRelated()
	m.uiState.EventsView.SetVirtualDetail(nil)
	m.uiState.EventsView.SetVirtualWindow(msg.query.Count(), 0, nil)
	m.uiState.EventsView.SetLogicalCursor(0)
	prior := b.current
	b.current = nil
	s.owner.mu.Lock()
	s.owner.current = nil
	s.owner.mu.Unlock()
	m.prepareEventsViewLayout()
	return m, func() tea.Msg {
		return offlineCleanupMsg{err: errors.Join(s.owner.releaseResult(prior), s.owner.releaseQuery(old))}
	}
}

func (m *Model) cancelOfflineEventFilter() {
	if s := m.offlineEventFilter; s != nil {
		s.cancelled = true
		s.owner.mu.Lock()
		if s.owner.cancel != nil {
			s.owner.cancel()
		}
		s.owner.mu.Unlock()
	}
}

func (m Model) offlineEventFilterModal() string {
	return components.RenderModal(m.offlineEventFilterModalOptions())
}

func (m *Model) offlineEventFilterModalOptions() components.ModalRenderOptions {
	s := m.offlineEventFilter
	s.owner.mu.Lock()
	p := s.owner.progress
	s.owner.mu.Unlock()
	if p.Token != s.token {
		p = offline.QueryProgress{Token: s.token, Total: s.owner.dataset.Count()}
	}
	title, label, footer := "Filtering complete offline events", "Cancel", ""
	if s.cancelled {
		title, label, footer = "Cancelling event filter", "Cancelling", "Waiting for cleanup"
	}
	content := fmt.Sprintf("Scanned: %d / %d\nMatches: %d", p.Scanned, p.Total, p.Matched)
	if !s.cancelled {
		content += "\n\n" + offlineProgressBar(p.Scanned, p.Total, true, 0)
	}
	return components.ModalRenderOptions{ID: fmt.Sprintf("offline-event-filter-%p", s), Title: title, Content: content, Footer: footer, State: &s.modalState, Width: m.uiState.Width, Height: m.uiState.Height, Theme: m.uiState.Theme, ModalWidth: offlineProgressModalWidth,
		Actions: []components.ModalAction{{ID: "cancel", Label: label, Shortcut: "Esc", Disabled: s.cancelled}, {ID: "quit", Label: "Quit", Shortcut: "Ctrl+C", Disabled: s.cancelled}}}
}

func (m *Model) offlineEventFilterModalAction(id string) tea.Cmd {
	if m.offlineEventFilter == nil {
		return nil
	}
	switch id {
	case "cancel":
		m.cancelOfflineEventFilter()
	case "quit":
		next, cmd := m.leaveOffline(nil, true)
		*m = next
		return cmd
	}
	return nil
}
