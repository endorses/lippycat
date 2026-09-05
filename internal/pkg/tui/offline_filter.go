//go:build tui || all

package tui

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/tui/filters"
)

// The session owns workers and unpublished queries even if Tea abandons messages.
type offlineFilterOwner struct {
	mu       sync.Mutex
	releases sync.WaitGroup
	cancel   context.CancelFunc
	done     chan struct{}
	queries  map[offline.Query]struct{}
	closed   bool
	progress offline.QueryProgress
}
type offlineFilterState struct {
	owner     *offlineFilterOwner
	token     offline.Token
	chain     *filters.FilterChain
	protocol  *components.Protocol
	cancelled bool
	jump      *offline.PacketID
}
type offlineFilterMsg struct {
	state *offlineFilterState
	query offline.Query
	err   error
}
type offlineFilterProgressMsg struct{ state *offlineFilterState }

func (o *offlineFilterOwner) close() error {
	o.mu.Lock()
	o.closed = true
	if o.cancel != nil {
		o.cancel()
	}
	done := o.done
	o.mu.Unlock()
	if done != nil {
		<-done
	}
	o.releases.Wait()
	o.mu.Lock()
	queries := o.queries
	o.queries = make(map[offline.Query]struct{})
	o.mu.Unlock()
	var err error
	for q := range queries {
		err = errors.Join(err, q.Close())
	}
	return err
}
func (o *offlineFilterOwner) release(q offline.Query) error {
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return nil
	}
	if _, ok := o.queries[q]; !ok {
		o.mu.Unlock()
		return nil
	}
	delete(o.queries, q)
	o.releases.Add(1)
	o.mu.Unlock()
	defer o.releases.Done()
	return q.Close()
}
func (m *Model) offlineQueryGeneration() offline.QueryGeneration {
	if m.offlineBrowse != nil {
		b := m.offlineBrowse.owner
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.query != nil {
			return b.query.Token().Query
		}
	}
	return 1
}
func (m *Model) offlinePacketCount() uint64 {
	if m.offlineBrowse != nil {
		b := m.offlineBrowse.owner
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.query != nil {
			return b.query.Count()
		}
	}
	if m.offlineSession != nil {
		return m.offlineSession.Dataset.Count()
	}
	return 0
}
func offlineFilterTick(s *offlineFilterState) tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(time.Time) tea.Msg { return offlineFilterProgressMsg{s} })
}
func (m *Model) startOfflineFilter(chain *filters.FilterChain, protocol *components.Protocol) tea.Cmd {
	if m.offlineSession == nil || m.offlineOpening || m.offlineLeaving {
		return nil
	}
	if m.offlineBrowse == nil {
		b := &offlineBrowser{dataset: m.offlineSession.Dataset, results: make(map[*offlineBrowseResult]struct{})}
		m.offlineSession.browser = b
		m.offlineBrowse = &offlineBrowserState{owner: b}
	}
	o := m.offlineSession.filter
	if o == nil {
		o = &offlineFilterOwner{queries: make(map[offline.Query]struct{})}
		m.offlineSession.filter = o
	}
	m.cancelOfflineBrowserReads()
	// Keep the last completed rows visible, but release the selected detail's
	// extra reservation so summary scanning has its normal record headroom.
	if r := m.offlineBrowse.current; r != nil && r.detail != nil {
		m.uiState.DetailsPanel.SetPacket(nil)
		if err := r.detail.Close(); err != nil {
			return m.uiState.Toast.Show(err.Error(), components.ToastError, components.ToastDurationLong)
		}
		r.detail = nil
	}
	b := m.offlineBrowse.owner
	b.mu.Lock()
	browserDone := b.done
	cutoff := m.offlineBrowse.request
	b.mu.Unlock()
	m.offlineFilterGeneration++
	s := &offlineFilterState{owner: o, token: offline.Token{Dataset: m.offlineSession.Dataset.Generation(), Query: m.offlineFilterGeneration + 1}, chain: chain, protocol: protocol}
	m.offlineFilter = s
	dataset := m.offlineSession.Dataset
	o.mu.Lock()
	if o.cancel != nil {
		o.cancel()
	}
	prior := o.done
	ctx, cancel := context.WithCancel(context.Background())
	o.cancel = cancel
	done := make(chan struct{})
	o.done = done
	o.progress = offline.QueryProgress{Token: s.token, Total: dataset.Count()}
	o.mu.Unlock()
	ch := make(chan tea.Msg, 1)
	go func() {
		defer close(done)
		if prior != nil {
			<-prior
		}
		if browserDone != nil {
			<-browserDone
		}
		var q offline.Query
		var err error
		if err = b.drainBefore(browserDone, cutoff); err != nil {
			ch <- offlineFilterMsg{s, nil, err}
			return
		}
		o.mu.Lock()
		obsoleteQueries := make([]offline.Query, 0, len(o.queries))
		for obsolete := range o.queries {
			obsoleteQueries = append(obsoleteQueries, obsolete)
		}
		o.mu.Unlock()
		for _, obsolete := range obsoleteQueries {
			err = errors.Join(err, o.release(obsolete))
		}
		if err != nil {
			ch <- offlineFilterMsg{s, nil, err}
			return
		}
		if err = ctx.Err(); err == nil {
			spec := offline.QuerySpec{Token: s.token, Description: chain.GetFilterDescriptions(), Progress: func(p offline.QueryProgress) {
				o.mu.Lock()
				if p.Token == s.token && ctx.Err() == nil {
					o.progress = p
				}
				o.mu.Unlock()
			}}
			if !chain.IsEmpty() {
				spec.Match = func(summary offline.Summary) bool { return chain.Match(summary) }
			}
			q, err = dataset.Query(ctx, spec)
		}
		o.mu.Lock()
		if q != nil {
			o.queries[q] = struct{}{}
		}
		o.mu.Unlock()
		ch <- offlineFilterMsg{s, q, err}
	}()
	return tea.Batch(func() tea.Msg { return <-ch }, offlineFilterTick(s))
}
func (m Model) handleOfflineFilter(msg offlineFilterMsg) (Model, tea.Cmd) {
	s := msg.state
	s.owner.mu.Lock()
	_, owned := s.owner.queries[msg.query]

	s.owner.mu.Unlock()
	dispose := func() tea.Msg {
		if owned {
			return offlineCleanupMsg{err: s.owner.release(msg.query)}
		}
		return nil
	}
	if m.offlineFilter != s || m.offlineSession == nil || m.offlineSession.Dataset.Generation() != s.token.Dataset || m.offlineLeaving || m.offlineOpening {
		return m, dispose
	}
	m.offlineFilter = nil
	if msg.err != nil || s.cancelled {
		if errors.Is(msg.err, context.Canceled) || s.cancelled {
			return m, dispose
		}
		return m, tea.Batch(dispose, m.uiState.Toast.Show("Offline filter failed: "+msg.err.Error(), components.ToastError, components.ToastDurationLong))
	}
	if !owned {
		return m, nil
	}
	s.owner.mu.Lock()
	delete(s.owner.queries, msg.query)
	s.owner.mu.Unlock()
	b := m.offlineBrowse.owner
	b.mu.Lock()
	old := b.query
	b.query = msg.query
	b.mu.Unlock()
	m.packetStore.SetFilter(s.chain)
	m.publishOfflineStatistics(msg.query)
	m.offlineBrowse.requested = false
	if r := m.offlineBrowse.current; r != nil {
		m.uiState.DetailsPanel.SetPacket(nil)
		if err := b.release(r); err != nil {
			return m, m.uiState.Toast.Show(err.Error(), components.ToastError, components.ToastDurationLong)
		}
		m.offlineBrowse.current = nil
		b.mu.Lock()
		b.current = nil
		b.mu.Unlock()
	}
	m.uiState.PacketList.Reset()
	m.uiState.PacketList.SetVirtualPackets(msg.query.Count(), 0, nil)
	if s.jump != nil {
		m.uiState.ViewMode = "packets"
		m.uiState.PacketList.SetLogicalCursor(uint64(*s.jump))
	}
	if s.protocol != nil {
		preserveEvents := m.uiState.ViewMode == "events" && eventScopeAvailable(s.protocol.Name)
		m.uiState.SelectedProtocol = *s.protocol
		m.uiState.StatisticsView.SetSelectedProtocol(s.protocol.Name)
		if preserveEvents {
			m.setCaptureView("events")
		} else if s.protocol.Name == "VoIP (SIP/RTP)" {
			m.uiState.ViewMode = "calls"
		} else {
			m.uiState.ViewMode = "packets"
		}
	}

	if old != nil {
		s.owner.mu.Lock()
		s.owner.queries[old] = struct{}{}
		s.owner.mu.Unlock()
	}
	return m, func() tea.Msg {
		if old != nil {
			return offlineCleanupMsg{err: s.owner.release(old)}
		}
		return nil
	}
}
func (m Model) offlineFilterModal() string {
	s := m.offlineFilter
	s.owner.mu.Lock()
	p := s.owner.progress
	s.owner.mu.Unlock()
	if p.Token != s.token {
		p = offline.QueryProgress{Token: s.token, Total: m.offlineSession.Dataset.Count()}
	}
	title := "Filtering offline packets"
	footer := "Esc: Cancel"
	if s.cancelled {
		title = "Cancelling filter"
		footer = "Waiting for cleanup"
	}
	content := fmt.Sprintf("Scanned: %d / %d\nMatches: %d", p.Scanned, p.Total, p.Matched)
	if !s.cancelled {
		content += "\n\n" + offlineProgressBar(p.Scanned, p.Total, true, 0)
	}
	return components.RenderModal(components.ModalRenderOptions{Title: title, Content: content, Footer: footer, Width: m.uiState.Width, Height: m.uiState.Height, Theme: m.uiState.Theme, ModalWidth: offlineProgressModalWidth})
}
