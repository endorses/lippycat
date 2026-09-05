//go:build tui || all

package tui

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/tui/filters"
)

// The session owns lookup cancellation and joins even abandoned command results.
type offlineRelatedOwner struct {
	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
	closed bool
}

func (o *offlineRelatedOwner) close() {
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
}
func (m *Model) cancelOfflineRelated() {
	if m.offlineRelated != nil {
		m.offlineRelated.cancel()
	}
	m.offlineRelated = nil
}

// A single selected-flow cache is independent of packet pages and remains
// bounded even when navigating a dataset with millions of distinct flows.
type offlineRelatedState struct {
	generation                         offline.DatasetGeneration
	flow                               offline.Flow
	cancel                             context.CancelFunc
	known, available, navigate, failed bool
	first                              offline.PacketID
}
type offlineRelatedMsg struct {
	state     *offlineRelatedState
	first     offline.PacketID
	available bool
	err       error
}

func offlineEventFlow(env events.Envelope) offline.Flow {
	return offline.Flow{Source: netip.AddrPortFrom(env.Flow.SourceAddress.Unmap(), env.Flow.SourcePort), Destination: netip.AddrPortFrom(env.Flow.DestinationAddress.Unmap(), env.Flow.DestinationPort), Transport: env.Flow.Protocol, Node: env.NodeID}
}
func (m *Model) presentOfflineRelated(event events.Event) {
	s := m.offlineRelated
	if s != nil && s.generation == m.offlineSession.Dataset.Generation() && s.flow == offlineEventFlow(m.relatedPacketEnvelope(event)) && s.known {
		m.uiState.EventsView.SetRelatedPacketsAvailable(s.available)
	} else {
		m.uiState.EventsView.SetRelatedPacketsPending()
	}
}

// Called by Update, never by rendering or layout preparation.
func (m *Model) requestOfflineRelated() tea.Cmd {
	if m.offlineSession == nil || m.offlineOpening || m.uiState.ViewMode != "events" || m.uiState.Tabs.GetActive() != 0 {
		if m.offlineRelated != nil {
			m.offlineRelated.navigate = false
		}
		if m.offlineRelated != nil && !m.offlineRelated.known {
			m.offlineRelated.cancel()
			m.offlineRelated = nil
		}
		return nil
	}
	selected, ok := m.uiState.EventsView.Selected()
	if !ok {
		m.cancelOfflineRelated()
		return nil
	}
	flow := offlineEventFlow(m.relatedPacketEnvelope(selected.Event))
	dataset := m.offlineSession.Dataset
	if s := m.offlineRelated; s != nil && s.generation == dataset.Generation() && s.flow == flow {
		return nil
	}
	if m.offlineRelated != nil {
		m.offlineRelated.cancel()
	}
	if m.offlineSession.related == nil {
		m.offlineSession.related = &offlineRelatedOwner{}
	}
	owner := m.offlineSession.related
	owner.mu.Lock()
	if owner.closed {
		owner.mu.Unlock()
		return nil
	}
	if owner.cancel != nil {
		owner.cancel()
	}
	prior := owner.done
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	owner.cancel, owner.done = cancel, done
	owner.mu.Unlock()
	state := &offlineRelatedState{generation: dataset.Generation(), flow: flow, cancel: cancel}
	m.offlineRelated = state
	m.uiState.EventsView.SetRelatedPacketsPending()
	m.prepareEventsViewLayout()
	pageBytes := offlinePageBudget(m.offlineInstalled.Limits)
	var browser *offlineBrowser
	var browserDone <-chan struct{}
	var browserCutoff offline.RequestID
	if m.offlineBrowse != nil {
		browser = m.offlineBrowse.owner
		browserCutoff = m.offlineBrowse.request
		browser.mu.Lock()
		browserDone = browser.done
		browser.mu.Unlock()
	}
	lookup := func() offlineRelatedMsg {
		result := offlineRelatedMsg{state: state}
		if browser != nil {
			if err := browser.drainBefore(browserDone, browserCutoff); err != nil {
				result.err = err
				return result
			}
		}

		token := offline.Token{Dataset: state.generation, Query: 1, Request: 1}
		query, err := dataset.Related(ctx, token, flow)
		if err != nil {
			result.err = err
			return result
		}
		result.available = query.Count() > 0
		if result.available {
			page, err := query.Page(ctx, offline.PageRequest{Token: token, Limit: 1, MaxBytes: pageBytes})
			if err != nil {
				result.err = err
			} else {
				if len(page.Rows) != 1 {
					result.err = fmt.Errorf("related packet query returned no first row")
				} else {
					result.first = page.Rows[0].ID
				}
				result.err = errors.Join(result.err, page.Close())
			}
		}
		result.err = errors.Join(result.err, query.Close())
		return result
	}
	ch := make(chan offlineRelatedMsg, 1)
	go func() {
		defer close(done)
		if prior != nil {
			<-prior
		}
		ch <- lookup()
	}()
	return func() tea.Msg { return <-ch }
}
func (m Model) handleOfflineRelated(msg offlineRelatedMsg) (Model, tea.Cmd) {
	if m.offlineRelated != msg.state || m.offlineSession == nil || m.offlineSession.Dataset.Generation() != msg.state.generation {
		return m, nil
	}
	s := m.offlineRelated
	if msg.err != nil {
		s.failed = true
		// Leave availability unknown on errors; only a completed scan establishes absence.
		return m, m.uiState.Toast.Show("Related packet lookup failed: "+msg.err.Error(), components.ToastError, components.ToastDurationLong)
	}
	s.known, s.available, s.first = true, msg.available, msg.first
	if selected, ok := m.uiState.EventsView.Selected(); ok {
		m.presentOfflineRelated(selected.Event)
	}
	m.prepareEventsViewLayout()
	selected, selectedOK := m.uiState.EventsView.Selected()
	if s.navigate && s.available && selectedOK && s.flow == offlineEventFlow(m.relatedPacketEnvelope(selected.Event)) && m.uiState.ViewMode == "events" && m.uiState.Tabs.GetActive() == 0 {
		return m.navigateOfflineRelated()
	}
	return m, nil
}
func (m Model) navigateOfflineRelated() (Model, tea.Cmd) {
	if m.offlineRelated != nil && m.offlineRelated.failed {
		m.cancelOfflineRelated()
	}
	cmd := m.requestOfflineRelated()
	s := m.offlineRelated
	if s == nil {
		return m, cmd
	}
	s.navigate = true
	if !s.known {
		return m, cmd
	}
	if !s.available {
		return m, m.uiState.Toast.Show("No related packets in this dataset", components.ToastInfo, components.ToastDurationShort)
	}
	s.navigate = false
	if m.packetStore.HasFilter() {
		cmd := m.startOfflineFilter(filters.NewFilterChain(), nil)
		if m.offlineFilter != nil {
			id := s.first
			m.offlineFilter.jump = &id
		}
		return m, cmd
	}
	m.uiState.ViewMode = "packets"
	m.uiState.PacketList.SetLogicalCursor(uint64(s.first))
	m.updateDetailsPanel()
	return m, cmd
}
