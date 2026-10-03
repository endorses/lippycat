//go:build tui || all

package tui

import (
	"context"
	"fmt"
	"sync"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
)

// Shared by model copies and the original program owner, so even an abandoned
// Bubble Tea delivery command cannot strand a resident marked export at shutdown.
type markedExportOwner struct {
	mu     sync.Mutex
	state  *offlineExportState
	closed bool
}

func (o *markedExportOwner) current() *offlineExportState {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.state
}

func markedExportActive(s *offlineExportState) bool {
	if s == nil {
		return false
	}
	select {
	case <-s.done:
		return false
	default:
		return true
	}
}

func (o *markedExportOwner) close() {
	if o == nil {
		return
	}
	o.mu.Lock()
	o.closed = true
	s := o.state
	o.mu.Unlock()
	if s != nil {
		s.cancel()
		<-s.done
	}
}

func (m *Model) startResidentMarkedExport(path string, records []offline.RawRecord) tea.Cmd {
	if m.markedExports == nil {
		m.markedExports = &markedExportOwner{}
	}
	owner := m.markedExports
	owner.mu.Lock()
	if owner.closed || markedExportActive(owner.state) {
		owner.mu.Unlock()
		return m.markError(fmt.Errorf("packet export is busy or capture is closing"))
	}
	ctx, cancel := context.WithCancel(context.Background())
	state := &offlineExportState{cancel: cancel, done: make(chan struct{})}
	owner.state = state
	owner.mu.Unlock()
	m.uiState.SaveInProgress = true
	// Start immediately, before returning a command that only delivers the result.
	go func() {
		defer close(state.done)
		defer cancel()
		count, err := exportOfflinePCAP(ctx, path, func(ctx context.Context, visit func(offline.RawRecord) error) error {
			for _, r := range records {
				if err := visit(r); err != nil {
					return err
				}
			}
			return nil
		})
		state.result = SaveCompleteMsg{Success: err == nil, Path: path, PacketsSaved: count, Error: err}
	}()
	return tea.Batch(m.uiState.Toast.ShowWithKey(fmt.Sprintf("Saving %d marked packets… Esc cancels export", len(records)), components.ToastInfo, 0, components.ToastKeyFileSave), func() tea.Msg { <-state.done; return state.result })
}
