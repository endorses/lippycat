package voip

import (
	"context"
	"sync"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/sipflow"
	"github.com/google/gopacket/layers"
)

type compatibilitySelections struct {
	mu       sync.RWMutex
	selected map[string]struct{}
}

func (s *compatibilitySelections) Selected(callID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.selected[callID]
	return ok
}
func (s *compatibilitySelections) MarkSelected(callID string) {
	s.mu.Lock()
	s.selected[callID] = struct{}{}
	s.mu.Unlock()
}
func (s *compatibilitySelections) Forget(callID string) {
	s.mu.Lock()
	delete(s.selected, callID)
	s.mu.Unlock()
}

// handleSipMessageWithTracker keeps older parser/security corpus tests focused
// on their original boolean assertion while exercising the production sipflow
// orchestration path. No production consumer retains the legacy handler.
func handleSipMessageWithTracker(tracker *CallTracker, data []byte, _ layers.LinkType) bool {
	flow, err := sipflow.New(sipflow.Config{
		SelectionPolicy: callregistry.StickySelectionPolicy{},
		SelectionStore:  &compatibilitySelections{selected: make(map[string]struct{})},
		Registry:        sniffRegistry{tracker: tracker},
		Completion:      sniffNeverComplete{},
	})
	if err != nil {
		return false
	}
	if err := flow.Start(context.Background()); err != nil {
		return false
	}
	defer flow.Close()
	result := flow.Analyze(sipflow.Message{
		Payload:          data,
		FilterConfigured: true,
		Match: func(event sharedsip.Event) bool {
			return containsUserInHeaders(event.Headers)
		},
		Validate: func(event sharedsip.Event) error {
			return ValidateCallIDForSecurity(event.CallID)
		},
	})
	return result.Stage.Outcome == pipeline.OutcomeAccepted
}
